use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use msphf_core::{hash::h_l, hkdf::hkdf_blake3, serde_utils::to_cbor_vec};
use pqcrypto_kyber::kyber768;
use zeroize::{Zeroize, Zeroizing};

use crate::barrier::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    barrier_path_nodes, compute_revocation_roots_hash,
};
use crate::barrier_crypto::{
    ML_KEM_EXPANDED_DK_BYTES, decapsulate_internal_node_shared_secret,
    derive_internal_node_key_material, derive_k_fs_after_pcs,
};
use crate::barrier_update::parse_barrier_update_for_recover;

#[derive(Clone, Copy, Debug)]
pub struct BarrierRecoveryNodeMaterialRef<'a> {
    pub dk: &'a [u8],
    pub pkhash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct DerivedBarrierNodeKeyMaterial {
    pub dk: Zeroizing<Vec<u8>>,
    pub pkhash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BarrierRecoverResult {
    pub barrier_version: u64,
    pub k_barrier_new: Zeroizing<[u8; 32]>,
    pub kem_tree_hash_after: [u8; 32],
    pub k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    pub derived_node_key_material: BTreeMap<u32, DerivedBarrierNodeKeyMaterial>,
}

pub struct BarrierRecoveryInput<'a> {
    pub gid: &'a [u8; 32],
    pub local_n_max: u64,
    pub local_cover_leaf_index: u64,
    pub local_slot_generation: u64,
    pub local_barrier_initialized: bool,
    pub local_barrier_version: u64,
    pub local_barrier_roots_hash: [u8; 32],
    pub local_kem_tree_hash_after: [u8; 32],
    pub local_pop_public_key: &'a [u8],
    pub local_leaf_material: BarrierRecoveryNodeMaterialRef<'a>,
    pub local_node_materials: BTreeMap<u32, BarrierRecoveryNodeMaterialRef<'a>>,
    pub local_k_fs_before: [u8; 32],
    pub weid: &'a [u8; 32],
    pub fs_ec: u64,
    pub raw_update: &'a [u8],
    pub barrier_update_reason: u64,
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub author_pop_public_key: Option<&'a [u8]>,
    pub max_barrier_update_bytes: usize,
    pub expected_before_hash: Option<[u8; 32]>,
    pub skip_local_checks: bool,
}

fn zeroize_path_secret_map(path_secrets: &mut BTreeMap<u64, [u8; 32]>) {
    for secret in path_secrets.values_mut() {
        secret.zeroize();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn recover_barrier_update(
    input: BarrierRecoveryInput<'_>,
) -> Result<Option<BarrierRecoverResult>> {
    if input.max_barrier_update_bytes == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }

    let n_max = input.local_n_max.max(1);
    let parsed =
        parse_barrier_update_for_recover(input.raw_update, n_max, input.max_barrier_update_bytes)?;

    let valid_progression = (parsed.prev_barrier_version == 0 && parsed.barrier_version == 0)
        || parsed.prev_barrier_version.saturating_add(1) == parsed.barrier_version;
    if !valid_progression {
        return Err(anyhow!("barrier version progression is invalid"));
    }

    if !input.skip_local_checks {
        let genesis_local_case = !input.local_barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        let valid_local_progression = genesis_local_case
            || (input.local_barrier_initialized
                && parsed.prev_barrier_version == input.local_barrier_version
                && parsed.barrier_version == input.local_barrier_version.saturating_add(1));
        if !valid_local_progression {
            return Err(anyhow!(
                "barrier version progression does not match local barrier state"
            ));
        }
    }

    if parsed.tree_size != n_max {
        return Err(anyhow!("barrier tree_size mismatch for local state"));
    }

    if !input.skip_local_checks {
        let required_before_hash = input
            .expected_before_hash
            .unwrap_or(input.local_kem_tree_hash_after);
        if input.barrier_update_reason != 2 && parsed.kem_tree_hash_before != required_before_hash {
            return Err(anyhow!("barrier hash-chain before-hash mismatch"));
        }
    }

    let expected_rrh =
        compute_revocation_roots_hash(&input.revoked_since_root, &input.revoked_root)?;
    if parsed.revocation_roots_hash != expected_rrh {
        return Err(anyhow!("barrier revocation_roots_hash mismatch"));
    }

    if !input.skip_local_checks {
        let genesis_local_case = !input.local_barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        if !genesis_local_case {
            if input.local_barrier_roots_hash == parsed.revocation_roots_hash {
                if !matches!(input.barrier_update_reason, 1 | 2) {
                    return Err(anyhow!(
                        "barrier_update_reason must be pcs_refresh (1) or join_finalize (2) when local barrier_roots_hash is unchanged"
                    ));
                }
            } else if input.barrier_update_reason != 0 {
                return Err(anyhow!(
                    "barrier_update_reason must be revocation_or_bootstrap (0) when local barrier_roots_hash changed"
                ));
            }
        }
    }

    let author_matches = input
        .author_pop_public_key
        .map(|pk| pk == input.local_pop_public_key)
        .unwrap_or(false);
    if author_matches
        && parsed.updater_leaf == input.local_cover_leaf_index
        && parsed.updater_slot_generation == input.local_slot_generation
    {
        return Ok(None);
    }

    let self_path = barrier_path_nodes(n_max, input.local_cover_leaf_index)?;
    let self_path_set: HashSet<u64> = self_path.iter().copied().collect();
    let leaf_node = self_path
        .first()
        .copied()
        .ok_or_else(|| anyhow!("local self path is empty"))?;

    let mut matches: Vec<(u64, u64, [u8; 32])> = Vec::new();
    let mut candidate_decrypt_failure = false;
    for node in &parsed.node_ciphertexts {
        if !self_path_set.contains(&node.target_node) {
            continue;
        }

        let (dk_bytes, pkhash_t) = if node.target_node == leaf_node {
            (
                input.local_leaf_material.dk,
                input.local_leaf_material.pkhash,
            )
        } else if let Some(material) = input.local_node_materials.get(&(node.target_node as u32)) {
            (material.dk, material.pkhash)
        } else {
            continue;
        };

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&pkhash_t[..16]);
        if target_prefix != node.target_pk_hash {
            continue;
        }

        let mut ss = if node.target_node == leaf_node {
            if dk_bytes.len() != kyber768::secret_key_bytes() {
                continue;
            }
            let ct = match kyber768::Ciphertext::from_bytes(node.kem_ct.as_slice()) {
                Ok(ct) => ct,
                Err(_) => continue,
            };
            let dk = match kyber768::SecretKey::from_bytes(dk_bytes) {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let shared = kyber768::decapsulate(&ct, &dk);
            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared.as_bytes());
            ss
        } else if dk_bytes.len() == ML_KEM_EXPANDED_DK_BYTES {
            match decapsulate_internal_node_shared_secret(dk_bytes, node.kem_ct.as_slice()) {
                Ok(ss) => ss,
                Err(_) => {
                    candidate_decrypt_failure = true;
                    continue;
                }
            }
        } else {
            candidate_decrypt_failure = true;
            continue;
        };

        let aad = to_cbor_vec(&crate::barrier_build::BarrierWrapAadPreimage(
            input.gid,
            parsed.barrier_version,
            parsed.prev_barrier_version,
            parsed.tree_size,
            &parsed.revocation_roots_hash,
            &parsed.kem_tree_hash_before,
            &parsed.kem_tree_hash_after,
            parsed.updater_leaf,
            parsed.updater_slot_generation,
            node.source_node,
            node.target_node,
            &pkhash_t,
        ))
        .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &crate::barrier_build::BarrierWrapNoncePreimage(node.source_node, node.target_node),
        )
        .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        let cipher = ChaCha20Poly1305::new((&ss).into());
        let mut plaintext = match cipher.decrypt(
            (&nonce).into(),
            Payload {
                msg: node.wrapped_ps.as_slice(),
                aad: aad.as_slice(),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                ss.zeroize();
                candidate_decrypt_failure = true;
                continue;
            }
        };
        ss.zeroize();
        if plaintext.len() != 32 {
            plaintext.zeroize();
            candidate_decrypt_failure = true;
            continue;
        }
        let mut path_secret = [0u8; 32];
        path_secret.copy_from_slice(plaintext.as_slice());
        plaintext.zeroize();
        matches.push((node.source_node, node.target_node, path_secret));
    }

    if matches.is_empty() {
        if candidate_decrypt_failure {
            return Err(anyhow!(
                "barrier recover rejected: candidate unwrap/decrypt failure (960.7)"
            ));
        }
        return Ok(None);
    }
    if matches.len() > 1 {
        for (_, _, secret) in &mut matches {
            secret.zeroize();
        }
        return Err(anyhow!("barrier recover rejected: multi-match (960.2)"));
    }

    let (source_node, target_node, source_secret) = matches.remove(0);
    if !self_path_set.contains(&source_node) || !self_path_set.contains(&target_node) {
        return Err(anyhow!(
            "barrier recover rejected: off-path source/target (960.7)"
        ));
    }
    let source_index = parsed
        .path_nodes
        .iter()
        .position(|node| *node == source_node)
        .ok_or_else(|| {
            anyhow!("barrier recover rejected: source missing from path_nodes (960.7)")
        })?;

    let mut path_secrets = BTreeMap::new();
    path_secrets.insert(source_node, source_secret);
    for k in (source_index + 1)..parsed.path_nodes.len() {
        let parent_node = parsed.path_nodes[k];
        let child_node = parsed.path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier recover missing child path secret"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(input.gid.as_slice(), parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier recover failed to derive root path secret"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(
            input.gid.as_slice(),
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
        ),
    )
    .map_err(|err| anyhow!("derive barrier key salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let expected_node_set: HashSet<u64> = parsed.path_nodes.iter().copied().skip(1).collect();
    let mut derived_node_key_material = BTreeMap::new();
    for node in parsed.path_nodes.iter().copied().skip(source_index) {
        if node == leaf_node || !self_path_set.contains(&node) {
            continue;
        }
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("barrier recover missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            input.gid.as_slice(),
            path_secret,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.tree_size,
            node,
        )?;
        if expected_node_set.contains(&node) {
            let announced_ek = parsed.new_public_keys.get(&node).ok_or_else(|| {
                anyhow!("barrier recover rejected: missing new_public_keys for node {node} (960.7)")
            })?;
            if announced_ek.as_slice() != ek_bytes.as_slice() {
                return Err(anyhow!(
                    "barrier recover rejected: new_public_keys mismatch for node {node} (960.7)"
                ));
            }
        }
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        derived_node_key_material.insert(
            node_index,
            DerivedBarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
    }

    let k_fs_after_pcs = if input.barrier_update_reason == 1 {
        Some(derive_k_fs_after_pcs(
            &input.local_k_fs_before,
            input.weid,
            input.fs_ec,
            parsed.barrier_version,
            &k_barrier_new,
        )?)
    } else {
        None
    };

    zeroize_path_secret_map(&mut path_secrets);

    Ok(Some(BarrierRecoverResult {
        barrier_version: parsed.barrier_version,
        k_barrier_new: Zeroizing::new(k_barrier_new),
        kem_tree_hash_after: parsed.kem_tree_hash_after,
        k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
        derived_node_key_material,
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::barrier::compute_barrier_pkhash;
    use crate::barrier_build::build_barrier_update_bytes;
    use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};

    #[test]
    fn recover_barrier_update_recovers_matching_leaf_and_root_material() -> Result<()> {
        let gid = [0x11; 32];
        let revoked_since_root = [0x22; 32];
        let revoked_root = [0x33; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        let (leaf_ek, leaf_dk) = kyber768::keypair();
        let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
        let leaf_dk_bytes = KemSecretKey::as_bytes(&leaf_dk).to_vec();
        let leaf_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;

        let snapshot_pre = vec![
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            leaf_ek_bytes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ];
        let kem_tree_hash_before = crate::barrier::compute_barrier_tree_hash(8, &snapshot_pre)?;
        let built = build_barrier_update_bytes(
            &gid,
            8,
            0,
            0,
            5,
            4,
            rrh,
            kem_tree_hash_before,
            &snapshot_pre,
        )?;
        let expected_k_fs_after =
            derive_k_fs_after_pcs(&[0x44; 32], &[0x55; 32], 7, 5, &built.k_barrier_new)?;

        let recovered = recover_barrier_update(BarrierRecoveryInput {
            gid: &gid,
            local_n_max: 8,
            local_cover_leaf_index: 4,
            local_slot_generation: 0,
            local_barrier_initialized: true,
            local_barrier_version: 4,
            local_barrier_roots_hash: rrh,
            local_kem_tree_hash_after: kem_tree_hash_before,
            local_pop_public_key: b"other-device",
            local_leaf_material: BarrierRecoveryNodeMaterialRef {
                dk: leaf_dk_bytes.as_slice(),
                pkhash: leaf_pkhash,
            },
            local_node_materials: BTreeMap::new(),
            local_k_fs_before: [0x44; 32],
            weid: &[0x55; 32],
            fs_ec: 7,
            raw_update: built.raw_update.as_slice(),
            barrier_update_reason: 1,
            revoked_since_root,
            revoked_root,
            author_pop_public_key: None,
            max_barrier_update_bytes: 1_048_576,
            expected_before_hash: None,
            skip_local_checks: false,
        })?
        .expect("recovery should match one ciphertext");

        assert_eq!(recovered.barrier_version, 5);
        assert_eq!(recovered.kem_tree_hash_after, built.kem_tree_hash_after);
        assert_eq!(recovered.derived_node_key_material.len(), 1);
        assert!(recovered.derived_node_key_material.contains_key(&0));
        assert_eq!(*recovered.k_barrier_new, *built.k_barrier_new);
        assert_eq!(
            recovered.k_fs_after_pcs.as_deref().copied(),
            Some(expected_k_fs_after)
        );
        Ok(())
    }
}
