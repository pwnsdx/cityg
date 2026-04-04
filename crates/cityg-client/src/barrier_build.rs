use std::collections::BTreeMap;

use anyhow::{Context as AnyhowContext, Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use msphf_core::{hash::h_l, hkdf::hkdf_blake3, serde_utils::to_cbor_vec};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::Ciphertext as KemCiphertext;
use rand::{Rng, rng};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::barrier::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    barrier_path_nodes, collect_resolution_targets, compute_barrier_pkhash,
    compute_barrier_tree_hash, expected_barrier_tree_nodes, sibling_node, validate_barrier_n_max,
};
use crate::barrier_crypto::derive_internal_node_key_material;
use crate::barrier_update::{
    BarrierUpdateWire, KemTreeCoverPayloadWire, NewPublicKeyWire, NodeCiphertextWire,
    compute_barrier_update_digest,
};

#[derive(Serialize)]
pub struct BarrierWrapNoncePreimage(pub u64, pub u64);

#[derive(Serialize)]
pub struct BarrierWrapAadPreimage<'a>(
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
    pub u64,
    pub u64,
    pub u64,
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
    pub u64,
    pub u64,
    pub u64,
    pub u64,
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
);

#[derive(Clone, Debug)]
pub struct BuiltBarrierNodeKeyMaterial {
    pub dk: Zeroizing<Vec<u8>>,
    pub pkhash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BarrierUpdateBuildResult {
    pub raw_update: Vec<u8>,
    pub barrier_update_digest: [u8; 32],
    pub kem_tree_hash_after: [u8; 32],
    pub k_barrier_new: Zeroizing<[u8; 32]>,
    pub on_path_key_material: BTreeMap<u32, BuiltBarrierNodeKeyMaterial>,
    pub snapshot_post: Vec<Vec<u8>>,
}

fn zeroize_path_secret_map(path_secrets: &mut BTreeMap<u64, [u8; 32]>) {
    for secret in path_secrets.values_mut() {
        secret.zeroize();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_barrier_update_bytes(
    gid: &[u8; 32],
    n_max: u64,
    updater_leaf: u64,
    updater_slot_generation: u64,
    barrier_version: u64,
    prev_barrier_version: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    snapshot_pre: &[Vec<u8>],
) -> Result<BarrierUpdateBuildResult> {
    let n_max = validate_barrier_n_max(n_max)?;
    if updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let expected_nodes = expected_barrier_tree_nodes(n_max)?;
    if snapshot_pre.len() != expected_nodes {
        return Err(anyhow!(
            "barrier snapshot size mismatch: expected {expected_nodes}, got {}",
            snapshot_pre.len()
        ));
    }

    let leaf_base = n_max.saturating_sub(1);
    let path_nodes = barrier_path_nodes(n_max, updater_leaf)?;

    let mut path_secrets = BTreeMap::new();
    let mut ps_leaf = [0u8; 32];
    rng().fill(&mut ps_leaf);
    path_secrets.insert(path_nodes[0], ps_leaf);
    ps_leaf.zeroize();
    for k in 1..path_nodes.len() {
        let parent_node = path_nodes[k];
        let child_node = path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier path secret derivation missing child"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(gid.as_slice(), parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree/path salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier path secret derivation missing root"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(gid.as_slice(), barrier_version, &revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier/derive/salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let mut expected_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
    expected_nodes.sort_unstable();
    let mut on_path_key_material = BTreeMap::new();
    let mut new_public_keys = Vec::with_capacity(expected_nodes.len());
    for node in expected_nodes {
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            gid.as_slice(),
            path_secret,
            barrier_version,
            &revocation_roots_hash,
            n_max,
            node,
        )?;
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        on_path_key_material.insert(
            node_index,
            BuiltBarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
        new_public_keys.push(NewPublicKeyWire(node, ek_bytes));
    }

    let mut snapshot_post = snapshot_pre.to_vec();
    for NewPublicKeyWire(node, ek) in &new_public_keys {
        let idx = usize::try_from(*node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot_post
            .get_mut(idx)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = ek.clone();
    }
    let kem_tree_hash_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

    let mut node_ciphertexts = Vec::new();
    for step in 0..path_nodes.len().saturating_sub(1) {
        let child_node = path_nodes[step];
        let source_node = path_nodes[step + 1];
        let sibling =
            sibling_node(child_node).ok_or_else(|| anyhow!("barrier sibling missing for root"))?;
        let mut targets = Vec::new();
        collect_resolution_targets(snapshot_pre, sibling, leaf_base, &mut targets)?;
        targets.sort_unstable();
        for target_node in targets {
            let target_index = usize::try_from(target_node)
                .map_err(|_| anyhow!("barrier node index out of range"))?;
            let target_pk = snapshot_pre
                .get(target_index)
                .ok_or_else(|| anyhow!("barrier node index out of range"))?;
            if target_pk.is_empty() {
                return Err(anyhow!("barrier resolution produced blank target node"));
            }
            let target_pkhash = compute_barrier_pkhash(target_pk.as_slice())?;
            let target_ek = kyber768::PublicKey::from_bytes(target_pk.as_slice())
                .map_err(|_| anyhow!("invalid ML-KEM target public key in snapshot_pre"))?;
            let (ss, kem_ct) = kyber768::encapsulate(&target_ek);
            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            let aad = to_cbor_vec(&BarrierWrapAadPreimage(
                gid,
                barrier_version,
                prev_barrier_version,
                n_max,
                &revocation_roots_hash,
                &kem_tree_hash_before,
                &kem_tree_hash_after,
                updater_leaf,
                updater_slot_generation,
                source_node,
                target_node,
                &target_pkhash,
            ))
            .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
            let nonce_full = h_l(
                "barrier/wrap/nonce",
                &BarrierWrapNoncePreimage(source_node, target_node),
            )
            .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_full[..12]);

            let source_secret = path_secrets
                .get(&source_node)
                .ok_or_else(|| anyhow!("missing path secret for source node {source_node}"))?;
            let cipher = ChaCha20Poly1305::new((&ss_bytes).into());
            let wrapped_ps = match cipher.encrypt(
                (&nonce).into(),
                Payload {
                    msg: source_secret.as_slice(),
                    aad: aad.as_slice(),
                },
            ) {
                Ok(wrapped_ps) => wrapped_ps,
                Err(_) => {
                    ss_bytes.zeroize();
                    return Err(anyhow!("barrier wrap encrypt failed"));
                }
            };
            ss_bytes.zeroize();
            node_ciphertexts.push(NodeCiphertextWire(
                source_node,
                target_node,
                target_pkhash[..16].to_vec(),
                KemCiphertext::as_bytes(&kem_ct).to_vec(),
                wrapped_ps,
            ));
        }
    }
    node_ciphertexts.sort_by_key(|entry| (entry.0, entry.1));

    let cover_payload = KemTreeCoverPayloadWire(
        updater_leaf,
        updater_slot_generation,
        path_nodes,
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover_payload).context("encode barrier cover payload")?;

    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        barrier_version,
        prev_barrier_version,
        n_max,
        revocation_roots_hash.to_vec(),
        kem_tree_hash_before.to_vec(),
        kem_tree_hash_after.to_vec(),
        cover_bytes,
    );
    let raw_update = to_cbor_vec(&update).context("encode barrier update")?;
    let barrier_update_digest = compute_barrier_update_digest(raw_update.as_slice())?;
    zeroize_path_secret_map(&mut path_secrets);

    Ok(BarrierUpdateBuildResult {
        raw_update,
        barrier_update_digest,
        kem_tree_hash_after,
        k_barrier_new: Zeroizing::new(k_barrier_new),
        on_path_key_material,
        snapshot_post,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::barrier_update::parse_barrier_update_for_recover;

    #[test]
    fn build_barrier_update_bytes_handles_single_leaf_tree() -> Result<()> {
        let snapshot_pre = vec![Vec::new()];
        let kem_tree_hash_before = compute_barrier_tree_hash(1, snapshot_pre.as_slice())?;
        let built = build_barrier_update_bytes(
            &[0x11; 32],
            1,
            0,
            0,
            0,
            0,
            [0x22; 32],
            kem_tree_hash_before,
            snapshot_pre.as_slice(),
        )?;
        let parsed = parse_barrier_update_for_recover(built.raw_update.as_slice(), 1, 1_048_576)?;
        assert_eq!(parsed.barrier_version, 0);
        assert_eq!(parsed.prev_barrier_version, 0);
        assert_eq!(parsed.updater_slot_generation, 0);
        assert_eq!(parsed.node_ciphertexts.len(), 0);
        assert_eq!(parsed.new_public_keys.len(), 0);
        assert_eq!(
            compute_barrier_update_digest(built.raw_update.as_slice())?,
            built.barrier_update_digest
        );
        Ok(())
    }

    #[test]
    fn build_barrier_update_bytes_builds_ciphertexts_for_resolution_targets() -> Result<()> {
        let gid = [0x33; 32];
        let rrh = [0x55; 32];
        let (_, _, ek_leaf) =
            derive_internal_node_key_material(gid.as_slice(), &[0x44; 32], 4, &rrh, 2, 2)?;
        let snapshot_pre = vec![Vec::new(), Vec::new(), ek_leaf];
        let kem_tree_hash_before = compute_barrier_tree_hash(2, snapshot_pre.as_slice())?;
        let built = build_barrier_update_bytes(
            &gid,
            2,
            0,
            0,
            5,
            4,
            rrh,
            kem_tree_hash_before,
            &snapshot_pre,
        )?;
        let parsed = parse_barrier_update_for_recover(built.raw_update.as_slice(), 2, 1_048_576)?;
        assert_eq!(parsed.barrier_version, 5);
        assert_eq!(parsed.prev_barrier_version, 4);
        assert_eq!(parsed.updater_slot_generation, 0);
        assert_eq!(parsed.node_ciphertexts.len(), 1);
        assert!(parsed.new_public_keys.contains_key(&0));
        assert_eq!(built.on_path_key_material.len(), 1);
        assert!(built.on_path_key_material.contains_key(&0));
        assert_eq!(built.snapshot_post.len(), 3);
        assert_eq!(
            compute_barrier_tree_hash(2, built.snapshot_post.as_slice())?,
            built.kem_tree_hash_after
        );
        Ok(())
    }
}
