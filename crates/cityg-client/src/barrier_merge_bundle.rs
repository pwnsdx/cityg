use std::collections::BTreeMap;

use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use anyhow::{Result, anyhow};
use ciborium::value::Value;
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, OrchestrationParams, PivotParity, derive_we_epoch_id,
    hdr,
};
use zeroize::Zeroizing;

use crate::barrier_crypto::derive_k_fs_after_pcs;
use crate::bundle_headers::{recompute_proofs_commit, recompute_srx_commit};
use crate::pivot::{apply_pivot_alignment, strip_rollup_metadata};
use crate::{CityGClient, ClientEpochBundle};

pub struct BarrierMergeBundleInputs<'a> {
    pub header: BTreeMap<u64, Value>,
    pub parts: AnchorInstanceParts<'a>,
    pub params: OrchestrationParams<'a>,
    pub forward_state: ForwardSecrecyState,
    pub parities: &'a [PivotParity],
    pub witness_bytes: Option<&'a [u8]>,
    pub pivot: &'a PivotParity,
    pub gid: &'a [u8; 32],
    pub cat: &'a [u8; 32],
    pub parent_root: &'a [u8; 32],
    pub current_k_fs: Option<&'a [u8; 32]>,
    pub next_barrier_version: u64,
    pub barrier_key: &'a [u8; 32],
    pub barrier_update_reason: u64,
    pub disable_autonomic_evolve: bool,
}

pub struct PreparedBarrierMergeBundle {
    pub bundle: ClientEpochBundle,
    pub forward_state_after: ForwardSecrecyState,
    pub observed_fs_ec: u64,
    pub k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
}

fn header_u64(header: &BTreeMap<u64, Value>, key: u64) -> Option<u64> {
    match header.get(&key)? {
        Value::Integer(int) => (*int).try_into().ok(),
        _ => None,
    }
}

pub fn build_barrier_merge_bundle(
    inputs: BarrierMergeBundleInputs<'_>,
) -> Result<PreparedBarrierMergeBundle> {
    let BarrierMergeBundleInputs {
        header,
        parts,
        params,
        mut forward_state,
        parities,
        witness_bytes,
        pivot,
        gid,
        cat,
        parent_root,
        current_k_fs,
        next_barrier_version,
        barrier_key,
        barrier_update_reason,
        disable_autonomic_evolve,
    } = inputs;

    let mut bundle = if disable_autonomic_evolve {
        CityGClient::generate_merge_with_forward_state_without_evolve(
            header,
            parts,
            params,
            Some(&mut forward_state),
            parities,
            None,
            witness_bytes,
        )
    } else {
        CityGClient::generate_merge_with_forward_state(
            header,
            parts,
            params,
            Some(&mut forward_state),
            parities,
            None,
            witness_bytes,
        )
    }?;

    strip_rollup_metadata(&mut bundle.header_map);
    apply_pivot_alignment(&mut bundle.header_map, pivot);
    let anchor_ctx = build_anchor_seed_ctx(&bundle.header_map)?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_ctx)?;
    let seed_commit = compute_seed_commit(
        &anchor_ctx,
        &SeedCommitFields {
            gid,
            cat: cat.as_slice(),
            we_epoch_id: bundle.we_epoch_id,
        },
    )?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &anchor_ctx,
        &bundle.hp_binding.rho_commit,
        gid,
        cat.as_slice(),
        parent_root,
    )?;
    let derived_we_epoch_id = derive_we_epoch_id(gid, parent_root, &seed_ctx_hash)?;
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC)
        .ok_or_else(|| anyhow!("merge bundle missing fs_ec"))?;
    let k_fs_after_pcs = current_k_fs
        .map(|k_fs_current| {
            derive_k_fs_after_pcs(
                k_fs_current,
                &derived_we_epoch_id,
                observed_fs_ec,
                next_barrier_version,
                barrier_key,
            )
            .map(Zeroizing::new)
        })
        .transpose()?;

    bundle.anchor.anchor_hdr_ctx = anchor_ctx;
    bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
    bundle.hp_binding.seed_commit = seed_commit;
    bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
    bundle.we_epoch_id = derived_we_epoch_id;
    let has_local_hp_material = !bundle.hp_ciphertext.is_empty() && bundle.hp_aead_key != [0u8; 32];
    if !has_local_hp_material {
        return Err(anyhow!("merge bundle missing local HP material"));
    }
    if barrier_update_reason == 2 {
        bundle.seal_local_hp_header_with_barrier_key(barrier_key)?;
    } else {
        bundle.rebind_local_hp_envelope_with_barrier_key(barrier_key)?;
    }

    bundle.header_map.insert(
        hdr::HDR_SEED_CTX_HASH,
        Value::Bytes(bundle.hp_binding.seed_ctx_hash.to_vec()),
    );
    bundle.header_map.insert(
        hdr::HDR_RHO_COMMIT,
        Value::Bytes(bundle.hp_binding.rho_commit.to_vec()),
    );
    bundle.header_map.insert(
        hdr::HDR_SEED_BUNDLE_COMMIT,
        Value::Bytes(bundle.hp_binding.seed_bundle_commit.to_vec()),
    );

    if let Some(commit) = recompute_srx_commit(&bundle.header_map)? {
        bundle
            .header_map
            .insert(hdr::HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
    }
    if let Some(recomputed) = recompute_proofs_commit(&bundle.header_map)
        .ok()
        .map(|arr| arr.to_vec())
    {
        bundle
            .header_map
            .insert(hdr::HDR_PROOFS_COMMIT, Value::Bytes(recomputed));
    }

    Ok(PreparedBarrierMergeBundle {
        bundle,
        forward_state_after: forward_state,
        observed_fs_ec,
        k_fs_after_pcs,
    })
}
