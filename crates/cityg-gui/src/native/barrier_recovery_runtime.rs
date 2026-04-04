use super::*;
use cityg_client::barrier_recovery::{
    BarrierRecoverResult as CoreBarrierRecoverResult,
    BarrierRecoveryInput as CoreBarrierRecoveryInput,
    BarrierRecoveryNodeMaterialRef as CoreBarrierRecoveryNodeMaterialRef,
    recover_barrier_update as recover_barrier_update_core,
};

pub(super) fn try_recover_barrier_from_header_with_expected_before(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        expected_before_hash,
        false,
    )
}

/// Best-effort barrier recovery that skips local version progression and
/// hash-chain checks. Used when the client is behind by multiple barrier
/// versions and cannot validate the chain, but can still attempt to decrypt
/// the barrier update using its leaf KEM key.
pub(super) fn try_recover_barrier_best_effort(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
        true,
    )
}

pub(super) fn try_recover_barrier_inner(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
    skip_local_checks: bool,
) -> Result<Option<BarrierRecoverResult>> {
    let raw_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
        None => return Ok(None),
    };
    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| anyhow!("barrier_update_reason is missing or malformed"))?;
    let revoked_since_root = header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT)
        .ok_or_else(|| anyhow!("header revoked_since_prev_root is missing or malformed"))?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT)
        .ok_or_else(|| anyhow!("header revoked_root is missing or malformed"))?;
    let core_local_node_materials = session
        .barrier_state
        .dk_nodes
        .iter()
        .map(|(node, material)| {
            (
                *node,
                CoreBarrierRecoveryNodeMaterialRef {
                    dk: material.dk.as_slice(),
                    pkhash: material.pkhash,
                },
            )
        })
        .collect();

    match recover_barrier_update_core(CoreBarrierRecoveryInput {
        gid: &session.gid,
        local_n_max: session.barrier_state.n_max,
        local_cover_leaf_index: session.barrier_state.cover_leaf_index,
        local_slot_generation: session.barrier_state.slot_generation,
        local_barrier_initialized: session.barrier_state.barrier_initialized,
        local_barrier_version: session.barrier_state.barrier_version,
        local_barrier_roots_hash: session.barrier_state.barrier_roots_hash,
        local_kem_tree_hash_after: session.barrier_state.kem_tree_hash_after,
        local_pop_public_key: session.pop_public_key.as_slice(),
        local_leaf_material: CoreBarrierRecoveryNodeMaterialRef {
            dk: session.barrier_state.dk_leaf.as_slice(),
            pkhash: session.barrier_state.pkhash_leaf,
        },
        local_node_materials: core_local_node_materials,
        local_k_fs_before: session.forward_state.snapshot().k_fs,
        weid,
        fs_ec,
        raw_update,
        barrier_update_reason: reason,
        revoked_since_root,
        revoked_root,
        author_pop_public_key: header_map
            .get(&hdr::HDR_POP_PK)
            .and_then(Value::as_bytes)
            .map(Vec::as_slice),
        max_barrier_update_bytes,
        expected_before_hash,
        skip_local_checks,
    })? {
        Some(CoreBarrierRecoverResult {
            barrier_version,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            derived_node_key_material,
        }) => Ok(Some(BarrierRecoverResult {
            barrier_version,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            derived_node_key_material: derived_node_key_material
                .into_iter()
                .map(|(node, material)| {
                    (
                        node,
                        BarrierNodeKeyMaterial {
                            dk: material.dk,
                            pkhash: material.pkhash,
                        },
                    )
                })
                .collect(),
        })),
        None => {
            if header_map
                .get(&hdr::HDR_POP_PK)
                .and_then(Value::as_bytes)
                .is_some_and(|pk| pk != session.pop_public_key.as_slice())
            {
                warn!(
                    code = BARRIER_CODE_RECOVER_NO_MATCH,
                    "barrier recover produced no matching ciphertext"
                );
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
pub(super) fn try_recover_barrier_from_header(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_from_header_with_expected_before(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
    )
}
