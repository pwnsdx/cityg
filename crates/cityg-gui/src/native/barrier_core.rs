use super::*;
use crate::barrier_shared::{
    require_current_state_history_commitment, require_same_history_commitment,
};

pub(super) const BARRIER_KEYGEN_D_INFO: &[u8] = b"city-g|barrier/keygen-d|v1";
pub(super) const BARRIER_KEYGEN_Z_INFO: &[u8] = b"city-g|barrier/keygen-z|v1";
pub(super) const FS_PCS_INFO: &[u8] = b"city-g|fs/pcs|v1";
pub(super) const ML_KEM_SEED_BYTES: usize = 64;
pub(super) const ML_KEM_EXPANDED_DK_BYTES: usize = 2400;
pub(super) const BARRIER_CODE_RECOVER_NO_MATCH: u32 = 9606;
pub(super) const BARRIER_CODE_SNAPSHOT_AUTH_FAILURE: u32 = 9609;

#[derive(Serialize)]
struct BarrierUpdateDigestPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize)]
pub(super) struct BarrierWrapNoncePreimage(pub(super) u64, pub(super) u64);

#[derive(Serialize)]
pub(super) struct BarrierWrapAadPreimage<'a>(
    #[serde(with = "serde_bytes")] pub(super) &'a [u8; 32],
    pub(super) u64,
    #[serde(with = "serde_bytes")] pub(super) &'a [u8; 32],
    pub(super) u64,
    pub(super) u64,
    pub(super) u64,
    #[serde(with = "serde_bytes")] pub(super) &'a [u8; 32],
);

#[derive(Serialize)]
struct FsPcsSaltPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8; 32], u64, u64);

#[derive(Serialize)]
struct BarrierKeygenSaltPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    u64,
);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct BarrierUpdateWire(
    pub(super) String,
    pub(super) u64,
    pub(super) u64,
    pub(super) u64,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct KemTreeCoverPayloadWire(
    pub(super) u64,
    pub(super) Vec<u64>,
    pub(super) Option<Vec<u64>>,
    pub(super) Vec<NodeCiphertextWire>,
    pub(super) Vec<NewPublicKeyWire>,
);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct NodeCiphertextWire(
    pub(super) u64,
    pub(super) u64,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct NewPublicKeyWire(
    pub(super) u64,
    #[serde(with = "serde_bytes")] pub(super) Vec<u8>,
);

#[derive(Clone, Debug)]
pub(super) struct ParsedNodeCiphertext {
    pub(super) source_node: u64,
    pub(super) target_node: u64,
    pub(super) target_pk_hash: [u8; 16],
    pub(super) kem_ct: Vec<u8>,
    pub(super) wrapped_ps: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) struct ParsedBarrierUpdate {
    pub(super) barrier_version: u64,
    pub(super) prev_barrier_version: u64,
    pub(super) tree_size: u64,
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) kem_tree_hash_before: [u8; 32],
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) updater_leaf: u64,
    pub(super) path_nodes: Vec<u64>,
    pub(super) node_ciphertexts: Vec<ParsedNodeCiphertext>,
    pub(super) new_public_keys: BTreeMap<u64, Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(super) struct BarrierRecoverResult {
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    pub(super) derived_node_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone, Debug)]
pub(super) struct BarrierUpdateBuildResult {
    pub(super) raw_update: Vec<u8>,
    pub(super) barrier_update_digest: [u8; 32],
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pub(super) snapshot_post: Arc<BarrierPublicTree>,
}

#[derive(Clone, Debug)]
pub(super) struct FullChainCheckResult {
    pub(super) expected_before: [u8; 32],
    pub(super) snapshot_post: Arc<BarrierPublicTree>,
}

pub(super) fn compute_barrier_update_digest(raw_update: &[u8]) -> Result<[u8; 32]> {
    h_l(
        "barrier/update/digest",
        &BarrierUpdateDigestPreimage(raw_update),
    )
    .map_err(|err| anyhow!("compute barrier_update_digest: {err}"))
}

pub(super) fn validate_barrier_tree_snapshot_auth(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: &BarrierPublicTree,
) -> Result<()> {
    if snapshot.kem_tree_hash_after != *expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): hash mismatch"
        ));
    }
    let computed_hash = compute_barrier_tree_hash(expected_n_max, snapshot.pk_entries.as_slice())?;
    if computed_hash != *expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): tree hash mismatch"
        ));
    }
    Ok(())
}

pub(super) fn current_public_tree_cache_matches(
    session: &AppSession,
    snapshot: &BarrierPublicTree,
) -> bool {
    snapshot.n_max == session.barrier_state.n_max.max(1)
        && snapshot.kem_tree_hash_after == session.barrier_state.kem_tree_hash_after
}

pub(super) fn current_public_tree_cache(session: &AppSession) -> Option<Arc<BarrierPublicTree>> {
    session
        .barrier_state
        .current_public_tree
        .as_ref()
        .filter(|snapshot| current_public_tree_cache_matches(session, snapshot))
        .cloned()
}

const MAX_RETAINED_LOCAL_PUBLIC_TREE_SNAPSHOTS: usize = 8;

fn retained_public_tree_cache_matches(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: &BarrierPublicTree,
) -> bool {
    snapshot.n_max == expected_n_max.max(1) && snapshot.kem_tree_hash_after == *expected_hash
}

fn retain_public_tree_snapshot(
    state: &mut BarrierSecretState,
    barrier_version: u64,
    history_commitment: Option<HistoryCommitment>,
    snapshot: Arc<BarrierPublicTree>,
) {
    state.retained_public_trees.retain(|entry| {
        !retained_public_tree_cache_matches(
            &snapshot.kem_tree_hash_after,
            snapshot.n_max,
            entry.snapshot.as_ref(),
        )
    });
    state.retained_public_trees.insert(
        0,
        RetainedBarrierPublicTree {
            barrier_version,
            history_commitment,
            snapshot,
        },
    );
    state
        .retained_public_trees
        .truncate(MAX_RETAINED_LOCAL_PUBLIC_TREE_SNAPSHOTS);
}

pub(super) fn retain_authenticated_current_public_tree(session: &mut AppSession) -> Result<()> {
    let snapshot = current_public_tree_cache(session).ok_or_else(|| {
        anyhow!(
            "cannot retain authenticated current public tree without a matching cached snapshot"
        )
    })?;
    let history_commitment = session
        .barrier_state
        .current_history_commitment
        .ok_or_else(|| {
            anyhow!("cannot retain authenticated current public tree without HistoryCommitment")
        })?;
    let barrier_version = session.barrier_state.barrier_version;
    retain_public_tree_snapshot(
        &mut session.barrier_state,
        barrier_version,
        Some(history_commitment),
        snapshot,
    );
    Ok(())
}

pub(super) fn retain_tree_hash_authenticated_public_tree(
    state: &mut BarrierSecretState,
    barrier_version: u64,
    snapshot: Arc<BarrierPublicTree>,
) {
    retain_public_tree_snapshot(state, barrier_version, None, snapshot);
}

pub(super) fn retained_authenticated_current_public_tree_cache(
    session: &AppSession,
) -> Option<(Arc<BarrierPublicTree>, HistoryCommitment)> {
    let current_history_commitment = session.barrier_state.current_history_commitment?;
    session
        .barrier_state
        .retained_public_trees
        .iter()
        .find(|entry| {
            entry.barrier_version == session.barrier_state.barrier_version
                && entry.history_commitment == Some(current_history_commitment)
                && retained_public_tree_cache_matches(
                    &session.barrier_state.kem_tree_hash_after,
                    session.barrier_state.n_max,
                    entry.snapshot.as_ref(),
                )
        })
        .map(|entry| (entry.snapshot.clone(), current_history_commitment))
}

pub(super) fn retained_public_tree_cache(
    session: &AppSession,
    expected_hash: &[u8; 32],
    expected_n_max: u64,
) -> Option<Arc<BarrierPublicTree>> {
    current_public_tree_cache(session)
        .filter(|snapshot| {
            retained_public_tree_cache_matches(expected_hash, expected_n_max, snapshot)
        })
        .or_else(|| {
            session
                .barrier_state
                .retained_public_trees
                .iter()
                .find(|entry| {
                    retained_public_tree_cache_matches(
                        expected_hash,
                        expected_n_max,
                        entry.snapshot.as_ref(),
                    )
                })
                .map(|entry| entry.snapshot.clone())
        })
}

pub(super) fn clear_current_public_tree_cache(state: &mut BarrierSecretState) {
    state.current_public_tree = None;
}

pub(super) fn clear_all_public_tree_caches(state: &mut BarrierSecretState) {
    state.current_public_tree = None;
    state.retained_public_trees.clear();
}

pub(super) fn install_current_public_tree_cache(
    session: &mut AppSession,
    snapshot: BarrierPublicTree,
) -> Result<()> {
    validate_barrier_tree_snapshot_auth(
        &session.barrier_state.kem_tree_hash_after,
        session.barrier_state.n_max.max(1),
        &snapshot,
    )?;
    session.barrier_state.current_public_tree = Some(Arc::new(snapshot));
    Ok(())
}

pub(super) fn expected_same_rrh_barrier_reason(
    join_records: &[BarrierJoinRecord],
    updater_leaf: u64,
) -> u64 {
    if join_records
        .iter()
        .any(|record| u64::from(record.leaf_index) == updater_leaf)
    {
        2
    } else {
        1
    }
}

pub(super) fn zeroize_path_secret_map(path_secrets: &mut BTreeMap<u64, [u8; 32]>) {
    for secret in path_secrets.values_mut() {
        secret.zeroize();
    }
}

pub(super) fn parse_deterministic_cbor<T>(raw: &[u8], label: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let decoded: T =
        ciborium::de::from_reader(raw).map_err(|err| anyhow!("failed to parse {label}: {err}"))?;
    let canonical = to_cbor_vec(&decoded)
        .map_err(|err| anyhow!("failed to re-encode canonical {label}: {err}"))?;
    if canonical.as_slice() != raw {
        return Err(anyhow!("non-canonical {label} encoding"));
    }
    Ok(decoded)
}

pub(super) fn to_array32(label: &str, bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes"))
}

pub(super) fn to_array16(label: &str, bytes: Vec<u8>) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 16 bytes"))
}

pub(super) fn normalize_max_barrier_update_bytes(limit: u64) -> Result<usize> {
    if limit == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }
    usize::try_from(limit).map_err(|_| anyhow!("max_barrier_update_bytes is too large"))
}

pub(super) fn parse_barrier_update_for_recover(
    raw_update: &[u8],
    expected_n_max: u64,
    max_barrier_update_bytes: usize,
) -> Result<ParsedBarrierUpdate> {
    if raw_update.len() > max_barrier_update_bytes {
        return Err(anyhow!(
            "barrier_update exceeds max_barrier_update_bytes: {} > {}",
            raw_update.len(),
            max_barrier_update_bytes
        ));
    }
    let expected_n_max = validate_barrier_n_max(expected_n_max)?;

    let BarrierUpdateWire(
        mode,
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash,
        kem_tree_hash_before,
        kem_tree_hash_after,
        cover_payload,
    ) = parse_deterministic_cbor(raw_update, "barrier_update")?;

    if mode != "barrier-v1" {
        return Err(anyhow!("unsupported barrier update mode: {mode}"));
    }
    if tree_size != expected_n_max {
        return Err(anyhow!(
            "barrier tree_size mismatch: expected {expected_n_max}, got {tree_size}"
        ));
    }

    let KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        _revoked_leaf_indices_hint,
        node_ciphertexts_wire,
        new_public_keys,
    ) = parse_deterministic_cbor(cover_payload.as_slice(), "barrier cover payload")?;

    if updater_leaf >= expected_n_max {
        return Err(anyhow!("barrier updater_leaf out of range"));
    }

    let expected_nodes = expected_n_max
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("barrier tree size overflow"))?;
    let max_index = expected_nodes.saturating_sub(1);
    let leaf_base = expected_n_max.saturating_sub(1);
    let expected_leaf = leaf_base.saturating_add(updater_leaf);

    if path_nodes.is_empty() {
        return Err(anyhow!("barrier path_nodes must be non-empty"));
    }
    if path_nodes.first().copied() != Some(expected_leaf) {
        return Err(anyhow!(
            "barrier path_nodes must start at updater leaf node"
        ));
    }
    if path_nodes.last().copied() != Some(0) {
        return Err(anyhow!("barrier path_nodes must end at root node"));
    }
    let mut path_seen = HashSet::new();
    for &node in &path_nodes {
        if node > max_index {
            return Err(anyhow!("barrier path node out of range"));
        }
        if !path_seen.insert(node) {
            return Err(anyhow!("barrier path_nodes contains duplicate nodes"));
        }
    }
    for pair in path_nodes.windows(2) {
        let child = pair[0];
        let parent = pair[1];
        if child == 0 || (child - 1) / 2 != parent {
            return Err(anyhow!("barrier path_nodes parent chain is invalid"));
        }
    }

    let expected_public_nodes: HashSet<u64> = path_nodes.iter().copied().skip(1).collect();
    if new_public_keys.len() != expected_public_nodes.len() {
        return Err(anyhow!(
            "barrier new_public_keys length does not match ExpectedNodeSet"
        ));
    }
    let mut seen_public_nodes = HashSet::new();
    let mut prev_public_node: Option<u64> = None;
    let mut parsed_new_public_keys = BTreeMap::new();
    for NewPublicKeyWire(node_index, ek) in &new_public_keys {
        if *node_index > max_index {
            return Err(anyhow!("barrier new_public_keys node out of range"));
        }
        if *node_index >= leaf_base {
            return Err(anyhow!(
                "barrier new_public_keys may reference only internal nodes"
            ));
        }
        if ek.len() != kyber768::public_key_bytes() {
            return Err(anyhow!(
                "barrier new_public_keys ek must be ML-KEM-768 length"
            ));
        }
        if prev_public_node.is_some_and(|prev| prev >= *node_index) {
            return Err(anyhow!(
                "barrier new_public_keys must be sorted by node index"
            ));
        }
        prev_public_node = Some(*node_index);
        if !seen_public_nodes.insert(*node_index) {
            return Err(anyhow!(
                "barrier new_public_keys contains duplicate node index"
            ));
        }
        parsed_new_public_keys.insert(*node_index, ek.clone());
    }
    if seen_public_nodes != expected_public_nodes {
        return Err(anyhow!(
            "barrier new_public_keys must match ExpectedNodeSet exactly"
        ));
    }

    let mut node_ciphertexts = Vec::with_capacity(node_ciphertexts_wire.len());
    let mut prev_pair: Option<(u64, u64)> = None;
    for NodeCiphertextWire(source_node, target_node, target_pk_hash, kem_ct, wrapped_ps) in
        node_ciphertexts_wire
    {
        if source_node > max_index || target_node > max_index {
            return Err(anyhow!("barrier node_ciphertext index out of range"));
        }
        if target_pk_hash.len() != 16 {
            return Err(anyhow!("barrier target_pk_hash must be 16 bytes"));
        }
        if kem_ct.len() != kyber768::ciphertext_bytes() {
            return Err(anyhow!("barrier kem_ct length mismatch"));
        }
        if wrapped_ps.len() != 48 {
            return Err(anyhow!("barrier wrapped_ps must be 48 bytes"));
        }
        let pair = (source_node, target_node);
        if prev_pair.is_some_and(|prev| prev >= pair) {
            return Err(anyhow!(
                "barrier node_ciphertexts must be sorted and duplicate-free"
            ));
        }
        prev_pair = Some(pair);
        node_ciphertexts.push(ParsedNodeCiphertext {
            source_node,
            target_node,
            target_pk_hash: to_array16("target_pk_hash", target_pk_hash)?,
            kem_ct,
            wrapped_ps,
        });
    }

    Ok(ParsedBarrierUpdate {
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash: to_array32("revocation_roots_hash", revocation_roots_hash)?,
        kem_tree_hash_before: to_array32("kem_tree_hash_before", kem_tree_hash_before)?,
        kem_tree_hash_after: to_array32("kem_tree_hash_after", kem_tree_hash_after)?,
        updater_leaf,
        path_nodes,
        node_ciphertexts,
        new_public_keys: parsed_new_public_keys,
    })
}

pub(super) async fn full_chain_check_barrier_update(
    client: &CitygApiClient,
    room_id: &str,
    session: &mut AppSession,
    header_map: &BTreeMap<u64, Value>,
    raw_update: &[u8],
    max_barrier_update_bytes: usize,
) -> Result<FullChainCheckResult> {
    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)
        .map_err(|err| anyhow!("barrier full chain-check prevalidation failed (960.7): {err}"))?;
    let local_barrier_version = session.barrier_state.barrier_version;
    let local_barrier_initialized = session.barrier_state.barrier_initialized;
    let barrier_reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing barrier_update_reason")
    })?;
    let genesis_local_case = !local_barrier_initialized
        && parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0;
    let valid_local_progression = genesis_local_case
        || (local_barrier_initialized
            && parsed.prev_barrier_version == local_barrier_version
            && parsed.barrier_version == local_barrier_version.saturating_add(1));
    if !valid_local_progression {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): local barrier version progression mismatch"
        ));
    }

    let h_prev = session.barrier_state.kem_tree_hash_after;
    let (snapshot_prev, snapshot_prev_history_commitment) = if let Some(snapshot_prev) =
        current_public_tree_cache(session)
    {
        let current_history_commitment = session
            .barrier_state
            .current_history_commitment
            .ok_or_else(|| {
                anyhow!(
                    "barrier tree snapshot auth failure (960.9): missing authenticated current-state history commitment for cached current public tree"
                )
            })?;
        ((*snapshot_prev).clone(), current_history_commitment)
    } else if let Some((snapshot_prev, current_history_commitment)) =
        retained_authenticated_current_public_tree_cache(session)
    {
        ((*snapshot_prev).clone(), current_history_commitment)
    } else {
        let snapshot_prev_response = client
            .barrier_fetch_public_tree(room_id, &h_prev)
            .await
            .map_err(|err| anyhow!("barrier tree snapshot auth failure (960.9): {err}"))?;
        let snapshot_prev = snapshot_prev_response.tree;
        if snapshot_prev.n_max != n_max {
            return Err(anyhow!(
                "barrier tree snapshot auth failure (960.9): n_max mismatch (expected {n_max}, got {})",
                snapshot_prev.n_max
            ));
        }
        validate_barrier_tree_snapshot_auth(&h_prev, n_max, &snapshot_prev)?;
        (snapshot_prev, snapshot_prev_response.history_commitment)
    };

    let revoked_since_root =
        header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT).ok_or_else(|| {
            anyhow!(
                "barrier full chain-check prevalidation failed (960.7): missing revoked_since_root"
            )
        })?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing revoked_root")
    })?;
    let revocation_roots_hash = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != revocation_roots_hash {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): revocation_roots_hash mismatch"
        ));
    }
    let join_resolution = client
        .barrier_resolve_joins_since(room_id, parsed.prev_barrier_version)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(room_id, &revocation_roots_hash)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    if require_current_state_history_commitment(
        &snapshot_prev_history_commitment,
        &join_resolution.history_commitment,
        &revoked_resolution.history_commitment,
    )
    .is_err()
    {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.9): snapshot / joins / revoked leaves do not share one authenticated current-state history commitment"
        ));
    }

    if !genesis_local_case {
        if session.barrier_state.barrier_roots_hash == parsed.revocation_roots_hash {
            let expected_reason = expected_same_rrh_barrier_reason(
                join_resolution.records.as_slice(),
                parsed.updater_leaf,
            );
            if barrier_reason != expected_reason {
                return Err(anyhow!(
                    "barrier full chain-check prevalidation failed (960.7): local barrier_roots_hash unchanged but barrier_update_reason != {expected_reason}"
                ));
            }
        } else if barrier_reason != 0 {
            return Err(anyhow!(
                "barrier full chain-check prevalidation failed (960.7): local barrier_roots_hash changed but barrier_update_reason != 0"
            ));
        }
    }

    let parsed_for_hash = parsed.clone();
    let snapshot_prev_entries = snapshot_prev.pk_entries.clone();
    let (expected_before, expected_after, snapshot_post) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32], BarrierPublicTree)> {
            let mut snapshot_pre = snapshot_prev_entries;
            apply_join_set_to_snapshot(
                snapshot_pre.as_mut_slice(),
                n_max,
                join_resolution.records.as_slice(),
            )?;
            apply_revoked_set_to_snapshot(
                snapshot_pre.as_mut_slice(),
                n_max,
                revoked_resolution.leaf_indices.as_slice(),
            )?;
            let expected_before = compute_barrier_tree_hash(n_max, snapshot_pre.as_slice())?;

            let mut snapshot_post = snapshot_pre;
            for (node, ek) in &parsed_for_hash.new_public_keys {
                let index = usize::try_from(*node)
                    .map_err(|_| anyhow!("barrier node index out of range"))?;
                let slot = snapshot_post
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("barrier node index out of range"))?;
                *slot = ek.clone();
            }
            let expected_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

            Ok((
                expected_before,
                expected_after,
                BarrierPublicTree {
                    n_max,
                    kem_tree_hash_after: expected_after,
                    pk_entries: snapshot_post,
                },
            ))
        })
        .await
        .map_err(|err| anyhow!("barrier full chain-check worker join failure (960.8): {err}"))??;

    if expected_before != parsed.kem_tree_hash_before {
        return Err(anyhow!(
            "barrier tree hash-chain failure (960.8): kem_tree_hash_before mismatch"
        ));
    }
    if expected_after != parsed.kem_tree_hash_after {
        return Err(anyhow!(
            "barrier tree hash-chain failure (960.8): kem_tree_hash_after mismatch"
        ));
    }

    Ok(FullChainCheckResult {
        expected_before,
        snapshot_post: Arc::new(snapshot_post),
    })
}

pub(super) async fn verify_join_finalize_bootstrap_current_state(
    client: &CitygApiClient,
    room_id: &str,
    session: &mut AppSession,
) -> Result<()> {
    let expected_commitment = session
        .barrier_state
        .bootstrap_history_commitment
        .ok_or_else(|| anyhow!("join_finalize bootstrap missing current_history_commitment"))?;
    let current_commitment = session
        .barrier_state
        .current_history_commitment
        .as_ref()
        .ok_or_else(|| {
            anyhow!("join_finalize bootstrap missing local current_history_commitment")
        })?;
    let predecessor_hash = session
        .barrier_state
        .bootstrap_predecessor_kem_tree_hash_after;
    require_same_history_commitment(current_commitment, &expected_commitment)
        .map_err(|_| anyhow!("join_finalize bootstrap current_history_commitment mismatch"))?;
    if predecessor_hash == [0u8; 32] {
        return Err(anyhow!(
            "join_finalize bootstrap missing predecessor committed kem_tree_hash_after"
        ));
    }
    if session
        .barrier_state
        .bootstrap_current_barrier_update
        .is_empty()
    {
        return Err(anyhow!(
            "join_finalize bootstrap missing current barrier_update bytes"
        ));
    }

    let n_max = session.barrier_state.n_max.max(1);
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(session.barrier_state.max_barrier_update_bytes.max(1))?;
    let parsed = parse_barrier_update_for_recover(
        session
            .barrier_state
            .bootstrap_current_barrier_update
            .as_slice(),
        n_max,
        max_barrier_update_bytes,
    )
    .map_err(|err| anyhow!("join_finalize bootstrap verification failed (960.7): {err}"))?;

    if parsed.barrier_version != session.barrier_state.barrier_version {
        return Err(anyhow!(
            "join_finalize bootstrap verification failed (960.7): current barrier_version mismatch"
        ));
    }
    if parsed.kem_tree_hash_after != session.barrier_state.kem_tree_hash_after {
        return Err(anyhow!(
            "join_finalize bootstrap verification failed (960.7): current kem_tree_hash_after mismatch"
        ));
    }

    let current_snapshot =
        if let Some((snapshot, _)) = retained_authenticated_current_public_tree_cache(session) {
            (*snapshot).clone()
        } else {
            let current_snapshot_response = client
                .barrier_fetch_public_tree(room_id, &session.barrier_state.kem_tree_hash_after)
                .await
                .map_err(|err| {
                    anyhow!("join_finalize bootstrap snapshot auth failure (960.9): {err}")
                })?;
            if current_snapshot_response.tree.n_max != n_max {
                return Err(anyhow!(
                    "join_finalize bootstrap snapshot auth failure (960.9): current n_max mismatch"
                ));
            }
            current_snapshot_response.tree
        };
    if current_snapshot.n_max != n_max {
        return Err(anyhow!(
            "join_finalize bootstrap snapshot auth failure (960.9): current n_max mismatch"
        ));
    }
    validate_barrier_tree_snapshot_auth(
        &session.barrier_state.kem_tree_hash_after,
        n_max,
        &current_snapshot,
    )?;
    // The provisioned current barrier_update bytes already bind the current
    // tree hash. After the JOIN itself is accepted, the same current tree can
    // legitimately be re-attested under a later local HistoryCommitment.

    let snapshot_base = if let Some(snapshot) =
        retained_public_tree_cache(session, &predecessor_hash, n_max)
    {
        (*snapshot).clone()
    } else {
        let snapshot_base_response = client
            .barrier_fetch_public_tree(room_id, &predecessor_hash)
            .await
            .map_err(|err| {
                anyhow!("join_finalize bootstrap snapshot auth failure (960.9): {err}")
            })?;
        if snapshot_base_response.tree.n_max != n_max {
            return Err(anyhow!(
                "join_finalize bootstrap snapshot auth failure (960.9): predecessor n_max mismatch"
            ));
        }
        validate_barrier_tree_snapshot_auth(
            &predecessor_hash,
            n_max,
            &snapshot_base_response.tree,
        )?;
        retain_tree_hash_authenticated_public_tree(
            &mut session.barrier_state,
            parsed.prev_barrier_version,
            Arc::new(snapshot_base_response.tree.clone()),
        );
        snapshot_base_response.tree
    };
    if snapshot_base.n_max != n_max {
        return Err(anyhow!(
            "join_finalize bootstrap snapshot auth failure (960.9): predecessor n_max mismatch"
        ));
    }
    validate_barrier_tree_snapshot_auth(&predecessor_hash, n_max, &snapshot_base)?;

    if session.barrier_state.bootstrap_join_records.is_empty()
        && session
            .barrier_state
            .bootstrap_revoked_leaf_indices
            .is_empty()
        && (parsed.prev_barrier_version != 0 || parsed.revocation_roots_hash != [0u8; 32])
    {
        return Err(anyhow!(
            "join_finalize bootstrap missing authenticated JoinSet / RevokedLeafSet provisioning"
        ));
    }

    let join_records = session.barrier_state.bootstrap_join_records.clone();
    let revoked_leaf_indices = session.barrier_state.bootstrap_revoked_leaf_indices.clone();

    let parsed_for_hash = parsed.clone();
    let snapshot_base_entries = snapshot_base.pk_entries.clone();
    let (expected_before, expected_after) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32])> {
            let mut snapshot_pre = snapshot_base_entries;
            apply_join_set_to_snapshot(
                snapshot_pre.as_mut_slice(),
                n_max,
                join_records.as_slice(),
            )?;
            apply_revoked_set_to_snapshot(
                snapshot_pre.as_mut_slice(),
                n_max,
                revoked_leaf_indices.as_slice(),
            )?;
            let expected_before = compute_barrier_tree_hash(n_max, snapshot_pre.as_slice())?;

            let mut snapshot_post = snapshot_pre;
            for (node, ek) in &parsed_for_hash.new_public_keys {
                let index = usize::try_from(*node)
                    .map_err(|_| anyhow!("barrier node index out of range"))?;
                let slot = snapshot_post
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("barrier node index out of range"))?;
                *slot = ek.clone();
            }
            let expected_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;
            Ok((expected_before, expected_after))
        })
        .await
        .map_err(|err| anyhow!("join_finalize bootstrap worker join failure (960.8): {err}"))??;

    if expected_before != parsed.kem_tree_hash_before {
        return Err(anyhow!(
            "join_finalize bootstrap hash-chain failure (960.8): kem_tree_hash_before mismatch"
        ));
    }
    if expected_after != parsed.kem_tree_hash_after {
        return Err(anyhow!(
            "join_finalize bootstrap hash-chain failure (960.8): kem_tree_hash_after mismatch"
        ));
    }

    install_current_public_tree_cache(session, current_snapshot)?;
    retain_authenticated_current_public_tree(session)?;

    Ok(())
}

pub(super) fn self_path_nodes(n_max: u64, cover_leaf_index: u64) -> Vec<u64> {
    let leaf_base = n_max.saturating_sub(1);
    let mut path = vec![leaf_base.saturating_add(cover_leaf_index)];
    while let Some(&node) = path.last() {
        if node == 0 {
            break;
        }
        path.push((node - 1) / 2);
    }
    path
}

pub(super) fn derive_k_fs_after_pcs(
    k_fs_before: &[u8; 32],
    weid: &[u8; 32],
    fs_ec: u64,
    barrier_version: u64,
    k_barrier_new: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(k_fs_before);
    ikm[32..].copy_from_slice(k_barrier_new);
    let salt = h_l(
        "fs/pcs/salt",
        &FsPcsSaltPreimage(weid, fs_ec, barrier_version),
    )
    .map_err(|err| anyhow!("derive fs pcs salt: {err}"))?;
    Ok(hkdf_blake3(&salt, &ikm, FS_PCS_INFO))
}

pub(super) fn derive_internal_node_key_material(
    gid: &[u8],
    path_secret: &[u8; 32],
    barrier_version: u64,
    revocation_roots_hash: &[u8; 32],
    n_max: u64,
    node: u64,
) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
    let d_salt = h_l(
        "barrier/keygen/d_salt",
        &BarrierKeygenSaltPreimage(gid, barrier_version, revocation_roots_hash, n_max, node),
    )
    .map_err(|err| anyhow!("derive barrier keygen d_salt: {err}"))?;
    let z_salt = h_l(
        "barrier/keygen/z_salt",
        &BarrierKeygenSaltPreimage(gid, barrier_version, revocation_roots_hash, n_max, node),
    )
    .map_err(|err| anyhow!("derive barrier keygen z_salt: {err}"))?;
    let d = hkdf_blake3(&d_salt, path_secret, BARRIER_KEYGEN_D_INFO);
    let z = hkdf_blake3(&z_salt, path_secret, BARRIER_KEYGEN_Z_INFO);
    let mut seed_bytes = [0u8; ML_KEM_SEED_BYTES];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);

    let dk = MlKem768DecapsulationKey::from_seed(MlKemSeed::from(seed_bytes));
    #[allow(deprecated)]
    let dk_expanded =
        <MlKem768DecapsulationKey as ml_kem::ExpandedKeyEncoding>::to_expanded_bytes(&dk);
    let ek_bytes = dk.encapsulation_key().to_bytes();
    let pkhash = compute_barrier_pkhash(ek_bytes.as_slice())?;
    Ok((
        dk_expanded.as_slice().to_vec(),
        pkhash,
        ek_bytes.as_slice().to_vec(),
    ))
}

pub(super) fn decapsulate_internal_node_shared_secret(
    dk_expanded_bytes: &[u8],
    kem_ct: &[u8],
) -> Result<[u8; 32]> {
    let expanded: MlKemExpandedDecapsulationKey<ml_kem_768::MlKem768> = dk_expanded_bytes
        .try_into()
        .map_err(|_| anyhow!("internal dk_n must be 2400 bytes"))?;
    #[allow(deprecated)]
    let dk =
        <MlKem768DecapsulationKey as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
            .map_err(|_| anyhow!("invalid internal dk_n encoding"))?;
    let shared = dk
        .decapsulate_slice(kem_ct)
        .map_err(|_| anyhow!("invalid internal node ciphertext"))?;
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared.as_slice());
    Ok(ss)
}
