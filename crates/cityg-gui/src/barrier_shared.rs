use std::time::Duration;

use anyhow::{Result, anyhow};
use cityg_api_client::BarrierJoinRecord;
use msphf_core::hash::h_l;
use rand::{RngExt, rng};
use serde::Serialize;

pub const DEFAULT_BARRIER_N_MAX: u64 = 1_024;
pub const BARRIER_TREE_INFO: &[u8] = b"city-g|barrier/tree|v1";
pub const BARRIER_KEY_INFO: &[u8] = b"city-g|barrier/key|v1";
pub const TICKET_RETRY_MAX_ATTEMPTS: u32 = 4;
pub const TICKET_RETRY_BASE_DELAY_MS: u64 = 50;
pub const TICKET_RETRY_MAX_DELAY_MS: u64 = 800;
pub const TICKET_RETRY_JITTER_MS: u64 = 40;

#[derive(Serialize)]
struct BarrierRootsPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
);

#[derive(Serialize)]
struct BarrierPkHashPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize)]
struct BarrierTreeLeafHashPreimage<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
}

#[derive(Serialize)]
struct BarrierTreeNodeHashPreimage<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
    #[serde(with = "serde_bytes")]
    left_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    right_hash: &'a [u8; 32],
}

#[derive(Serialize)]
pub struct BarrierTreePathSaltPreimage(pub u64);

#[derive(Serialize)]
pub struct BarrierDeriveSaltPreimage<'a>(
    pub u64,
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
);

pub fn should_retry_ticket_http_error(
    status_code: u16,
    message: &str,
    freeze_code: Option<u32>,
) -> bool {
    let lowered = message.to_ascii_lowercase();
    let looks_like_concurrency_race = lowered.contains("window full")
        || lowered.contains("mh_heads_invalid")
        || lowered.contains("barrier_version")
        || lowered.contains("pivot head missing")
        || lowered.contains("refresh payload diverges from stored parity")
        || lowered.contains("barrier_update required on revocation change")
        || lowered.contains("barrier update required on revocation change");
    let status_hint = matches!(status_code, 409 | 429 | 500 | 503);
    let freeze_hint = matches!(freeze_code, Some(925));
    status_hint && (looks_like_concurrency_race || freeze_hint)
}

pub fn ticket_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base = TICKET_RETRY_BASE_DELAY_MS.saturating_mul(1u64 << exponent);
    let capped = base.min(TICKET_RETRY_MAX_DELAY_MS);
    let jitter = rng().random_range(0..=TICKET_RETRY_JITTER_MS);
    Duration::from_millis(capped.saturating_add(jitter))
}

pub fn compute_revocation_roots_hash(
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
) -> Result<[u8; 32]> {
    h_l(
        "barrier/roots",
        &BarrierRootsPreimage(revoked_since_root, revoked_root),
    )
    .map_err(|err| anyhow!("compute revocation_roots_hash: {err}"))
}

pub fn compute_barrier_pkhash(ek: &[u8]) -> Result<[u8; 32]> {
    h_l("barrier/pk-hash", &BarrierPkHashPreimage(ek))
        .map_err(|err| anyhow!("compute barrier/pk-hash: {err}"))
}

pub fn compute_barrier_tree_hash(n_max: u64, pk_entries: &[Vec<u8>]) -> Result<[u8; 32]> {
    let n_max_usize =
        usize::try_from(n_max).map_err(|_| anyhow!("barrier tree n_max too large"))?;
    let expected_len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("barrier tree size overflow"))?;
    if pk_entries.len() != expected_len {
        return Err(anyhow!(
            "barrier tree size mismatch: expected {expected_len}, got {}",
            pk_entries.len()
        ));
    }
    let leaf_base = n_max.saturating_sub(1);
    compute_barrier_tree_hash_recursive(0, leaf_base, n_max, pk_entries)
}

fn compute_barrier_tree_hash_recursive(
    node: u64,
    leaf_base: u64,
    n_max: u64,
    pk_entries: &[Vec<u8>],
) -> Result<[u8; 32]> {
    let node_index =
        usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
    let pk = pk_entries
        .get(node_index)
        .ok_or_else(|| anyhow!("barrier node index out of range"))?;
    if node >= leaf_base {
        return h_l(
            "barrier/tree/leaf-hash",
            &BarrierTreeLeafHashPreimage {
                n_max,
                node_index: node,
                pk: pk.as_slice(),
            },
        )
        .map_err(|err| anyhow!("compute barrier leaf hash: {err}"));
    }

    let left = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    let right = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    let left_hash = compute_barrier_tree_hash_recursive(left, leaf_base, n_max, pk_entries)?;
    let right_hash = compute_barrier_tree_hash_recursive(right, leaf_base, n_max, pk_entries)?;
    h_l(
        "barrier/tree/node-hash",
        &BarrierTreeNodeHashPreimage {
            n_max,
            node_index: node,
            pk: pk.as_slice(),
            left_hash: &left_hash,
            right_hash: &right_hash,
        },
    )
    .map_err(|err| anyhow!("compute barrier node hash: {err}"))
}

pub fn expected_barrier_tree_nodes(n_max: u64) -> Result<usize> {
    usize::try_from(n_max)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("invalid barrier n_max"))
}

pub fn barrier_path_nodes(n_max: u64, updater_leaf: u64) -> Result<Vec<u64>> {
    if n_max == 0 || !n_max.is_power_of_two() || updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let leaf_base = n_max.saturating_sub(1);
    let mut path_nodes = vec![leaf_base.saturating_add(updater_leaf)];
    while let Some(&node) = path_nodes.last() {
        if node == 0 {
            break;
        }
        path_nodes.push((node - 1) / 2);
    }
    Ok(path_nodes)
}

pub fn sibling_node(node: u64) -> Option<u64> {
    if node == 0 {
        return None;
    }
    if node.is_multiple_of(2) {
        Some(node - 1)
    } else {
        Some(node + 1)
    }
}

pub fn blank_leaf_and_path(snapshot: &mut [Vec<u8>], leaf_node: u64) -> Result<()> {
    let mut node = leaf_node;
    loop {
        let index =
            usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        slot.clear();
        if node == 0 {
            break;
        }
        node = (node - 1) / 2;
    }
    Ok(())
}

pub fn blank_internal_path_from_leaf(snapshot: &mut [Vec<u8>], leaf_node: u64) -> Result<()> {
    let mut node = leaf_node;
    while node > 0 {
        node = (node - 1) / 2;
        let index =
            usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        slot.clear();
    }
    Ok(())
}

pub fn apply_join_set_to_snapshot(
    snapshot: &mut [Vec<u8>],
    n_max: u64,
    join_records: &[BarrierJoinRecord],
) -> Result<()> {
    let leaf_base = n_max.saturating_sub(1);
    for record in join_records {
        let leaf_node = leaf_base.saturating_add(u64::from(record.leaf_index));
        let index =
            usize::try_from(leaf_node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = record.ek_leaf.clone();
        blank_internal_path_from_leaf(snapshot, leaf_node)?;
    }
    Ok(())
}

pub fn apply_revoked_set_to_snapshot(
    snapshot: &mut [Vec<u8>],
    n_max: u64,
    revoked_indices: &[u32],
) -> Result<()> {
    let leaf_base = n_max.saturating_sub(1);
    for leaf_index in revoked_indices {
        let leaf_node = leaf_base.saturating_add(u64::from(*leaf_index));
        blank_leaf_and_path(snapshot, leaf_node)?;
    }
    Ok(())
}

pub fn collect_resolution_targets(
    snapshot: &[Vec<u8>],
    node: u64,
    leaf_base: u64,
    targets: &mut Vec<u64>,
) -> Result<()> {
    let index = usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
    let Some(pk) = snapshot.get(index) else {
        return Ok(());
    };
    if !pk.is_empty() {
        targets.push(node);
        return Ok(());
    }
    if node >= leaf_base {
        return Ok(());
    }
    let left = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    let right = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    collect_resolution_targets(snapshot, left, leaf_base, targets)?;
    collect_resolution_targets(snapshot, right, leaf_base, targets)?;
    Ok(())
}
