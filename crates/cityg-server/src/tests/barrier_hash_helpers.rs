use super::super::{
    GroupState, build_all_blank_pk_entries, build_pk_entries_view,
    compute_barrier_subtree_hash_cached, compute_barrier_tree_hash_with_changes,
    compute_group_barrier_tree_hash, record_barrier_public_tree_snapshot,
};
use super::*;

#[test]
fn barrier_tree_incremental_hash_matches_full_rehash() -> Result<(), CityGError> {
    let n_max = 8;
    let mut base = build_all_blank_pk_entries(n_max)?;
    base[7] = vec![0x01; 1184];
    base[8] = vec![0x02; 1184];
    base[10] = vec![0x03; 1184];

    let mut updated = base.clone();
    updated[0] = vec![0xA0; 1184];
    updated[2] = vec![0xA2; 1184];
    updated[6] = vec![0xA6; 1184];
    updated[10] = vec![0xAA; 1184];

    let mut changed = std::collections::BTreeSet::new();
    changed.insert(0usize);
    changed.insert(2usize);
    changed.insert(6usize);
    changed.insert(10usize);
    let mut before_cache = std::collections::HashMap::new();

    let incremental = compute_barrier_tree_hash_with_changes(
        n_max,
        updated.as_slice(),
        &changed,
        None,
        &mut before_cache,
    )?
    .0;
    let full = super::compute_barrier_tree_hash(n_max, updated.as_slice())?;
    assert_eq!(incremental, full);

    let empty_change = std::collections::BTreeSet::new();
    let unchanged = compute_barrier_tree_hash_with_changes(
        n_max,
        base.as_slice(),
        &empty_change,
        None,
        &mut before_cache,
    )?
    .0;
    assert_eq!(
        unchanged,
        super::compute_barrier_tree_hash(n_max, base.as_slice())?
    );

    let mut out_of_range = std::collections::BTreeSet::new();
    out_of_range.insert(usize::MAX);
    assert!(matches!(
        compute_barrier_tree_hash_with_changes(
            n_max,
            updated.as_slice(),
            &out_of_range,
            None,
            &mut before_cache,
        ),
        Err(CityGError::InvalidInput("barrier node index out of range"))
    ));

    Ok(())
}

#[test]
fn barrier_tree_fallback_helpers_cover_empty_and_owned_paths() -> Result<(), CityGError> {
    let zero_state = GroupState {
        n_max: 0,
        ..GroupState::default()
    };
    assert!(matches!(
        build_pk_entries_view(&zero_state),
        Err(CityGError::InvalidInput(
            "barrier n_max must be a non-zero power of two"
        ))
    ));

    let mut state = GroupState {
        n_max: 4,
        ..GroupState::default()
    };
    record_barrier_public_tree_snapshot(&[0u8; 32], &mut state)?;
    assert!(state.barrier_public_tree_history.is_empty());

    let leaf = cityg_client::demo::demo_member_leaf("fallback-owned");
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    state.leaf_barrier_public.insert(leaf, vec![0x77; 1184]);

    let view = build_pk_entries_view(&state)?;
    let owned = match view {
        std::borrow::Cow::Borrowed(_) => {
            return Err(CityGError::InvalidInput(
                "expected fallback builder to allocate owned entries",
            ));
        }
        std::borrow::Cow::Owned(entries) => entries,
    };
    assert_eq!(owned.len(), 7);
    let computed = compute_group_barrier_tree_hash(&state)?;
    assert_eq!(
        computed,
        super::compute_barrier_tree_hash(state.n_max, owned.as_slice())?
    );
    Ok(())
}

#[test]
#[ignore = "manual benchmark: compare full rehash vs incremental barrier tree hash"]
fn benchmark_barrier_tree_incremental_hash_vs_full_rehash() -> Result<(), CityGError> {
    fn hex_prefix4(bytes: &[u8; 32]) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }

    fn synthetic_entries(n_max: u64) -> Result<Vec<Vec<u8>>, CityGError> {
        let n_max_usize = usize::try_from(n_max)
            .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
        let total = n_max_usize
            .checked_mul(2)
            .and_then(|v| v.checked_sub(1))
            .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;
        let mut out = Vec::with_capacity(total);
        for i in 0..total {
            if i % 11 == 0 {
                out.push(vec![0xA5; 1184]);
            } else {
                out.push(Vec::new());
            }
        }
        Ok(out)
    }

    for &(n_max, rounds, stride) in &[(1024u64, 200u64, 257usize), (2048u64, 120u64, 389usize)] {
        let base = synthetic_entries(n_max)?;
        let mut updated = base.clone();
        let mut changed_nodes = std::collections::BTreeSet::new();
        for idx in (0..updated.len()).step_by(stride) {
            updated[idx] = vec![0x5A; 1184];
            changed_nodes.insert(idx);
        }

        let full_start = std::time::Instant::now();
        let mut full_acc = [0u8; 32];
        for _ in 0..rounds {
            let before = super::compute_barrier_tree_hash(n_max, base.as_slice())?;
            let after = super::compute_barrier_tree_hash(n_max, updated.as_slice())?;
            for i in 0..full_acc.len() {
                full_acc[i] ^= before[i] ^ after[i];
            }
        }
        let full_elapsed = full_start.elapsed();

        let incremental_start = std::time::Instant::now();
        let mut incr_acc = [0u8; 32];
        for _ in 0..rounds {
            let mut before_cache = std::collections::HashMap::new();
            let before = compute_barrier_subtree_hash_cached(
                0,
                n_max,
                usize::try_from(n_max)
                    .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?,
                base.as_slice(),
                None,
                &mut before_cache,
            )?;
            let after = compute_barrier_tree_hash_with_changes(
                n_max,
                updated.as_slice(),
                &changed_nodes,
                None,
                &mut before_cache,
            )?
            .0;
            for i in 0..incr_acc.len() {
                incr_acc[i] ^= before[i] ^ after[i];
            }
        }
        let incremental_elapsed = incremental_start.elapsed();

        assert_eq!(
            super::compute_barrier_tree_hash(n_max, updated.as_slice())?,
            compute_barrier_tree_hash_with_changes(
                n_max,
                updated.as_slice(),
                &changed_nodes,
                None,
                &mut std::collections::HashMap::new(),
            )?
            .0,
            "incremental hash must remain equivalent to full rehash"
        );

        let full_ms = full_elapsed.as_secs_f64() * 1_000.0;
        let incremental_ms = incremental_elapsed.as_secs_f64() * 1_000.0;
        let speedup = full_ms / incremental_ms.max(1e-9);
        eprintln!(
            "BENCH[server_barrier_hash] n_max={n_max} rounds={rounds} changed_nodes={} full_total_ms={full_ms:.2} full_per_round_ms={:.3} incremental_total_ms={incremental_ms:.2} incremental_per_round_ms={:.3} speedup_x={speedup:.2} hash_prefix_full={} hash_prefix_incr={}",
            changed_nodes.len(),
            full_ms / (rounds as f64),
            incremental_ms / (rounds as f64),
            hex_prefix4(&full_acc),
            hex_prefix4(&incr_acc),
        );
    }

    Ok(())
}
