#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${CITYG_CARGO_TARGET_SLOT:=slot-lease-conformance}"
source "$SCRIPT_DIR/cargo_repo_env.sh"

cd "$REPO_ROOT"

cargo test --locked -p cityg-server \
  tests::slot_reuse_join_finalize_reclaim_clears_committed_revocation \
  -- --nocapture
cargo test --locked -p cityg-server \
  tests::slot_reuse_rejects_stale_join_finalize_auth_token \
  -- --nocapture
cargo test --locked -p cityg-api --test integration \
  public_stale_join_finalize_auth_rejected_after_slot_reuse \
  -- --exact --nocapture
cargo test --locked -p cityg-server \
  barrier_snapshot_helpers::resolve_join_occupancies_since_keeps_latest_generation_for_reused_slot \
  -- --nocapture

cargo test --locked -p cityg-client --lib \
  barrier::tests::apply_join_set_to_snapshot_keeps_latest_generation_for_reused_slot \
  -- --exact --nocapture
cargo test --locked -p cityg-client --lib \
  barrier_transition::tests::compute_barrier_snapshot_transition_applies_versioned_revocations \
  -- --exact --nocapture

cargo test --locked -p cityg-api-client --test history_authority_extensions \
  helper_completeness_attestation_binds_slot_generation \
  -- --exact --nocapture
cargo test --locked -p cityg-api-client --lib \
  tests::barrier_resolve_revoked_occupancies_preserves_multiple_generations_for_one_slot \
  -- --exact --nocapture
cargo test --locked -p cityg-api --test integration \
  public_barrier_helpers_preserve_slot_generations_across_slot_reuse \
  -- --exact --nocapture
cargo test --locked -p cityg-api --test integration \
  public_lookup_merge_acceptance_tracks_reclaim_join_finalize \
  -- --exact --nocapture
cargo test --locked -p cityg-api --test integration \
  public_telemetry_tracks_slot_capacity_after_reclaim_join_finalize \
  -- --exact --nocapture
cargo test --locked -p cityg-api --test integration \
  public_telemetry_tracks_pending_reclaim_capacity_before_acceptance \
  -- --exact --nocapture
cargo test --locked -p cityg-api-client --lib \
  tests::prepare_runtime_join_ticket_rejects_tampered_join_occupancy_slot_generation \
  -- --exact --nocapture
cargo test --locked -p cityg-api-client --lib \
  tests::prepare_runtime_join_ticket_rejects_tampered_revoked_occupancy_slot_generation \
  -- --exact --nocapture
cargo test --locked -p cityg-api-client --lib \
  tests::merge_ticket_rejects_tampered_slot_generation \
  -- --exact --nocapture
