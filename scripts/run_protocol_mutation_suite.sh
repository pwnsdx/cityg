#!/usr/bin/env bash
# Hostile-input suite: tampered commits, update paths, signatures and
# encodings, forged senders, forks, admissions without authority, reused
# admissions of removed members, mismatched welcomes, light-member data that
# does not prove what it claims, and the delivery service's handling of
# malformed requests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${CITYG_CARGO_TARGET_SLOT:=protocol-mutation-suite}"
source "$SCRIPT_DIR/cargo_repo_env.sh"

cd "$REPO_ROOT"

cargo test --locked -p cityg-core -- \
  tampering_is_detected \
  tampered_paths_are_rejected \
  registry_and_signatures_are_enforced \
  signatures_and_encodings_are_checked \
  a_member_cannot_speak_for_another \
  forks_and_foreign_commits_are_rejected \
  joins_need_an_admission_from_a_current_admin \
  a_removed_admin_cannot_admit_in_the_same_commit \
  a_group_without_admin_cannot_be_taken_over_with_a_stale_invite \
  removed_devices_cannot_rejoin_with_their_old_admission \
  admin_admissions_are_checked_against_the_admins \
  requests_verify_and_are_authorized \
  welcomes_open_only_with_the_init_key \
  welcomes_are_bound_to_their_request_and_epoch \
  light_sessions_reject_what_they_cannot_prove \
  light_join_data_is_checked \
  leaf_proofs_verify_against_the_tree_hash \
  encodings_round_trip_and_reject_non_canonical_trees \
  malformed_registries_are_rejected \
  malformed_snapshots_are_rejected \
  decode_requires_deterministic_bytes \
  rejects_duplicate_keys_floats_and_tags \
  the_gid_binds_the_creator_key_and_nonce \
  the_announced_tree_and_registry_hashes_are_recomputed \
  the_ledger_accepts_only_the_group_info_of_the_computed_epoch \
  --nocapture
cargo test --locked -p cityg-server -p cityg-runtime -- --nocapture
