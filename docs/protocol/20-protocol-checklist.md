# 20 — Protocol Checklist

> [!IMPORTANT]
> This chapter is an informative protocol-to-runtime checklist for the current
> `v0.1.4` base profile. The normative source remains
> [`../specs.md`](../specs.md). If this checklist conflicts with the unified
> spec or implementation behavior/tests, follow the unified spec and the live
> tests.

## Purpose

This checklist converts the current profile into user-visible guarantees and
maps each guarantee to one or more end-to-end flows. The goal is to review the
system by protocol contract rather than by implementation detail.

## Coverage Matrix

| Guarantee | What should be true | Status | Primary flows / gates |
|---|---|---|---|
| End-to-end confidentiality | The server stays blind to payload plaintext and session secrets. | Covered | `./scripts/verify_no_secrets.sh`, `./scripts/security_review.sh`, [`../preproduction-validation.md`](../preproduction-validation.md) |
| Public-room join works | Any member can join a public room without manual peer interaction. | Covered | `native::tests::perform_join_succeeds_with_bootstrap_disabled`, `native::tests::perform_join_second_member_can_send_immediately` |
| Fresh joiner can write immediately | A second member can join and immediately send room traffic. | Covered | `native::tests::perform_join_second_member_can_send_immediately` |
| Bidirectional messaging after join | Two members can both send/fetch after the room becomes active. | Covered | `native::tests::send_fetch_and_members_roundtrip`, Flow A in [`../evidence/e2e-local-validation-2026-03-27.md`](../evidence/e2e-local-validation-2026-03-27.md) |
| Offline member catches up and decrypts after refresh | A member that was offline during a `pcs_refresh` can return, sync, and decrypt the new traffic. | Covered | `native::tests::offline_member_restart_then_epoch_sync_after_pcs_refresh_decrypts_new_messages` |
| Repeated fetches do not replay old traffic | The client only releases new traffic between fetch rounds. | Covered | `native::tests::message_replay_state_only_releases_new_messages_between_fetch_rounds` |
| Replay-state survives client restart | A restart does not cause old ciphertexts to be re-released. | Covered | `native::tests::message_replay_state_survives_client_restart_between_fetch_rounds` |
| Watch reconnect bridges offline backlog and resumes live notifications | A dropped watcher can reconnect, fetch the traffic emitted while it was offline, and then keep receiving fresh live notifications without replaying the backlog twice. | Covered | `native::tests::watch_reconnect_fetches_offline_backlog_and_resumes_live_notifications`, `tests::watch_mode_reconnect_under_burst_resumes_live_notifications` in [`../../crates/cityg-gui/src/bin/join_leave.rs`](../../crates/cityg-gui/src/bin/join_leave.rs) |
| Self-exclusion works | A member can leave and survivors converge on the new roster. | Covered | `native::tests::sequential_member_leaves_succeed` |
| Same identity can rejoin after room empty | A member that emptied the room can rejoin with the same persistent identity. | Covered | `native::tests::rejoin_with_same_persisted_identity_succeeds_after_room_becomes_empty`, Flow B |
| Room admin can expel a member | An authorized admin can expel another leaf from the room. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging` |
| Expelled member loses future write access | An expelled member cannot keep sending after revocation. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging` |
| Expelled member cannot read post-expel traffic | A stale expelled client must not decrypt newer survivor traffic. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging` |
| Survivors continue after expel | Expelling a member does not strand the remaining room. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging`, `native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging` |
| Survivor refresh after expel preserves room continuity | After an admin expels a member, a survivor can refresh, the expelled member stays locked out, and a fresh joiner can still re-enter the room. | Covered | `native::tests::admin_expel_then_survivor_refresh_preserves_room_and_new_joiner_messaging` |
| Stale concurrent refreshes converge | Two stale `pcs_refresh` attempts converge to one room head without wedging. | Covered | `native::tests::stale_dueling_pcs_refreshes_converge_and_preserve_messaging`, Flow H |
| Multi-author messaging survives an epoch change | Traffic sent before and after a `pcs_refresh` stays readable for the right members without replaying old bursts. | Covered | `native::tests::multi_author_messaging_across_refresh_epoch_change_preserves_delivery` |
| Multi-version gap recovery is bounded | A stale member can survive a version gap after `refresh + leave` without dangerous best-effort activation. | Covered | `native::tests::epoch_sync_survives_multi_version_barrier_gap_after_refresh_and_leave` |
| Client restart during multi-version catch-up recovers cleanly | A stale client can restart across a `refresh + leave` gap, sync, and return to message-ready operation. | Covered | `native::tests::client_restart_during_multi_version_catchup_after_refresh_and_leave_recovers_cleanly` |
| Two restarted members resume messaging without duplicate delivery | Two members can both restart from disk, resume bilateral traffic immediately, and keep fetch replay-state suppression intact across the restart boundary. | Covered | `native::tests::two_restarted_members_exchange_traffic_without_duplicate_delivery` |
| Restart after leave preserves room health | Restarting the server after leave churn preserves survivor state and allows new joins. | Covered | `native::tests::restart_after_leave_preserves_survivor_refresh_and_new_join` |
| Restart after expel preserves room health | Restarting the server after admin expel preserves survivor state and allows a fresh joiner to resume room traffic. | Covered | `native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging` |
| Restart during pending `join_finalize` activation recovers cleanly | If a `join_finalize` is published but the joiner crashes before reload, a server restart still leaves the published epoch bundle fetchable and `epoch_sync` clears the pending recovery state. | Covered | `native::tests::restart_during_pending_join_finalize_activation_recovers_via_epoch_sync`, `restart_rehydrates_bundle_store_for_post_restart_bundle_fetch` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Watch-mode burst traffic survives chaos | Under `cityg-stress`, watch traffic and short bursts survive client/server restarts. | Covered | Flow E / Flow F in [`../evidence/e2e-local-validation-2026-03-27.md`](../evidence/e2e-local-validation-2026-03-27.md), [`../preproduction-validation.md`](../preproduction-validation.md) |
| Watch reconnect resumes live notifications | A dropped watch websocket can reconnect under active traffic and resume receiving fresh message notifications. | Covered | `tests::watch_mode_reconnect_under_burst_resumes_live_notifications` in [`../../crates/cityg-gui/src/bin/join_leave.rs`](../../crates/cityg-gui/src/bin/join_leave.rs) |
| Membership revoke signal is visible to the client | A revoke event is surfaced on the websocket membership feed. | Covered | `native::tests::websocket_worker_reports_revoke_membership_event` |
| Room-admin grant/revoke lifecycle | Admin authority can be granted/revoked cleanly end-to-end via one user flow. | Covered | `native::tests::room_admin_grant_and_revoke_flow_preserves_authorization_boundaries` |
| Barrier bundle history commitment mismatches are rejected | `epoch_sync` must fail closed if helper/current-state headers disagree with the authenticated local state. | Covered | `native::tests::epoch_sync_rejects_barrier_bundle_history_commitment_mismatch` |
| Barrier bundle FS policy mismatches are rejected | `epoch_sync` must fail closed if the bundle carries an incompatible FS policy version. | Covered | `native::tests::epoch_sync_rejects_barrier_bundle_fs_policy_version_mismatch` |
| Sender leaf spoofing is rejected during fetch | A ciphertext signed by one device key but claimed under another leaf must not decrypt or release plaintext. | Covered | `native::tests::perform_fetch_rejects_sender_leaf_spoofing_with_mismatched_public_key` |
| Malformed join payloads cannot poison room state or restart recovery | A malicious join attempt must be rejected without corrupting the live roster, and the room must still admit later honest joins even after restart. | Covered | `malformed_join_rejection_does_not_poison_room_state` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs), `malformed_join_rejection_does_not_poison_restart_or_future_honest_joins`, `concurrent_malformed_join_and_honest_join_preserve_room_across_restart`, `restart_during_concurrent_malformed_join_and_honest_join_recovers_cleanly` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Malformed leave payloads cannot poison room state | A malicious self-removal payload must be rejected without corrupting the live roster, and the room must still accept later honest traffic. | Covered | `malformed_leave_rejection_does_not_poison_room_state` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs) |
| Malformed refresh payloads cannot poison room state | A malicious epoch-advance payload, including a forged `reason=1` mutation, must be rejected without wedging the room or preventing later honest joins. | Covered | `malformed_refresh_rejection_does_not_poison_room_state` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs) |
| Honest publish wins over a malformed refresh race | A malformed refresh-shaped payload racing with a later honest join must fail closed without overriding the healthy room or blocking restart recovery. | Covered | `malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs) |
| Structured barrier mutations fail closed without poisoning restart recovery | A bundle with intact overall shape but corrupted witness, receipt, attestation, reason, or barrier-update bytes must be rejected without corrupting the live roster or later restart recovery. | Covered | `hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs) |
| Malformed `join_finalize` payloads cannot poison restart recovery | A malicious `reason=2` activation payload must be rejected without corrupting persisted state, and restart must still expose a healthy refresh / `join_finalize` recovery path. | Covered | `malformed_join_finalize_rejection_does_not_poison_restart_recovery` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs) |
| Malformed admin expel payloads cannot poison room state or restart recovery | A malicious admin-targeted revocation payload must be rejected without corrupting either the live roster or the bootstrapped room state, and restart must still preserve a healthy room that admits later honest traffic. | Covered | `malformed_admin_expel_rejection_does_not_poison_room_state`, `malformed_admin_expel_rejection_does_not_poison_restart_recovery` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs), `malformed_admin_expel_request_does_not_poison_restart_or_future_honest_joins` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Honest join wins over a malformed admin control-plane race | A malformed admin expel request racing with an honest public join must fail closed without blocking the join, and restart must preserve both the joined member and the room-admin ACL. | Covered | `malformed_admin_expel_request_concurrent_with_honest_join_survives_restart`, `concurrent_malformed_admin_expel_request_and_honest_join_preserve_room_across_restart` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Restart during a hostile control-plane race still converges to the honest state | If the server restarts while a malformed admin expel request races with an honest join, the room must converge after restart to the honest joined member with the ACL still intact. | Covered | `restart_during_concurrent_malformed_admin_race_and_honest_join_recovers_cleanly` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Malformed room-admin grant/revoke requests cannot poison ACL or restart recovery | A malformed control-plane admin mutation must fail closed, leave ACL state intact, and still allow later honest ACL changes after restart. | Covered | `malformed_room_admin_mutation_requests_do_not_poison_acl_or_restart` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Honest progress wins over a stale leave race | A valid leave bundle built from stale room state must not override a later honest join, and restart must still preserve the healthy room. | Covered | `stale_leave_race_with_honest_join_does_not_poison_restart_recovery` in [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs) |
| Room-admin proof replays stay rejected across restart | A previously valid admin proof replayed after restart must fail closed and leave ACL state healthy for later honest governance changes. | Covered | `replayed_room_admin_grant_proof_rejected_after_restart_without_poisoning_acl` in [`../../crates/cityg-api/tests/integration.rs`](../../crates/cityg-api/tests/integration.rs) |
| Helper responses missing authenticated fields are rejected fail-closed | Helper paths must reject missing history commitments or manifests instead of accepting underspecified state. | Covered | `barrier_fetch_public_tree_rejects_missing_history_commitment`, `barrier_fetch_public_tree_rejects_missing_deployment_profile_manifest` in [`../../crates/cityg-api-client/src/lib.rs`](../../crates/cityg-api-client/src/lib.rs) |
| Base-profile helper guards reject unexpected completeness/authority extensions | Helper responses with unsupported completeness attestations or local-authority extensions must fail closed under the base profile. | Covered | `barrier_resolve_revoked_leaves_rejects_unexpected_completeness_attestation`, `barrier_resolve_joins_since_rejects_unexpected_completeness_attestation`, `barrier_fetch_public_tree_rejects_local_history_authority_in_base_profile` in [`../../crates/cityg-api-client/src/lib.rs`](../../crates/cityg-api-client/src/lib.rs) |

## Minimum Runtime Gates

Run these before longer smoke or chaos campaigns when you want direct protocol
signal:

```bash
cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::perform_join_second_member_can_send_immediately \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::send_fetch_and_members_roundtrip \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::offline_member_restart_then_epoch_sync_after_pcs_refresh_decrypts_new_messages \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::admin_expel_removes_member_and_preserves_survivor_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::admin_expel_then_survivor_refresh_preserves_room_and_new_joiner_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::room_admin_grant_and_revoke_flow_preserves_authorization_boundaries \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::stale_dueling_pcs_refreshes_converge_and_preserve_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::multi_author_messaging_across_refresh_epoch_change_preserves_delivery \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::watch_reconnect_fetches_offline_backlog_and_resumes_live_notifications \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::client_restart_during_multi_version_catchup_after_refresh_and_leave_recovers_cleanly \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::two_restarted_members_exchange_traffic_without_duplicate_delivery \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::restart_during_pending_join_finalize_activation_recovers_via_epoch_sync \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin join_leave \
  tests::watch_mode_reconnect_under_burst_resumes_live_notifications \
  -- --exact --nocapture

cargo test --locked -p cityg-api --test integration \
  malformed_join_rejection_does_not_poison_restart_or_future_honest_joins \
  concurrent_malformed_join_and_honest_join_preserve_room_across_restart \
  restart_during_concurrent_malformed_join_and_honest_join_recovers_cleanly \
  -- --exact --nocapture

cargo test --locked -p cityg-server \
  malformed_leave_rejection_does_not_poison_room_state \
  malformed_refresh_rejection_does_not_poison_room_state \
  malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery \
  hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery \
  malformed_join_finalize_rejection_does_not_poison_restart_recovery \
  stale_leave_race_with_honest_join_does_not_poison_restart_recovery \
  -- --nocapture

cargo test --locked -p cityg-server \
  malformed_admin_expel_rejection_does_not_poison_room_state \
  malformed_admin_expel_rejection_does_not_poison_restart_recovery \
  -- --nocapture

cargo test --locked -p cityg-api --test integration \
  malformed_admin_expel_request_does_not_poison_restart_or_future_honest_joins \
  malformed_admin_expel_request_concurrent_with_honest_join_survives_restart \
  concurrent_malformed_admin_expel_request_and_honest_join_preserve_room_across_restart \
  restart_during_concurrent_malformed_admin_race_and_honest_join_recovers_cleanly \
  -- --exact --nocapture

cargo test --locked -p cityg-api --test integration \
  malformed_room_admin_mutation_requests_do_not_poison_acl_or_restart \
  replayed_room_admin_grant_proof_rejected_after_restart_without_poisoning_acl \
  -- --exact --nocapture
```

## Notes

- “Covered” here means at least one current flow exercises the guarantee in the
  live repo state.
- The checklist is intentionally protocol-facing. It does not replace lower
  level KATs, unit tests, or acceptance-pipeline tests.
- The matrix is intentionally runtime-facing; lower-level API unit tests still
  exist below these end-to-end flows.

## Next Useful E2E TODO

- `P1`: hostile `refresh` / honest publish race with and without server restart
- `P1`: hostile `join_finalize` / honest survivor refresh race with and without server restart
- `P2`: 8-to-16 member churn flow combining expel, refresh, rejoin, offline catch-up, and active traffic
- `P2`: dual-client restart during active watch traffic plus backlog replay validation
- `P2`: API-side mutation harness that systematically flips `barrier_update`, `reason`, `header[180..183]`, manifests, and sender binding fields while asserting fail-closed recovery
