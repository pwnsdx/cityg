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
| Self-exclusion works | A member can leave and survivors converge on the new roster. | Covered | `native::tests::sequential_member_leaves_succeed` |
| Same identity can rejoin after room empty | A member that emptied the room can rejoin with the same persistent identity. | Covered | `native::tests::rejoin_with_same_persisted_identity_succeeds_after_room_becomes_empty`, Flow B |
| Room admin can expel a member | An authorized admin can expel another leaf from the room. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging` |
| Expelled member loses future write access | An expelled member cannot keep sending after revocation. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging` |
| Expelled member cannot read post-expel traffic | A stale expelled client must not decrypt newer survivor traffic. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging` |
| Survivors continue after expel | Expelling a member does not strand the remaining room. | Covered | `native::tests::admin_expel_removes_member_and_preserves_survivor_messaging`, `native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging` |
| Stale concurrent refreshes converge | Two stale `pcs_refresh` attempts converge to one room head without wedging. | Covered | `native::tests::stale_dueling_pcs_refreshes_converge_and_preserve_messaging`, Flow H |
| Multi-version gap recovery is bounded | A stale member can survive a version gap after `refresh + leave` without dangerous best-effort activation. | Covered | `native::tests::epoch_sync_survives_multi_version_barrier_gap_after_refresh_and_leave` |
| Restart after leave preserves room health | Restarting the server after leave churn preserves survivor state and allows new joins. | Covered | `native::tests::restart_after_leave_preserves_survivor_refresh_and_new_join` |
| Restart after expel preserves room health | Restarting the server after admin expel preserves survivor state and allows a fresh joiner to resume room traffic. | Covered | `native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging` |
| Watch-mode burst traffic survives chaos | Under `cityg-stress`, watch traffic and short bursts survive client/server restarts. | Covered | Flow E / Flow F in [`../evidence/e2e-local-validation-2026-03-27.md`](../evidence/e2e-local-validation-2026-03-27.md), [`../preproduction-validation.md`](../preproduction-validation.md) |
| Membership revoke signal is visible to the client | A revoke event is surfaced on the websocket membership feed. | Covered | `native::tests::websocket_worker_reports_revoke_membership_event` |
| Room-admin grant/revoke lifecycle | Admin authority can be granted/revoked cleanly end-to-end via one user flow. | Covered | `native::tests::room_admin_grant_and_revoke_flow_preserves_authorization_boundaries` |

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
  native::tests::room_admin_grant_and_revoke_flow_preserves_authorization_boundaries \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::stale_dueling_pcs_refreshes_converge_and_preserve_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging \
  --features native-app -- --exact --nocapture
```

## Notes

- “Covered” here means at least one current flow exercises the guarantee in the
  live repo state.
- The checklist is intentionally protocol-facing. It does not replace lower
  level KATs, unit tests, or acceptance-pipeline tests.
- The matrix is intentionally runtime-facing; lower-level API unit tests still
  exist below these end-to-end flows.
