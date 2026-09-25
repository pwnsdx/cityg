#!/usr/bin/env bash
# Client-state hardening: encrypted session files, refusal of damaged or
# foreign state, spent message generations made durable before a message
# leaves the device (no nonce reuse after a crash), resync after a lost
# state or after commits that expired from the server log.
set -euo pipefail

cd "$(dirname "$0")/.."
export CITYG_CARGO_TARGET_SLOT="${CITYG_CARGO_TARGET_SLOT:-client-state}"
source "$(pwd)/scripts/cargo_repo_env.sh"

cargo test --locked -p cityg-core -- \
  a_member_that_lost_its_state_resyncs \
  sessions_persist_and_resume \
  identities_and_pending_states_are_checked
cargo test --locked -p cityg-api --test integration -- \
  the_state_sink_makes_spent_generations_durable \
  concurrent_commits_retry_and_lost_state_resyncs \
  a_member_that_missed_pruned_commits_resyncs \
  members_wrap_only_their_own_sessions
cargo test --locked -p cityg-gui --features native-app -- native::tests::persistence
