#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo test -p cityg-gui --features native-app native::tests::persist_session_fault_injection_truncates_session_file_after_write -- --exact
cargo test -p cityg-gui --features native-app native::tests::persist_session_fault_injection_rewrites_pointer_to_missing_session -- --exact
cargo test -p cityg-gui --features native-app native::tests::pending_barrier_activation_fault_injection_preserves_pending_state_on_error -- --exact
cargo test -p cityg-gui --features native-app native::tests::join_finalize_fault_injection_persists_pending_state_before_publish -- --exact
cargo test -p cityg-gui --features native-app native::tests::join_finalize_fault_injection_after_publish_recovers_via_epoch_sync -- --exact
cargo test -p cityg-gui --features native-app native::tests::client_state_props::client_state_model_never_silently_clears_pending_recovery -- --exact
cargo test -p cityg-gui --features native-app native::tests::client_state_props::client_state_model_never_activates_same_pending_twice -- --exact
cargo test -p cityg-gui --features native-app native::tests::client_state_props::client_state_model_join_finalize_does_not_reseed_k_fs -- --exact
cargo test -p cityg-gui --features native-app native::tests::client_state_props::client_state_model_restart_is_pre_or_post_transaction_only -- --exact
cargo test -p cityg-gui --features native-app native::tests::client_state_props::client_state_model_insufficient_history_never_marks_ready -- --exact
cargo test -p cityg-gui --features native-app native::tests::client_state_props::persisted_pending_state_roundtrip_property_preserves_fields -- --exact
cargo test -p msphf-orchestrator client_state_manifest_is_well_formed_and_complete -- --exact
