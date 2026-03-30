use super::*;

#[tokio::test]
async fn perform_leave_rejects_while_barrier_recovery_is_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xC31, "http://127.0.0.1:9", "room-leave-guard", "alice")?;
    session.barrier_state.barrier_recovery_pending = true;

    let err = perform_leave(LeaveRequest::from_session(&session))
        .await
        .expect_err("leave should be blocked while barrier recovery is pending");
    assert!(
        err.to_string()
            .contains("complete FULL barrier recovery first"),
        "expected explicit recover-before-update guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_leave_rejects_without_full_barrier_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xC33,
        "http://127.0.0.1:9",
        "room-leave-recover-only",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = false;
    session.barrier_state.current_barrier_full_verified = false;

    let err = perform_leave(LeaveRequest::from_session(&session))
        .await
        .expect_err("leave should be blocked while barrier state is recover-only");
    assert!(
        err.to_string().contains("recover-only barrier state"),
        "expected explicit FULL-verification guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_pcs_refresh_rejects_while_barrier_recovery_is_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session =
        build_test_session(0xC32, "http://127.0.0.1:9", "room-refresh-guard", "alice")?;
    session.barrier_state.barrier_recovery_pending = true;

    let err = perform_pcs_refresh(LeaveRequest::from_session(&session))
        .await
        .expect_err("pcs refresh should be blocked while barrier recovery is pending");
    assert!(
        err.to_string()
            .contains("complete FULL barrier recovery first"),
        "expected explicit recover-before-update guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_pcs_refresh_rejects_without_full_barrier_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xC34,
        "http://127.0.0.1:9",
        "room-refresh-recover-only",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = false;
    session.barrier_state.current_barrier_full_verified = false;

    let err = perform_pcs_refresh(LeaveRequest::from_session(&session))
        .await
        .expect_err("pcs refresh should be blocked while barrier state is recover-only");
    assert!(
        err.to_string().contains("recover-only barrier state"),
        "expected explicit FULL-verification guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_join_finalize_rejects_pending_session_without_bootstrap_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().expect("create temp dir");
    let _override_guard = set_config_dir_override_for_tests(Some(temp_dir.path().to_path_buf()));
    let mut session = build_test_session(
        0xC35,
        "http://127.0.0.1:9",
        "room-join-finalize-bootstrap-guard",
        "alice",
    )?;
    session.parent_root = [0x44; 32];
    session.barrier_state.barrier_version = 3;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.current_barrier_full_verified = false;
    session.barrier_state.bootstrap_history_commitment = None;
    session
        .barrier_state
        .bootstrap_current_barrier_update
        .clear();
    persist_session(&session)?;

    let err = match perform_join_finalize_inner(LeaveRequest::from_session(&session)).await {
        Ok(_) => {
            return Err("pending join_finalize must fail closed without bootstrap artifact".into());
        }
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("bootstrap missing"),
        "expected explicit bootstrap-artifact guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_join_finalize_rejects_pending_session_without_auth_token()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xC36,
        "http://127.0.0.1:9",
        "room-join-finalize-auth-guard",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.current_barrier_full_verified = true;
    session.barrier_state.bootstrap_join_finalize_auth_token = [0u8; 32];

    let err = match perform_join_finalize_inner(LeaveRequest::from_session(&session)).await {
        Ok(_) => {
            return Err("pending join_finalize must fail closed without auth token".into());
        }
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("join_finalize auth token"),
        "expected explicit join_finalize auth-token guidance: {err}"
    );
    Ok(())
}
