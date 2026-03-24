use super::*;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
enum ClientStateEvent {
    Join,
    PublishJoinFinalize,
    RestartPre,
    RestartPost,
    HistoryFoundAccept,
    HistoryFoundReject,
    NewerVersionSeen,
    NotFoundAfterNewerVersion,
    PcsRefresh,
    Leave,
    MessageFetch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingKind {
    JoinFinalize,
    PcsRefresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientRecoveryState {
    Ready,
    PendingRecovery,
    PendingSelfFinalize,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartSnapshot {
    state: ClientRecoveryState,
    barrier_recovery_pending: bool,
    pending_id: Option<u8>,
    k_fs_generation: u8,
}

#[derive(Clone, Debug)]
struct PendingModel {
    id: u8,
    kind: PendingKind,
    published: bool,
    newer_version_seen: bool,
    k_fs_before: u8,
    k_fs_after_pcs: Option<u8>,
}

#[derive(Clone, Debug)]
struct ClientStateModel {
    next_pending_id: u8,
    state: ClientRecoveryState,
    barrier_recovery_pending: bool,
    pending: Option<PendingModel>,
    activated: BTreeSet<u8>,
    k_fs_generation: u8,
    silent_clear_detected: bool,
    double_activation_detected: bool,
    join_finalize_reseed_detected: bool,
    invalid_restart_detected: bool,
    insufficient_history_ready_detected: bool,
    last_restart_snapshot: Option<RestartSnapshot>,
}

impl Default for ClientStateModel {
    fn default() -> Self {
        Self {
            next_pending_id: 1,
            state: ClientRecoveryState::Ready,
            barrier_recovery_pending: false,
            pending: None,
            activated: BTreeSet::new(),
            k_fs_generation: 1,
            silent_clear_detected: false,
            double_activation_detected: false,
            join_finalize_reseed_detected: false,
            invalid_restart_detected: false,
            insufficient_history_ready_detected: false,
            last_restart_snapshot: None,
        }
    }
}

impl ClientStateModel {
    fn canonical_snapshot(&self) -> RestartSnapshot {
        RestartSnapshot {
            state: self.state,
            barrier_recovery_pending: self.barrier_recovery_pending,
            pending_id: self.pending.as_ref().map(|pending| pending.id),
            k_fs_generation: self.k_fs_generation,
        }
    }

    fn restart_candidates(&self) -> Vec<RestartSnapshot> {
        let mut candidates = vec![self.canonical_snapshot()];
        if let Some(pending) = &self.pending
            && pending.published
        {
            let mut post = self.canonical_snapshot();
            post.state = ClientRecoveryState::Ready;
            post.barrier_recovery_pending = false;
            post.pending_id = None;
            if let Some(k_fs_after_pcs) = pending.k_fs_after_pcs {
                post.k_fs_generation = k_fs_after_pcs;
            }
            candidates.push(post);
        }
        candidates
    }

    fn begin_pending(&mut self, kind: PendingKind) {
        if !matches!(self.state, ClientRecoveryState::Ready) || self.pending.is_some() {
            return;
        }
        let pending = PendingModel {
            id: self.next_pending_id,
            kind,
            published: false,
            newer_version_seen: false,
            k_fs_before: self.k_fs_generation,
            k_fs_after_pcs: (kind == PendingKind::PcsRefresh)
                .then_some(self.k_fs_generation.saturating_add(1)),
        };
        self.next_pending_id = self.next_pending_id.saturating_add(1);
        self.pending = Some(pending);
        self.barrier_recovery_pending = true;
        self.state = match kind {
            PendingKind::JoinFinalize => ClientRecoveryState::PendingSelfFinalize,
            PendingKind::PcsRefresh => ClientRecoveryState::PendingRecovery,
        };
    }

    fn resolve_pending(&mut self, pending: PendingModel) {
        if !self.activated.insert(pending.id) {
            self.double_activation_detected = true;
        }
        let k_fs_before = self.k_fs_generation;
        match pending.kind {
            PendingKind::JoinFinalize => {
                if self.k_fs_generation != pending.k_fs_before {
                    self.join_finalize_reseed_detected = true;
                }
            }
            PendingKind::PcsRefresh => {
                self.k_fs_generation = pending.k_fs_after_pcs.unwrap_or(k_fs_before);
            }
        }
        if pending.kind == PendingKind::JoinFinalize && self.k_fs_generation != k_fs_before {
            self.join_finalize_reseed_detected = true;
        }
        self.pending = None;
        self.state = ClientRecoveryState::Ready;
        self.barrier_recovery_pending = false;
    }

    fn discard_to_recovery_required(&mut self) {
        self.pending = None;
        self.state = ClientRecoveryState::RecoveryRequired;
        self.barrier_recovery_pending = true;
    }

    fn check_invariants(&mut self) {
        if self.pending.is_some() && !self.barrier_recovery_pending {
            self.silent_clear_detected = true;
        }
        if self.pending.is_none()
            && matches!(
                self.state,
                ClientRecoveryState::PendingRecovery | ClientRecoveryState::PendingSelfFinalize
            )
        {
            self.silent_clear_detected = true;
        }
    }

    fn apply(&mut self, event: ClientStateEvent) {
        match event {
            ClientStateEvent::Join => self.begin_pending(PendingKind::JoinFinalize),
            ClientStateEvent::PublishJoinFinalize => {
                if let Some(pending) = self.pending.as_mut()
                    && pending.kind == PendingKind::JoinFinalize
                {
                    pending.published = true;
                }
            }
            ClientStateEvent::RestartPre => {
                let snapshot = self.canonical_snapshot();
                self.last_restart_snapshot = Some(snapshot);
                if !self.restart_candidates().contains(&snapshot) {
                    self.invalid_restart_detected = true;
                }
            }
            ClientStateEvent::RestartPost => {
                let snapshot = if let Some(pending) = self.pending.clone() {
                    if pending.published {
                        let mut post = self.canonical_snapshot();
                        post.state = ClientRecoveryState::Ready;
                        post.barrier_recovery_pending = false;
                        post.pending_id = None;
                        if let Some(k_fs_after_pcs) = pending.k_fs_after_pcs {
                            post.k_fs_generation = k_fs_after_pcs;
                        }
                        self.resolve_pending(pending);
                        post
                    } else {
                        self.canonical_snapshot()
                    }
                } else {
                    self.canonical_snapshot()
                };
                self.last_restart_snapshot = Some(snapshot);
                if !self.restart_candidates().contains(&snapshot) {
                    self.invalid_restart_detected = true;
                }
            }
            ClientStateEvent::HistoryFoundAccept => {
                if let Some(pending) = self.pending.clone() {
                    self.resolve_pending(pending);
                }
            }
            ClientStateEvent::HistoryFoundReject => {
                let had_pending = self.pending.is_some();
                if let Some(pending) = &self.pending
                    && pending.kind == PendingKind::JoinFinalize
                    && pending.newer_version_seen
                {
                    self.discard_to_recovery_required();
                } else if had_pending && matches!(self.state, ClientRecoveryState::Ready) {
                    self.insufficient_history_ready_detected = true;
                }
            }
            ClientStateEvent::NewerVersionSeen => {
                if let Some(pending) = self.pending.as_mut() {
                    pending.newer_version_seen = true;
                }
            }
            ClientStateEvent::NotFoundAfterNewerVersion => {
                let had_pending = self.pending.is_some();
                if let Some(pending) = &self.pending
                    && pending.newer_version_seen
                {
                    self.discard_to_recovery_required();
                } else if had_pending && matches!(self.state, ClientRecoveryState::Ready) {
                    self.insufficient_history_ready_detected = true;
                }
            }
            ClientStateEvent::PcsRefresh => self.begin_pending(PendingKind::PcsRefresh),
            ClientStateEvent::Leave | ClientStateEvent::MessageFetch => {}
        }
        self.check_invariants();
    }
}

fn event_strategy() -> impl Strategy<Value = Vec<ClientStateEvent>> {
    prop::collection::vec(
        prop_oneof![
            Just(ClientStateEvent::Join),
            Just(ClientStateEvent::PublishJoinFinalize),
            Just(ClientStateEvent::RestartPre),
            Just(ClientStateEvent::RestartPost),
            Just(ClientStateEvent::HistoryFoundAccept),
            Just(ClientStateEvent::HistoryFoundReject),
            Just(ClientStateEvent::NewerVersionSeen),
            Just(ClientStateEvent::NotFoundAfterNewerVersion),
            Just(ClientStateEvent::PcsRefresh),
            Just(ClientStateEvent::Leave),
            Just(ClientStateEvent::MessageFetch),
        ],
        1..64,
    )
}

fn bytes32_strategy() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn testcase_fail<E: std::fmt::Display>(err: E) -> TestCaseError {
    TestCaseError::fail(err.to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn client_state_model_never_silently_clears_pending_recovery(events in event_strategy()) {
        let trace = events.clone();
        let mut model = ClientStateModel::default();
        for event in events {
            model.apply(event);
        }
        prop_assert!(
            !model.silent_clear_detected,
            "pending state cleared without an authenticated resolution in trace {:?}",
            trace
        );
    }

    #[test]
    fn client_state_model_never_activates_same_pending_twice(events in event_strategy()) {
        let trace = events.clone();
        let mut model = ClientStateModel::default();
        for event in events {
            model.apply(event);
        }
        prop_assert!(
            !model.double_activation_detected,
            "same pending activation resolved more than once in trace {:?}",
            trace
        );
    }

    #[test]
    fn client_state_model_join_finalize_does_not_reseed_k_fs(events in event_strategy()) {
        let trace = events.clone();
        let mut model = ClientStateModel::default();
        for event in events {
            model.apply(event);
        }
        prop_assert!(
            !model.join_finalize_reseed_detected,
            "join_finalize reseeded K_fs in trace {:?}",
            trace
        );
    }

    #[test]
    fn client_state_model_restart_is_pre_or_post_transaction_only(events in event_strategy()) {
        let trace = events.clone();
        let mut model = ClientStateModel::default();
        for event in events {
            model.apply(event);
        }
        prop_assert!(
            !model.invalid_restart_detected,
            "restart produced a mixed transaction snapshot in trace {:?}",
            trace
        );
    }

    #[test]
    fn client_state_model_insufficient_history_never_marks_ready(events in event_strategy()) {
        let trace = events.clone();
        let mut model = ClientStateModel::default();
        for event in events {
            model.apply(event);
        }
        prop_assert!(
            !model.insufficient_history_ready_detected,
            "insufficient authenticated history still produced Ready in trace {:?}",
            trace
        );
    }

    #[test]
    fn persisted_pending_state_roundtrip_property_preserves_fields(
        seed in any::<u64>(),
        barrier_version in 1u64..1024,
        fs_ec in 0u64..1024,
        next_forward_fs_ec in 0u64..2048,
        we_epoch_id in bytes32_strategy(),
        next_forward_fs_dev_commit in bytes32_strategy(),
        next_forward_last_weid in bytes32_strategy(),
        revocation_roots_hash in bytes32_strategy(),
        kem_tree_hash_after in bytes32_strategy(),
        k_barrier_new in bytes32_strategy(),
        maybe_k_fs_after_pcs in prop::option::of(bytes32_strategy()),
        barrier_update_digest in bytes32_strategy(),
        pkhash_a in bytes32_strategy(),
        pkhash_b in bytes32_strategy(),
        dk_a in prop::collection::vec(any::<u8>(), 32..96),
        dk_b in prop::collection::vec(any::<u8>(), 32..96),
        barrier_update_reason in prop::option::of(prop_oneof![Just(1u64), Just(2u64)]),
    ) {
        let _env_lock = ENV_VAR_LOCK.lock().map_err(|_| testcase_fail("env var lock poisoned"))?;
        let temp_dir = TempDir::new().map_err(testcase_fail)?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let server_url = format!("https://prop-{}.example.invalid", seed);
        let room_id = format!("{:064x}", u128::from(seed));
        let mut session = build_test_session(
            seed ^ 0x5A5A_5A5A_5A5A_5A5A,
            &server_url,
            &room_id,
            "prop",
        )
        .map_err(testcase_fail)?;
        let mut on_path = BTreeMap::new();
        on_path.insert(
            1,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_a.clone()),
                pkhash: pkhash_a,
            },
        );
        on_path.insert(
            3,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_b.clone()),
                pkhash: pkhash_b,
            },
        );

        session.barrier_state.barrier_recovery_pending = true;
        session.barrier_state.pending = Some(BarrierPendingState {
            barrier_version,
            we_epoch_id,
            fs_ec,
            next_forward_fs_ec,
            next_forward_fs_dev_commit,
            next_forward_last_weid,
            revocation_roots_hash,
            kem_tree_hash_after,
            k_barrier_new: Zeroizing::new(k_barrier_new),
            k_fs_after_pcs: maybe_k_fs_after_pcs.map(Zeroizing::new),
            barrier_update_reason,
            barrier_update_digest,
            on_path_key_material: on_path.clone(),
        });

        persist_session(&session).map_err(testcase_fail)?;
        let loaded = load_session_at(&server_url, &room_id)
            .map_err(testcase_fail)?
            .ok_or_else(|| testcase_fail("expected persisted session after roundtrip"))?;
        let pending = loaded
            .barrier_state
            .pending
            .ok_or_else(|| testcase_fail("expected persisted pending state after roundtrip"))?;

        prop_assert_eq!(pending.barrier_version, barrier_version);
        prop_assert_eq!(pending.we_epoch_id, we_epoch_id);
        prop_assert_eq!(pending.fs_ec, fs_ec);
        prop_assert_eq!(pending.next_forward_fs_ec, next_forward_fs_ec);
        prop_assert_eq!(pending.next_forward_fs_dev_commit, next_forward_fs_dev_commit);
        prop_assert_eq!(pending.next_forward_last_weid, next_forward_last_weid);
        prop_assert_eq!(pending.revocation_roots_hash, revocation_roots_hash);
        prop_assert_eq!(pending.kem_tree_hash_after, kem_tree_hash_after);
        prop_assert_eq!(*pending.k_barrier_new, k_barrier_new);
        prop_assert_eq!(
            pending.k_fs_after_pcs.as_ref().map(|value| **value),
            maybe_k_fs_after_pcs
        );
        prop_assert_eq!(pending.barrier_update_reason, barrier_update_reason);
        prop_assert_eq!(pending.barrier_update_digest, barrier_update_digest);
        prop_assert_eq!(pending.on_path_key_material.len(), on_path.len());

        let loaded_a = pending
            .on_path_key_material
            .get(&1)
            .ok_or_else(|| testcase_fail("missing persisted key material for node 1"))?;
        prop_assert_eq!(loaded_a.pkhash, pkhash_a);
        prop_assert_eq!(&*loaded_a.dk, dk_a.as_slice());

        let loaded_b = pending
            .on_path_key_material
            .get(&3)
            .ok_or_else(|| testcase_fail("missing persisted key material for node 3"))?;
        prop_assert_eq!(loaded_b.pkhash, pkhash_b);
        prop_assert_eq!(&*loaded_b.dk, dk_b.as_slice());
    }
}
