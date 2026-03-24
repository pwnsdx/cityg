use super::*;

#[derive(Serialize, Deserialize)]
pub(in crate::native) struct PersistedSession {
    pub(in crate::native) version: u32,
    pub(in crate::native) server_url: String,
    pub(in crate::native) room_id: String,
    pub(in crate::native) alias: String,
    pub(in crate::native) gid_hex: String,
    pub(in crate::native) cat_hex: String,
    pub(in crate::native) leaf_hex: String,
    pub(in crate::native) parent_root_hex: String,
    pub(in crate::native) join_delta_root_hex: String,
    pub(in crate::native) revoked_since_root_hex: String,
    pub(in crate::native) revoked_root_hex: String,
    pub(in crate::native) tswe_salt_hash_hex: String,
    pub(in crate::native) pox_r_commit_hex: String,
    pub(in crate::native) we_epoch_id_hex: String,
    #[serde(default)]
    pub(in crate::native) xk_hash_hex: String,
    pub(in crate::native) epoch_key_hex: String,
    pub(in crate::native) proof_mode: String,
    pub(in crate::native) vrf_id: String,
    pub(in crate::native) policy_version: String,
    pub(in crate::native) msphf_crs_id: String,
    pub(in crate::native) msphf_params_id: String,
    pub(in crate::native) fs_policy_version: String,
    pub(in crate::native) fs_epoch_base_ts: u64,
    pub(in crate::native) kbroad_public_hex: String,
    pub(in crate::native) bootstrap_public_hex: String,
    pub(in crate::native) pop_public_hex: String,
    pub(in crate::native) pop_secret_hex: String,
    pub(in crate::native) msg_sign_public_hex: String,
    pub(in crate::native) msg_sign_secret_hex: String,
    pub(in crate::native) vrf_public_hex: String,
    pub(in crate::native) vrf_secret_hex: String,
    pub(in crate::native) fs_ec: u64,
    pub(in crate::native) fs_epoch_commit_hex: String,
    pub(in crate::native) fs_dev_prev_commit_hex: String,
    #[serde(default = "super::default_epoch_rotation_interval")]
    pub(in crate::native) fs_epoch_rotation_interval_secs: u64,
    #[serde(default)]
    pub(in crate::native) fs_epoch_created_at_unix_ms: u64,
    pub(in crate::native) forward_state: PersistedForwardState,
    #[serde(default)]
    pub(in crate::native) last_fetch_timestamp_ms: Option<u64>,
    #[serde(default)]
    pub(in crate::native) msg_replay_state: PersistedMsgReplayState,
    #[serde(default)]
    pub(in crate::native) capss_witness_hex: String,
    #[serde(default)]
    pub(in crate::native) regular_fingerprint_hex: String,
    #[serde(default)]
    pub(in crate::native) barrier_state: PersistedBarrierState,
}

impl PersistedSession {
    pub(in crate::native) fn from_session(session: &AppSession) -> Self {
        let snapshot = session.forward_state.snapshot();
        let fs_epoch_created_at_unix_ms = session
            .fs_epoch_created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        Self {
            version: 12,
            server_url: session.server_url.clone(),
            room_id: session.room_id.clone(),
            alias: session.alias.clone(),
            gid_hex: hex_encode(session.gid),
            cat_hex: hex_encode(session.cat),
            leaf_hex: hex_encode(session.leaf_id),
            parent_root_hex: hex_encode(session.parent_root),
            join_delta_root_hex: hex_encode(session.join_delta_root),
            revoked_since_root_hex: hex_encode(session.revoked_since_root),
            revoked_root_hex: hex_encode(session.revoked_root),
            tswe_salt_hash_hex: hex_encode(session.tswe_salt_hash),
            pox_r_commit_hex: hex_encode(session.pox_r_commit),
            we_epoch_id_hex: hex_encode(session.we_epoch_id),
            xk_hash_hex: hex_encode(session.xk_hash),
            epoch_key_hex: hex_encode(session.epoch_key),
            proof_mode: session.proof_mode.clone(),
            vrf_id: session.vrf_id.clone(),
            policy_version: session.policy_version.clone(),
            msphf_crs_id: session.msphf_crs_id.clone(),
            msphf_params_id: session.msphf_params_id.clone(),
            fs_policy_version: session.fs_policy_version.clone(),
            fs_epoch_base_ts: session.fs_epoch_base_ts,
            kbroad_public_hex: hex_encode(&session.kbroad_public),
            bootstrap_public_hex: hex_encode(&session.bootstrap_public),
            pop_public_hex: hex_encode(&session.pop_public_key),
            pop_secret_hex: hex_encode(&session.pop_secret_key),
            msg_sign_public_hex: hex_encode(&session.msg_sign_public_key),
            msg_sign_secret_hex: hex_encode(&session.msg_sign_secret_key),
            vrf_public_hex: hex_encode(&session.vrf_public_key),
            vrf_secret_hex: hex_encode(&session.vrf_secret_key),
            fs_ec: session.fs_ec,
            fs_epoch_commit_hex: hex_encode(session.fs_epoch_commit),
            fs_dev_prev_commit_hex: hex_encode(session.fs_dev_prev_commit),
            fs_epoch_created_at_unix_ms,
            fs_epoch_rotation_interval_secs: session.fs_epoch_rotation_interval_secs,
            forward_state: PersistedForwardState {
                k_fs_hex: hex_encode(snapshot.k_fs),
                fs_ec: snapshot.fs_ec,
                fs_dev_commit_hex: hex_encode(snapshot.fs_dev_commit),
                fs_last_weid_hex: hex_encode(snapshot.last_weid),
            },
            last_fetch_timestamp_ms: session.last_fetch_timestamp_ms,
            msg_replay_state: PersistedMsgReplayState::from_runtime(&session.msg_replay_state),
            capss_witness_hex: hex_encode(&session.capss_witness),
            regular_fingerprint_hex: session
                .regular_fingerprint
                .as_ref()
                .map(hex_encode)
                .unwrap_or_default(),
            barrier_state: PersistedBarrierState::from_runtime(&session.barrier_state),
        }
    }

    pub(in crate::native) fn into_app_session(self) -> Result<AppSession> {
        let PersistedSession {
            version,
            server_url,
            room_id,
            alias,
            gid_hex,
            cat_hex,
            leaf_hex,
            parent_root_hex,
            join_delta_root_hex,
            revoked_since_root_hex,
            revoked_root_hex,
            tswe_salt_hash_hex,
            pox_r_commit_hex,
            we_epoch_id_hex,
            xk_hash_hex,
            epoch_key_hex,
            proof_mode,
            vrf_id,
            policy_version,
            msphf_crs_id,
            msphf_params_id,
            fs_policy_version,
            fs_epoch_base_ts,
            kbroad_public_hex,
            bootstrap_public_hex,
            pop_public_hex,
            pop_secret_hex,
            msg_sign_public_hex,
            msg_sign_secret_hex,
            vrf_public_hex,
            vrf_secret_hex,
            fs_ec: fs_join_ec,
            fs_epoch_commit_hex,
            fs_dev_prev_commit_hex,
            fs_epoch_rotation_interval_secs,
            fs_epoch_created_at_unix_ms,
            forward_state,
            last_fetch_timestamp_ms,
            msg_replay_state,
            capss_witness_hex,
            regular_fingerprint_hex,
            barrier_state,
        } = self;

        if !(version == 4
            || version == 5
            || version == 6
            || version == 7
            || version == 8
            || version == 9
            || version == 10
            || version == 11
            || version == 12)
        {
            return Err(anyhow!(
                "unsupported session file version {version} (expected 4, 5, 6, 7, 8, 9, 10, 11, or 12 with ML-DSA-65 authentication)"
            ));
        }

        let gid = decode_hex32("gid_hex", &gid_hex)?;
        let cat = decode_hex32("cat_hex", &cat_hex)?;
        let leaf_id = decode_hex32("leaf_hex", &leaf_hex)?;
        let parent_root = decode_hex32("parent_root_hex", &parent_root_hex)?;
        let join_delta_root = decode_hex32("join_delta_root_hex", &join_delta_root_hex)?;
        let revoked_since_root = decode_hex32("revoked_since_root_hex", &revoked_since_root_hex)?;
        let revoked_root = decode_hex32("revoked_root_hex", &revoked_root_hex)?;
        let tswe_salt_hash = decode_hex32("tswe_salt_hash_hex", &tswe_salt_hash_hex)?;
        let pox_r_commit = decode_hex32("pox_r_commit_hex", &pox_r_commit_hex)?;
        let we_epoch_id = decode_hex32("we_epoch_id_hex", &we_epoch_id_hex)?;
        let xk_hash = decode_hex32_or_zero("xk_hash_hex", &xk_hash_hex)?;
        let epoch_key = decode_hex32("epoch_key_hex", &epoch_key_hex)?;
        let kbroad_public = decode_hex_vec("kbroad_public_hex", &kbroad_public_hex)?;
        let bootstrap_public = decode_hex_vec("bootstrap_public_hex", &bootstrap_public_hex)?;
        let pop_public_key = decode_hex_vec("pop_public_hex", &pop_public_hex)?;
        let pop_secret_key = decode_hex_vec("pop_secret_hex", &pop_secret_hex)?;
        let msg_sign_public_key = decode_hex_vec("msg_sign_public_hex", &msg_sign_public_hex)?;
        let msg_sign_secret_key = decode_hex_vec("msg_sign_secret_hex", &msg_sign_secret_hex)?;
        let vrf_public_key = decode_hex_vec("vrf_public_hex", &vrf_public_hex)?;
        let vrf_secret_key = decode_hex_vec("vrf_secret_hex", &vrf_secret_hex)?;
        let fs_epoch_commit = decode_hex32("fs_epoch_commit_hex", &fs_epoch_commit_hex)?;
        let fs_dev_prev_commit = decode_hex32("fs_dev_prev_commit_hex", &fs_dev_prev_commit_hex)?;
        let capss_witness = decode_hex_vec("capss_witness_hex", &capss_witness_hex)?;
        let msg_replay_state = msg_replay_state.into_runtime()?;
        let barrier_state = barrier_state.into_runtime()?;
        let regular_fingerprint = if regular_fingerprint_hex.is_empty() {
            None
        } else {
            Some(decode_hex32(
                "regular_fingerprint_hex",
                &regular_fingerprint_hex,
            )?)
        };
        let PersistedForwardState {
            k_fs_hex,
            fs_ec,
            fs_dev_commit_hex,
            fs_last_weid_hex,
        } = forward_state;

        let k_fs = decode_hex32("forward_state.k_fs_hex", &k_fs_hex)?;
        let fs_dev_commit = decode_hex32("forward_state.fs_dev_commit_hex", &fs_dev_commit_hex)?;
        let fs_last_weid = if fs_last_weid_hex.is_empty() {
            we_epoch_id
        } else {
            decode_hex32("forward_state.fs_last_weid_hex", &fs_last_weid_hex)?
        };
        let forward_state =
            ForwardSecrecyState::with_state(k_fs, fs_ec, fs_dev_commit, fs_last_weid);

        let fs_epoch_created_at = if fs_epoch_created_at_unix_ms > 0 {
            UNIX_EPOCH + Duration::from_millis(fs_epoch_created_at_unix_ms)
        } else {
            SystemTime::now()
        };

        let mut session = AppSession {
            server_url,
            room_id,
            alias,
            gid,
            cat,
            leaf_id,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            regular_fingerprint,
            fs_fingerprint: None,
            tswe_salt_hash,
            pox_r_commit,
            we_epoch_id,
            xk_hash,
            epoch_key,
            forward_state,
            fs_ec: fs_join_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            fs_epoch_created_at,
            fs_epoch_rotation_interval_secs,
            pop_public_key,
            pop_secret_key,
            msg_sign_public_key,
            msg_sign_secret_key,
            vrf_secret_key,
            vrf_public_key,
            kbroad_public,
            bootstrap_public,
            proof_mode,
            vrf_id,
            policy_version,
            msphf_crs_id,
            msphf_params_id,
            fs_policy_version,
            fs_epoch_base_ts,
            last_fetch_timestamp_ms,
            msg_replay_state,
            capss_witness,
            barrier_state,
        };

        session.fs_fingerprint = derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        );
        let legacy_barrier_state_present = session.barrier_state.barrier_recovery_pending
            || session.barrier_state.barrier_version > 0
            || session.barrier_state.kem_tree_hash_after != [0u8; 32]
            || *session.barrier_state.k_barrier != [0u8; 32]
            || !session.barrier_state.dk_leaf.is_empty()
            || !session.barrier_state.dk_nodes.is_empty();
        if !session.barrier_state.barrier_initialized && legacy_barrier_state_present {
            session.barrier_state.barrier_initialized = true;
        }
        if session.barrier_state.barrier_initialized
            && session.barrier_state.barrier_roots_hash == [0u8; 32]
        {
            session.barrier_state.barrier_roots_hash =
                compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
        }

        Ok(session)
    }
}
