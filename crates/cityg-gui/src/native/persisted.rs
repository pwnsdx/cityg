use super::*;

pub(super) const ROOM_IDENTITY_VERSION: u32 = 1;
pub(super) const ALIAS_STORE_VERSION: u32 = 2;
pub(super) const SECURITY_LOG_VERSION: u32 = 1;
pub(super) const MAX_SECURITY_EVENTS: usize = 128;
pub(super) const MAX_ACTIVITY_EVENTS: usize = 256;
pub(super) const ENCRYPTED_SESSION_ENVELOPE_VERSION: u32 = 1;
pub(super) const ENCRYPTED_SESSION_ALG: &str = "chacha20poly1305";
pub(super) const SESSION_PASSPHRASE_ENV: &str = "CITYG_GUI_SESSION_PASSPHRASE";
pub(super) const CLIENT_ADMIN_TOKEN_ENV: &str = "CITYG_CLIENT_ADMIN_TOKEN";
pub(super) const CLIENT_MESSAGE_TOKEN_ENV: &str = "CITYG_CLIENT_MESSAGE_AUTH_TOKEN";
pub(super) const SESSION_KEY_DERIVE_CONTEXT: &str = "cityg/gui/session-encryption/v1";
pub(super) const SESSION_LOCAL_KEY_FILE: &str = "session-key-v1.bin";

#[derive(Serialize, Deserialize)]
pub(super) struct PersistedSession {
    pub(super) version: u32,
    pub(super) server_url: String,
    pub(super) room_id: String,
    pub(super) alias: String,
    pub(super) gid_hex: String,
    pub(super) cat_hex: String,
    pub(super) leaf_hex: String,
    pub(super) parent_root_hex: String,
    pub(super) join_delta_root_hex: String,
    pub(super) revoked_since_root_hex: String,
    pub(super) revoked_root_hex: String,
    pub(super) tswe_salt_hash_hex: String,
    pub(super) pox_r_commit_hex: String,
    pub(super) we_epoch_id_hex: String,
    #[serde(default)]
    pub(super) xk_hash_hex: String,
    pub(super) epoch_key_hex: String,
    pub(super) proof_mode: String,
    pub(super) vrf_id: String,
    pub(super) policy_version: String,
    pub(super) msphf_crs_id: String,
    pub(super) msphf_params_id: String,
    pub(super) fs_policy_version: String,
    pub(super) fs_epoch_base_ts: u64,
    pub(super) kbroad_public_hex: String,
    pub(super) bootstrap_public_hex: String,
    pub(super) pop_public_hex: String,
    pub(super) pop_secret_hex: String,
    pub(super) msg_sign_public_hex: String,
    pub(super) msg_sign_secret_hex: String,
    pub(super) vrf_public_hex: String,
    pub(super) vrf_secret_hex: String,
    pub(super) fs_ec: u64,
    pub(super) fs_epoch_commit_hex: String,
    pub(super) fs_dev_prev_commit_hex: String,
    #[serde(default = "default_epoch_rotation_interval")]
    pub(super) fs_epoch_rotation_interval_secs: u64,
    #[serde(default)]
    pub(super) fs_epoch_created_at_unix_ms: u64,
    pub(super) forward_state: PersistedForwardState,
    #[serde(default)]
    pub(super) last_fetch_timestamp_ms: Option<u64>,
    #[serde(default)]
    pub(super) msg_replay_state: PersistedMsgReplayState,
    #[serde(default)]
    pub(super) capss_witness_hex: String,
    #[serde(default)]
    pub(super) regular_fingerprint_hex: String,
    #[serde(default)]
    pub(super) barrier_state: PersistedBarrierState,
}

#[derive(Serialize, Deserialize)]
pub(super) struct PersistedRoomIdentity {
    version: u32,
    pop_public_hex: String,
    pop_secret_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedAliasStore {
    pub(super) version: u32,
    pub(super) bindings: AHashMap<String, PersistedAliasBinding>,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedAliasBinding {
    pub(super) pop_public_key_hex: String,
    #[serde(default)]
    pub(super) leaf_id_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedSecurityLog {
    pub(super) version: u32,
    pub(super) events: Vec<PersistedSecurityEvent>,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedSecurityEvent {
    pub(super) alias: String,
    pub(super) description: String,
    pub(super) timestamp_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct PersistedForwardState {
    pub(super) k_fs_hex: String,
    pub(super) fs_ec: u64,
    pub(super) fs_dev_commit_hex: String,
    #[serde(default)]
    pub(super) fs_last_weid_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedBarrierState {
    #[serde(default)]
    pub(super) barrier_initialized: bool,
    #[serde(default)]
    pub(super) barrier_version: u64,
    #[serde(default)]
    pub(super) barrier_roots_hash_hex: String,
    #[serde(default)]
    pub(super) k_barrier_hex: String,
    #[serde(default)]
    pub(super) kem_tree_hash_after_hex: String,
    #[serde(default = "default_max_barrier_update_bytes")]
    pub(super) max_barrier_update_bytes: u64,
    #[serde(default = "default_barrier_n_max")]
    pub(super) n_max: u64,
    #[serde(default)]
    pub(super) cover_leaf_index: u64,
    #[serde(default)]
    pub(super) dk_leaf_hex: String,
    #[serde(default)]
    pub(super) pkhash_leaf_hex: String,
    #[serde(default)]
    pub(super) dk_nodes: BTreeMap<u32, PersistedBarrierNodeKeyMaterial>,
    #[serde(default)]
    pub(super) pending: Option<PersistedBarrierPendingState>,
    #[serde(default = "default_barrier_recovery_pending")]
    pub(super) barrier_recovery_pending: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedBarrierNodeKeyMaterial {
    #[serde(default)]
    pub(super) dk_hex: String,
    #[serde(default)]
    pub(super) pkhash_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct PersistedBarrierPendingState {
    #[serde(default)]
    pub(super) barrier_version: u64,
    #[serde(default)]
    pub(super) we_epoch_id_hex: String,
    #[serde(default)]
    pub(super) fs_ec: u64,
    #[serde(default)]
    pub(super) next_forward_fs_ec: u64,
    #[serde(default)]
    pub(super) next_forward_fs_dev_commit_hex: String,
    #[serde(default)]
    pub(super) next_forward_last_weid_hex: String,
    #[serde(default)]
    pub(super) revocation_roots_hash_hex: String,
    #[serde(default)]
    pub(super) kem_tree_hash_after_hex: String,
    #[serde(default)]
    pub(super) k_barrier_new_hex: String,
    #[serde(default)]
    pub(super) k_fs_after_pcs_hex: String,
    #[serde(default)]
    pub(super) barrier_update_reason: Option<u64>,
    #[serde(default)]
    pub(super) barrier_update_digest_hex: String,
    #[serde(default)]
    pub(super) on_path_key_material: BTreeMap<u32, PersistedBarrierNodeKeyMaterial>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct EncryptedSessionEnvelope {
    pub(super) version: u32,
    pub(super) alg: String,
    pub(super) key_source: String,
    pub(super) nonce_hex: String,
    pub(super) ciphertext_hex: String,
}

#[derive(Clone, Copy)]
pub(super) enum SessionKeySource {
    EnvPassphrase,
    LocalKeyFile,
}

impl SessionKeySource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            SessionKeySource::EnvPassphrase => "env-passphrase",
            SessionKeySource::LocalKeyFile => "local-key-file",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct LastSessionPointer {
    pub(super) server_url: String,
    pub(super) room_id: String,
}

pub(super) fn default_epoch_rotation_interval() -> u64 {
    300
}

fn read_nonempty_env(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn configured_client_admin_token() -> Option<String> {
    read_nonempty_env(CLIENT_ADMIN_TOKEN_ENV)
        .or_else(|| read_nonempty_env("CITYG_SERVER_ROOMS_ADMIN_TOKEN"))
        .or_else(|| read_nonempty_env("CITYG_SERVER_WINDOW_ADMIN_TOKEN"))
}

pub(super) fn configured_client_message_token() -> Option<String> {
    read_nonempty_env(CLIENT_MESSAGE_TOKEN_ENV)
        .or_else(|| read_nonempty_env("CITYG_SERVER_MESSAGE_AUTH_TOKEN"))
}

fn default_barrier_n_max() -> u64 {
    DEFAULT_BARRIER_N_MAX
}

fn default_max_barrier_update_bytes() -> u64 {
    0
}

fn default_barrier_recovery_pending() -> bool {
    false
}

pub(super) fn new_api_client(server_url: &str) -> CitygApiClient {
    let mut client = CitygApiClient::new(server_url);
    if let Some(token) = configured_client_admin_token() {
        client = client.with_admin_token(token);
    }
    if let Some(token) = configured_client_message_token() {
        client = client.with_message_auth_token(token);
    }
    client
}

impl PersistedRoomIdentity {
    pub(super) fn from_runtime(identity: &RoomIdentity) -> Self {
        Self {
            version: ROOM_IDENTITY_VERSION,
            pop_public_hex: hex_encode(&identity.pop_public_key),
            pop_secret_hex: hex_encode(&identity.pop_secret_key),
        }
    }

    pub(super) fn into_runtime(self) -> Result<RoomIdentity> {
        if self.version != ROOM_IDENTITY_VERSION {
            return Err(anyhow!(
                "unsupported room identity file version {} (expected {})",
                self.version,
                ROOM_IDENTITY_VERSION
            ));
        }

        Ok(RoomIdentity {
            pop_public_key: decode_hex_vec("pop_public_hex", &self.pop_public_hex)?,
            pop_secret_key: decode_hex_vec("pop_secret_hex", &self.pop_secret_hex)?,
        })
    }
}

impl PersistedBarrierNodeKeyMaterial {
    fn from_runtime(material: &BarrierNodeKeyMaterial) -> Self {
        Self {
            dk_hex: hex_encode(material.dk.as_slice()),
            pkhash_hex: hex_encode(material.pkhash),
        }
    }

    fn into_runtime(self, field_prefix: &str) -> Result<BarrierNodeKeyMaterial> {
        let dk = decode_hex_vec(&format!("{field_prefix}.dk_hex"), &self.dk_hex)?;
        let pkhash = decode_hex32_or_zero(&format!("{field_prefix}.pkhash_hex"), &self.pkhash_hex)?;
        Ok(BarrierNodeKeyMaterial {
            dk: Zeroizing::new(dk),
            pkhash,
        })
    }
}

impl PersistedBarrierPendingState {
    fn from_runtime(pending: &BarrierPendingState) -> Self {
        let on_path_key_material = pending
            .on_path_key_material
            .iter()
            .map(|(node, material)| {
                (
                    *node,
                    PersistedBarrierNodeKeyMaterial::from_runtime(material),
                )
            })
            .collect();
        Self {
            barrier_version: pending.barrier_version,
            we_epoch_id_hex: hex_encode(pending.we_epoch_id),
            fs_ec: pending.fs_ec,
            next_forward_fs_ec: pending.next_forward_fs_ec,
            next_forward_fs_dev_commit_hex: hex_encode(pending.next_forward_fs_dev_commit),
            next_forward_last_weid_hex: hex_encode(pending.next_forward_last_weid),
            revocation_roots_hash_hex: hex_encode(pending.revocation_roots_hash),
            kem_tree_hash_after_hex: hex_encode(pending.kem_tree_hash_after),
            k_barrier_new_hex: hex_encode(*pending.k_barrier_new),
            k_fs_after_pcs_hex: pending
                .k_fs_after_pcs
                .as_ref()
                .map(|value| hex_encode(**value))
                .unwrap_or_default(),
            barrier_update_reason: pending.barrier_update_reason,
            barrier_update_digest_hex: hex_encode(pending.barrier_update_digest),
            on_path_key_material,
        }
    }

    fn into_runtime(self) -> Result<BarrierPendingState> {
        let mut on_path_key_material = BTreeMap::new();
        for (node, material) in self.on_path_key_material {
            on_path_key_material.insert(
                node,
                material.into_runtime(&format!(
                    "barrier_state.pending.on_path_key_material[{node}]"
                ))?,
            );
        }
        let k_fs_after_pcs = if self.k_fs_after_pcs_hex.is_empty() {
            None
        } else {
            Some(decode_hex32(
                "barrier_state.pending.k_fs_after_pcs_hex",
                &self.k_fs_after_pcs_hex,
            )?)
        };
        Ok(BarrierPendingState {
            barrier_version: self.barrier_version,
            we_epoch_id: decode_hex32_or_zero(
                "barrier_state.pending.we_epoch_id_hex",
                &self.we_epoch_id_hex,
            )?,
            fs_ec: self.fs_ec,
            next_forward_fs_ec: self.next_forward_fs_ec,
            next_forward_fs_dev_commit: decode_hex32_or_zero(
                "barrier_state.pending.next_forward_fs_dev_commit_hex",
                &self.next_forward_fs_dev_commit_hex,
            )?,
            next_forward_last_weid: decode_hex32_or_zero(
                "barrier_state.pending.next_forward_last_weid_hex",
                &self.next_forward_last_weid_hex,
            )?,
            revocation_roots_hash: decode_hex32_or_zero(
                "barrier_state.pending.revocation_roots_hash_hex",
                &self.revocation_roots_hash_hex,
            )?,
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.pending.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            k_barrier_new: decode_hex32_or_zero(
                "barrier_state.pending.k_barrier_new_hex",
                &self.k_barrier_new_hex,
            )
            .map(Zeroizing::new)?,
            k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
            barrier_update_reason: self.barrier_update_reason,
            barrier_update_digest: decode_hex32_or_zero(
                "barrier_state.pending.barrier_update_digest_hex",
                &self.barrier_update_digest_hex,
            )?,
            on_path_key_material,
        })
    }
}

impl PersistedBarrierState {
    fn from_runtime(state: &BarrierSecretState) -> Self {
        let dk_nodes = state
            .dk_nodes
            .iter()
            .map(|(node, material)| {
                (
                    *node,
                    PersistedBarrierNodeKeyMaterial::from_runtime(material),
                )
            })
            .collect();
        Self {
            barrier_initialized: state.barrier_initialized,
            barrier_version: state.barrier_version,
            barrier_roots_hash_hex: hex_encode(state.barrier_roots_hash),
            k_barrier_hex: hex_encode(*state.k_barrier),
            kem_tree_hash_after_hex: hex_encode(state.kem_tree_hash_after),
            max_barrier_update_bytes: state.max_barrier_update_bytes,
            n_max: state.n_max.max(1),
            cover_leaf_index: state.cover_leaf_index,
            dk_leaf_hex: hex_encode(state.dk_leaf.as_slice()),
            pkhash_leaf_hex: hex_encode(state.pkhash_leaf),
            dk_nodes,
            pending: state
                .pending
                .as_ref()
                .map(PersistedBarrierPendingState::from_runtime),
            barrier_recovery_pending: state.barrier_recovery_pending,
        }
    }

    fn into_runtime(self) -> Result<BarrierSecretState> {
        let mut dk_nodes = BTreeMap::new();
        for (node, material) in self.dk_nodes {
            dk_nodes.insert(
                node,
                material.into_runtime(&format!("barrier_state.dk_nodes[{node}]"))?,
            );
        }
        Ok(BarrierSecretState {
            barrier_initialized: self.barrier_initialized,
            barrier_version: self.barrier_version,
            barrier_roots_hash: decode_hex32_or_zero(
                "barrier_state.barrier_roots_hash_hex",
                &self.barrier_roots_hash_hex,
            )?,
            k_barrier: Zeroizing::new(decode_hex32_or_zero(
                "barrier_state.k_barrier_hex",
                &self.k_barrier_hex,
            )?),
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            max_barrier_update_bytes: self.max_barrier_update_bytes,
            n_max: self.n_max.max(1),
            cover_leaf_index: self.cover_leaf_index,
            dk_leaf: Zeroizing::new(decode_hex_vec(
                "barrier_state.dk_leaf_hex",
                &self.dk_leaf_hex,
            )?),
            pkhash_leaf: decode_hex32_or_zero(
                "barrier_state.pkhash_leaf_hex",
                &self.pkhash_leaf_hex,
            )?,
            dk_nodes,
            pending: self
                .pending
                .map(PersistedBarrierPendingState::into_runtime)
                .transpose()?,
            barrier_recovery_pending: self.barrier_recovery_pending,
        })
    }
}

impl PersistedSession {
    pub(super) fn from_session(session: &AppSession) -> Self {
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

    pub(super) fn into_app_session(self) -> Result<AppSession> {
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
