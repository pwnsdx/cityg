use super::*;

pub(super) struct JoinParams {
    pub(super) server_url: String,
    pub(super) room_id: String,
    pub(super) alias: String,
}

#[derive(Clone)]
pub(super) struct LeaveRequest {
    pub(super) server_url: String,
    pub(super) room_id: String,
    pub(super) gid: [u8; 32],
    pub(super) leaf_id: [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) current_history_commitment: Option<HistoryCommitment>,
    pub(super) forward_state: ForwardSecrecyState,
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
    pub(super) vrf_secret_key: Vec<u8>,
    pub(super) vrf_public_key: Vec<u8>,
    pub(super) fs_ec: u64,
    pub(super) fs_epoch_commit: [u8; 32],
    pub(super) fs_dev_prev_commit: [u8; 32],
    pub(super) k_fs_current: [u8; 32],
    pub(super) max_barrier_update_bytes: u64,
    pub(super) barrier_recovery_pending: bool,
    pub(super) current_barrier_full_verified: bool,
    pub(super) join_finalize_auth_token: [u8; 32],
}

#[derive(Clone)]
pub(super) struct MembersParams {
    pub(super) server_url: String,
    pub(super) gid: [u8; 32],
    pub(super) parent_root: [u8; 32],
    pub(super) offset: u64,
    pub(super) limit: u32,
    pub(super) mode: MembersMode,
}

#[derive(Clone)]
pub(super) struct RoomAdminQueryParams {
    pub(super) server_url: String,
    pub(super) room_id: String,
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(super) enum RoomAdminMutationKind {
    Grant,
    Revoke,
}

impl RoomAdminMutationKind {
    pub(super) fn operation(self) -> RoomAdminOperation {
        match self {
            Self::Grant => RoomAdminOperation::GrantAdmin,
            Self::Revoke => RoomAdminOperation::RevokeAdmin,
        }
    }

    pub(super) fn present_progressive(self) -> &'static str {
        match self {
            Self::Grant => "Granting room-admin access…",
            Self::Revoke => "Revoking room-admin access…",
        }
    }

    pub(super) fn success_message(self) -> &'static str {
        match self {
            Self::Grant => "Room admin granted",
            Self::Revoke => "Room admin revoked",
        }
    }
}

#[derive(Clone)]
pub(super) struct RoomAdminMutationParams {
    pub(super) query: RoomAdminQueryParams,
    pub(super) target_pop_public_key: Vec<u8>,
    pub(super) kind: RoomAdminMutationKind,
}

#[derive(Clone)]
pub(super) struct RoomAdminMutationOutcome {
    pub(super) status: String,
    pub(super) admin_count: u64,
}

pub(super) struct MembersPage {
    pub(super) members: Vec<MemberEntry>,
    pub(super) root: [u8; 32],
    pub(super) total_count: u64,
    pub(super) next_offset: u64,
}

impl LeaveRequest {
    pub(super) fn from_session(session: &AppSession) -> Self {
        Self {
            server_url: session.server_url.clone(),
            room_id: session.room_id.clone(),
            gid: session.gid,
            leaf_id: session.leaf_id,
            barrier_version: session.barrier_state.barrier_version,
            kem_tree_hash_after: session.barrier_state.kem_tree_hash_after,
            current_history_commitment: session.barrier_state.current_history_commitment,
            forward_state: session.forward_state.clone(),
            pop_public_key: session.pop_public_key.clone(),
            pop_secret_key: session.pop_secret_key.clone(),
            vrf_secret_key: session.vrf_secret_key.clone(),
            vrf_public_key: session.vrf_public_key.clone(),
            fs_ec: session.fs_ec,
            fs_epoch_commit: session.fs_epoch_commit,
            fs_dev_prev_commit: session.fs_dev_prev_commit,
            k_fs_current: session.forward_state.snapshot().k_fs,
            max_barrier_update_bytes: session.barrier_state.max_barrier_update_bytes,
            barrier_recovery_pending: session.barrier_state.barrier_recovery_pending,
            current_barrier_full_verified: session.barrier_state.current_barrier_full_verified,
            join_finalize_auth_token: session.barrier_state.bootstrap_join_finalize_auth_token,
        }
    }
}

impl MembersParams {
    pub(super) fn from_session(
        session: &AppSession,
        offset: u64,
        limit: u32,
        mode: MembersMode,
    ) -> Self {
        Self {
            server_url: session.server_url.clone(),
            gid: session.gid,
            parent_root: session.parent_root,
            offset,
            limit,
            mode,
        }
    }
}

impl RoomAdminQueryParams {
    pub(super) fn from_session(session: &AppSession) -> Self {
        Self {
            server_url: session.server_url.clone(),
            room_id: session.room_id.clone(),
            pop_public_key: session.pop_public_key.clone(),
            pop_secret_key: session.pop_secret_key.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) struct SendParams {
    pub(super) server_url: String,
    pub(super) gid: [u8; 32],
    pub(super) we_epoch_id: [u8; 32],
    pub(super) xk_hash: [u8; 32],
    pub(super) epoch_key: [u8; 32],
    pub(super) fs_ec: u64,
    pub(super) barrier_version: u64,
    pub(super) k_barrier: [u8; 32],
    pub(super) msg_index: u64,
    pub(super) leaf_id: [u8; 32],
    pub(super) alias: String,
    pub(super) plaintext: String,
    pub(super) pop_secret_key: Vec<u8>,
    pub(super) pop_public_key: Vec<u8>,
}

impl SendParams {
    pub(super) fn from_session(
        session: &AppSession,
        plaintext: String,
        msg_index: u64,
    ) -> Result<Self> {
        if session.barrier_state.barrier_recovery_pending {
            return Err(anyhow!(
                "Cannot send messages while barrier recovery is pending. Waiting for next barrier update."
            ));
        }
        Ok(Self {
            server_url: session.server_url.clone(),
            gid: session.gid,
            we_epoch_id: session.we_epoch_id,
            xk_hash: session.xk_hash,
            epoch_key: session.epoch_key,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_state.barrier_version,
            k_barrier: *session.barrier_state.k_barrier,
            msg_index,
            leaf_id: session.leaf_id,
            alias: session.alias.clone(),
            plaintext,
            pop_secret_key: session.pop_secret_key.clone(),
            pop_public_key: session.pop_public_key.clone(),
        })
    }
}

#[derive(Clone)]
pub(super) struct FetchParams {
    pub(super) server_url: String,
    pub(super) gid: [u8; 32],
    pub(super) we_epoch_id: [u8; 32],
    pub(super) xk_hash: [u8; 32],
    pub(super) epoch_key: [u8; 32],
    pub(super) fs_ec: u64,
    pub(super) barrier_version: u64,
    pub(super) k_barrier: [u8; 32],
    pub(super) n_max: u64,
    pub(super) msg_replay_state: MsgReplayState,
    pub(super) leaf_id: [u8; 32],
    pub(super) since: Option<u64>,
}

impl FetchParams {
    pub(super) fn from_session(session: &AppSession, since: Option<u64>) -> Result<Self> {
        if session.barrier_state.barrier_recovery_pending {
            return Err(anyhow!(
                "Cannot fetch/decrypt messages while barrier recovery is pending. Waiting for next barrier update."
            ));
        }
        Ok(Self {
            server_url: session.server_url.clone(),
            gid: session.gid,
            we_epoch_id: session.we_epoch_id,
            xk_hash: session.xk_hash,
            epoch_key: session.epoch_key,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_state.barrier_version,
            k_barrier: *session.barrier_state.k_barrier,
            n_max: session.barrier_state.n_max,
            msg_replay_state: session.msg_replay_state.clone(),
            leaf_id: session.leaf_id,
            since,
        })
    }
}

pub(super) struct FetchOutcome {
    pub(super) messages: Vec<ChatMessageEntry>,
    pub(super) last_timestamp_ms: Option<u64>,
    pub(super) msg_replay_state: MsgReplayState,
}

pub(super) struct EpochSyncOutcome {
    pub(super) session: AppSession,
    pub(super) changed: bool,
}
