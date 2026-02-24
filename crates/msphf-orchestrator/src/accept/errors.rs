use crate::mhw::FreezeError;

pub const FREEZE_SEEDCTX_MISMATCH: FreezeError = FreezeError {
    code: 922,
    reason: "msphf_seedctx_mismatch",
};

pub const FREEZE_STARK_OVERSIZE: FreezeError = FreezeError {
    code: 923,
    reason: "msphf_hp_binding_invalid",
};

pub const FREEZE_RHO_PARITY: FreezeError = FreezeError {
    code: 924,
    reason: "msphf_rho_parity",
};

pub const FREEZE_MSPHF_RHO_PARITY: FreezeError = FreezeError {
    code: 924,
    reason: "msphf_rho_parity",
};

pub const FREEZE_MH_HEADS_INVALID: FreezeError = FreezeError {
    code: 927,
    reason: "mh_heads_invalid",
};

pub const FREEZE_EPOCHID_MISMATCH: FreezeError = FreezeError {
    code: 928,
    reason: "epochid_mismatch",
};

pub const FREEZE_HASH_CBOR: FreezeError = FreezeError {
    code: 9071,
    reason: "cbor_malformed",
};

pub const FREEZE_HASH_NONCANONICAL: FreezeError = FreezeError {
    code: 9072,
    reason: "nonmem_noncanonical",
};

pub const FREEZE_HASH_LEAF_BIND: FreezeError = FreezeError {
    code: 9073,
    reason: "leaf_bind_mismatch",
};

pub const FREEZE_HASH_PROJ_FAIL: FreezeError = FreezeError {
    code: 9074,
    reason: "proj_eval_fail",
};

pub const FREEZE_HASH_PATH_OVERSIZE: FreezeError = FreezeError {
    code: 9075,
    reason: "path_oversize",
};

pub const FREEZE_HASH_MEM_MALFORMED: FreezeError = FreezeError {
    code: 90721,
    reason: "mem_malformed",
};

pub const FREEZE_FIELD_MISSING: FreezeError = FreezeError {
    code: 9071,
    reason: "cbor_malformed",
};

pub const FREEZE_TSWE_ALG_INVALID: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_MERKLE_SUITE_INVALID: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_KBROAD_ALG_INVALID: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_KBROAD_PARENT_MISMATCH: FreezeError = FreezeError {
    code: 921,
    reason: "kbroad_parent_mismatch",
};

pub const FREEZE_PARENT_EID_FORBIDDEN: FreezeError = FreezeError {
    code: 921,
    reason: "parent_eid_forbidden",
};

pub const FREEZE_MSPHF_CRS_INVALID: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_MERGE_JOIN_KEYS: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_PARAMS_ID_INVALID: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE: FreezeError = FreezeError {
    code: 9480,
    reason: "fs_policy_window_incompatible",
};

pub const FREEZE_FS_JOIN_MISSING: FreezeError = FreezeError {
    code: 9441,
    reason: "fs_join_missing",
};

pub const FREEZE_FS_BASE_MISMATCH: FreezeError = FreezeError {
    code: 9450,
    reason: "fs_base_mismatch",
};

pub const FREEZE_FS_DEV_CHAIN_BREAK: FreezeError = FreezeError {
    code: 9470,
    reason: "fs_dev_chain_break",
};

pub const FREEZE_FS_DEV_CHAIN_BIND_MISMATCH: FreezeError = FreezeError {
    code: 9472,
    reason: "fs_dev_chain_bind_mismatch",
};

pub const FREEZE_FS_POLICY_VERSION_UNSUPPORTED: FreezeError = FreezeError {
    code: 9446,
    reason: "fs_policy_version_unsupported",
};

pub const FREEZE_FS_FORWARD_JUMP_DEVICE: FreezeError = FreezeError {
    code: 9474,
    reason: "fs_forward_jump_device",
};

pub const FREEZE_FS_FORWARD_JUMP_FIRST: FreezeError = FreezeError {
    code: 9475,
    reason: "fs_forward_jump_first",
};

pub const FREEZE_FS_FORWARD_JUMP_GROUP: FreezeError = FreezeError {
    code: 9476,
    reason: "fs_forward_jump_group",
};

pub const FREEZE_FS_CHECKPOINT_BACKDATE: FreezeError = FreezeError {
    code: 9471,
    reason: "fs_checkpoint_backdate",
};

pub const FREEZE_FS_CHECKPOINT_MONOTONICITY: FreezeError = FreezeError {
    code: 9473,
    reason: "fs_checkpoint_monotonicity",
};

pub const FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE: FreezeError = FreezeError {
    code: 9603,
    reason: "barrier_expectedpairs_failure",
};

pub const FREEZE_BARRIER_UPDATER_INVALID: FreezeError = FreezeError {
    code: 9601,
    reason: "barrier_updater_invalid",
};

pub const FREEZE_BARRIER_MERGE_DELEGATION_FORBIDDEN: FreezeError = FreezeError {
    code: 9604,
    reason: "barrier_merge_delegation_forbidden",
};

pub const FREEZE_BARRIER_PROACTIVE_FORBIDDEN: FreezeError = FreezeError {
    code: 9605,
    reason: "barrier_proactive_forbidden",
};

pub const FREEZE_BARRIER_UPDATE_MALFORMED: FreezeError = FreezeError {
    code: 9607,
    reason: "barrier_update_malformed",
};

#[allow(dead_code)]
pub const FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE: FreezeError = FreezeError {
    code: 9608,
    reason: "barrier_tree_hash_chain_failure",
};

pub const FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE: FreezeError = FreezeError {
    code: 9609,
    reason: "barrier_tree_snapshot_auth_failure",
};

pub const FREEZE_BARRIER_GENESIS_REQUIRED: FreezeError = FreezeError {
    code: 96010,
    reason: "barrier_genesis_required",
};

pub const FREEZE_BARRIER_UPDATE_REQUIRED_ON_REVOCATION_CHANGE: FreezeError = FreezeError {
    code: 96011,
    reason: "barrier_update_required_on_revocation_change",
};

pub const FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED: FreezeError = FreezeError {
    code: 96012,
    reason: "pcs_refresh_rate_limited",
};

pub const FREEZE_BARRIER_PCS_REFRESH_FORBIDDEN_WHILE_PENDING_REVOCATIONS: FreezeError =
    FreezeError {
        code: 96013,
        reason: "pcs_refresh_forbidden_while_pending_revocations",
    };
