use msphf_orchestrator::{
    AnchorInstanceParts, FsJoinInputs, FsMergeInputs, LeafIdMode, OrchestrationParams, PopKeypair,
    SrxInputs, SrxMode,
};
use pqcrypto_dilithium::dilithium5;

pub struct BarrierOrchestrationInputs<'a> {
    pub gid: &'a [u8; 32],
    pub cat: &'a [u8; 32],
    pub tswe_salt_hash: &'a [u8; 32],
    pub parent_root: &'a [u8; 32],
    pub join_delta_root: &'a [u8; 32],
    pub revoked_since_root: &'a [u8; 32],
    pub revoked_root: &'a [u8; 32],
    pub pox_r_commit: &'a [u8; 32],
    pub msphf_crs_id: &'a str,
    pub msphf_params_id: &'a str,
    pub srx: Option<SrxInputs<'a>>,
    pub pop_public_key: &'a [u8],
    pub pop_secret_key: &'a dilithium5::SecretKey,
    pub proof_mode: &'a str,
    pub vrf_id: &'a str,
    pub policy_version: &'a str,
    pub vrf_secret_key: &'a [u8],
    pub vrf_public_key: &'a [u8],
    pub fs_policy_version: &'a str,
    pub fs_epoch_base_ts: u64,
    pub barrier_version: u64,
    pub fs_join: FsJoinInputs,
}

pub struct PreparedBarrierOrchestration<'a> {
    pub params: OrchestrationParams<'a>,
    pub parts: AnchorInstanceParts<'a>,
}

pub fn prepare_barrier_orchestration(
    inputs: BarrierOrchestrationInputs<'_>,
) -> PreparedBarrierOrchestration<'_> {
    let BarrierOrchestrationInputs {
        gid,
        cat,
        tswe_salt_hash,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        pox_r_commit,
        msphf_crs_id,
        msphf_params_id,
        srx,
        pop_public_key,
        pop_secret_key,
        proof_mode,
        vrf_id,
        policy_version,
        vrf_secret_key,
        vrf_public_key,
        fs_policy_version,
        fs_epoch_base_ts,
        barrier_version,
        fs_join,
    } = inputs;

    let params = OrchestrationParams {
        msphf_crs_id,
        params_id: msphf_params_id,
        srx,
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key,
            secret_key: pop_secret_key,
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode,
        vrf_id,
        policy_version,
        vrf_secret_key: Some(vrf_secret_key),
        vrf_public_key: Some(vrf_public_key),
        fs_policy_version,
        fs_epoch_base_ts,
        barrier_version,
        fs_join,
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid,
        cat: cat.as_slice(),
        tswe_salt_hash: tswe_salt_hash.as_slice(),
        parent_root: parent_root.as_slice(),
        join_delta_root: join_delta_root.as_slice(),
        revoked_since_prev_root: revoked_since_root.as_slice(),
        revoked_root: revoked_root.as_slice(),
        pox_r_commit: Some(pox_r_commit.as_slice()),
    };

    PreparedBarrierOrchestration { params, parts }
}
