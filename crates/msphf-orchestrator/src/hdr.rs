//! Header key definitions (single source of truth for CBOR map indices).
pub const HDR_TSWE_ALG: u64 = 90;
pub const HDR_SEED_CTX_HASH: u64 = 91;
pub const HDR_MERKLE_SUITE: u64 = 92;
pub const HDR_RHO_COMMIT: u64 = 93;
pub const HDR_SEED_BUNDLE_COMMIT: u64 = 94;
pub const HDR_VRF_PROOF: u64 = 95;
pub const HDR_HP_BYTES: u64 = 97;
pub const HDR_CRS_ID: u64 = 98;
pub const HDR_HP_COMMIT: u64 = 99;
pub const HDR_KBROAD_ALG: u64 = 104;
pub const HDR_KBROAD_PUB: u64 = 105;
pub const HDR_PARAMS_ID: u64 = 106;
pub const HDR_POP_ALG: u64 = 107;
pub const HDR_POP_PK: u64 = 108;
pub const HDR_POP_SIG: u64 = 109;
pub const HDR_PARENT_ROOT: u64 = 110;
pub const HDR_JOIN_DELTA_ROOT: u64 = 111;
pub const HDR_VRF_ID: u64 = 116;
pub const HDR_PROOF_MODE: u64 = 119;
pub const HDR_SRX_MODE: u64 = 120;
pub const HDR_SRX_COMMIT: u64 = 121;
pub const HDR_SRX_PAYLOAD: u64 = 122;
pub const HDR_SRX_HINT_COUNTS: u64 = 123;
pub const HDR_SRX_HINT_SIZES: u64 = 124;
pub const HDR_PROOFS_COMMIT: u64 = 125;
pub const HDR_SRX_ROOT_SW: u64 = 160;
pub const HDR_SRX_SMALLWOOD: u64 = 161;
pub const HDR_MH_HEADS: u64 = 130;
pub const HDR_ROLLUP_PIVOT_WEID: u64 = 131;
pub const HDR_ROLLUP_PROVENANCE_COMMIT: u64 = 132;
pub const HDR_ROLLUP_EPOCH_REPLAY: u64 = 133;
pub const HDR_ROLLUP_VCK_COMMIT: u64 = 134;
pub const HDR_MERGE_DELEGATION_SIG: u64 = 135;
pub const HDR_KBROAD_REPLAY: u64 = 136;
pub const HDR_ROLLUP_FS_MODE: u64 = 138;
pub const HDR_BOOTSTRAP_ALG: u64 = 170;
pub const HDR_BOOTSTRAP_SIG: u64 = 171;
pub const HDR_BOOTSTRAP_PK: u64 = 172;
pub const HDR_BARRIER_UPDATE: u64 = 175;
pub const HDR_BARRIER_VERSION: u64 = 176;
pub const HDR_BARRIER_LEAF_PK: u64 = 177;
pub const HDR_BARRIER_UPDATE_REASON: u64 = 178;
pub const HDR_JOIN_FINALIZE_AUTH: u64 = 179;
pub const HDR_BARRIER_HISTORY_COMMITMENT: u64 = 180;
pub const HDR_BARRIER_FULL_VERIFICATION_RECEIPT: u64 = 181;
pub const HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION: u64 = 182;
pub const HDR_POLICY_VERSION: u64 = 140; // legacy policy version field (pre-FS profiles)
pub const HDR_FS_POLICY_VERSION: u64 = 139;
pub const HDR_FS_EC: u64 = 141;
pub const HDR_FS_EPOCH_COMMIT: u64 = 142;
pub const HDR_FS_EPOCH_BASE_TS: u64 = 143;
pub const HDR_FS_EVOLUTION_BOUNDARY: u64 = 144;
pub const HDR_FS_PURGE_TIMES: u64 = 145;
pub const HDR_FS_CAPSS: u64 = 146;
pub const HDR_FS_DEV_PREV_COMMIT: u64 = 152;
pub const HDR_FS_DEV_COMMIT: u64 = 153;
pub const HDR_VRF_MASK_A: u64 = 154;
pub const HDR_VRF_MASK_B: u64 = 155;
pub const HDR_VRF_PUBLIC_KEY: u64 = 156;
pub const HDR_FS_CHECKPOINT_EC: u64 = 148;
pub const HDR_REVOKED_SINCE_ROOT: u64 = 112;
pub const HDR_REVOKED_ROOT: u64 = 113;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn header_tag_values_are_unique() {
        let tags = [
            HDR_TSWE_ALG,
            HDR_SEED_CTX_HASH,
            HDR_MERKLE_SUITE,
            HDR_RHO_COMMIT,
            HDR_SEED_BUNDLE_COMMIT,
            HDR_VRF_PROOF,
            HDR_HP_BYTES,
            HDR_CRS_ID,
            HDR_HP_COMMIT,
            HDR_KBROAD_ALG,
            HDR_KBROAD_PUB,
            HDR_PARAMS_ID,
            HDR_POP_ALG,
            HDR_POP_PK,
            HDR_POP_SIG,
            HDR_PARENT_ROOT,
            HDR_JOIN_DELTA_ROOT,
            HDR_VRF_ID,
            HDR_PROOF_MODE,
            HDR_SRX_MODE,
            HDR_SRX_COMMIT,
            HDR_SRX_PAYLOAD,
            HDR_SRX_HINT_COUNTS,
            HDR_SRX_HINT_SIZES,
            HDR_PROOFS_COMMIT,
            HDR_SRX_ROOT_SW,
            HDR_SRX_SMALLWOOD,
            HDR_MH_HEADS,
            HDR_ROLLUP_PIVOT_WEID,
            HDR_ROLLUP_PROVENANCE_COMMIT,
            HDR_ROLLUP_EPOCH_REPLAY,
            HDR_ROLLUP_VCK_COMMIT,
            HDR_MERGE_DELEGATION_SIG,
            HDR_KBROAD_REPLAY,
            HDR_ROLLUP_FS_MODE,
            HDR_BOOTSTRAP_ALG,
            HDR_BOOTSTRAP_SIG,
            HDR_BOOTSTRAP_PK,
            HDR_BARRIER_UPDATE,
            HDR_BARRIER_VERSION,
            HDR_BARRIER_LEAF_PK,
            HDR_BARRIER_UPDATE_REASON,
            HDR_JOIN_FINALIZE_AUTH,
            HDR_BARRIER_HISTORY_COMMITMENT,
            HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
            HDR_POLICY_VERSION,
            HDR_FS_POLICY_VERSION,
            HDR_FS_EC,
            HDR_FS_EPOCH_COMMIT,
            HDR_FS_EPOCH_BASE_TS,
            HDR_FS_EVOLUTION_BOUNDARY,
            HDR_FS_PURGE_TIMES,
            HDR_FS_CAPSS,
            HDR_FS_DEV_PREV_COMMIT,
            HDR_FS_DEV_COMMIT,
            HDR_VRF_MASK_A,
            HDR_VRF_MASK_B,
            HDR_VRF_PUBLIC_KEY,
            HDR_FS_CHECKPOINT_EC,
            HDR_REVOKED_SINCE_ROOT,
            HDR_REVOKED_ROOT,
        ];

        let unique: HashSet<u64> = tags.into_iter().collect();
        assert_eq!(unique.len(), tags.len());
    }
}
