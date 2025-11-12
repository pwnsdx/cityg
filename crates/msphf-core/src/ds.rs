//! Domain-separation labels for the tswe/msphf-we/fs-hybrid profile.

/// BLAKE3 derive-key label for the branch-bound hash digest (shared by full/projective).
pub const MSPHF_HASH: &str = "msphf/hash";
/// BLAKE3 derive-key label for the canonical epoch target Y*.
pub const MSPHF_YSTAR: &str = "msphf/ystar";
/// BLAKE3 derive-key label for the mask associated to a branch.
pub const MSPHF_MASK: &str = "msphf/mask";
/// BLAKE3 derive-key label for the hp_k commit binding.
pub const MSPHF_HP_COMMIT: &str = "msphf/hp/commit";
/// BLAKE3 derive-key label for the seed-context hash (header key #91).
pub const MSPHF_SEED_CTX: &str = "seedctx";
/// BLAKE3 derive-key label for the seed-commit value fed into KGen.
pub const MSPHF_KGEN_SEED: &str = "msphf/kgen/seed";
/// BLAKE3 derive-key label for the joiner private seed commitment (key 93).
pub const MSPHF_KGEN_RHO: &str = "msphf/kgen/rho";
/// BLAKE3 derive-key label for deriving the private seed material ρ from the PoP.
pub const MSPHF_RHO_DER: &str = "msphf/rho/der";
/// BLAKE3 derive-key label for the branch-A sub-seed used in KGen.
pub const MSPHF_KGEN_A: &str = "msphf/kgen/A";
/// BLAKE3 derive-key label for the branch-B sub-seed used in KGen.
pub const MSPHF_KGEN_B: &str = "msphf/kgen/B";
/// BLAKE3 derive-key label for the deterministic DRBG used in KGen.
pub const MSPHF_DRBG: &str = "msphf/drbg";
/// BLAKE3 derive-key label for the epoch identifier (we_epoch_id).
pub const MSPHF_SLOT_ID: &str = "weid";
/// BLAKE3 derive-key label for the deterministic encoding of the public instance X_k.
pub const MSPHF_XK: &str = "msphf/xk";
/// BLAKE3 derive-key label for the epoch identifier derived from E_k.
pub const MSPHF_EID: &str = "we/eid";
/// BLAKE3 derive-key label for the leaf binding hash (device public key).
pub const MSPHF_LEAF_ID: &str = "leaf-id";
/// BLAKE3 derive-key label for the PoP message authentication binding.
pub const MSPHF_POP_MSG: &str = "msphf/pop/msg";
/// BLAKE3 derive-key label for the TSWE salt binding.
pub const MSPHF_TSWE_SALT: &str = "tswe/salt";
/// BLAKE3 derive-key label for the SRX/v1 commitment binding.
pub const MSPHF_SRX_COMMIT: &str = "srx/commit";
/// BLAKE3 derive-key label for parameter pack commitments.
pub const MSPHF_PARAMS: &str = "msphf/params";
/// BLAKE3 derive-key label for epoch hash function.
pub const MSPHF_EPOCH: &str = "msphf/epoch";

/// BLAKE3 derive-key label for hashing anchor metadata that is shared
/// between STARK gadgets (e.g., Eval vectors) and device-side code.
pub const MSPHF_SHARED_META: &str = "msphf/meta";

/// BLAKE3 derive-key label for canonical witness commitments.
pub const MSPHF_WITNESS_COMMIT: &str = "msphf/witness/commit";

/// RPO-256 leaf tag.
pub const DS_MT_LEAF: &str = "rpo-256/leaf";
/// RPO-256 node tag.
pub const DS_MT_NODE: &str = "rpo-256/node";
/// RPO-256 non-membership interval node tag.
pub const DS_NONMEM_INTNODE: &str = "rpo-256/nonmem";
