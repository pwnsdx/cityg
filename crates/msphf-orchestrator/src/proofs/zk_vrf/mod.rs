//! Zero-knowledge VRF plumbing backed by the lattice-based LB-VRF implementation.

#[cfg(not(feature = "zkvrf-pq"))]
compile_error!("The `zkvrf-pq` feature must be enabled; the stub implementation has been removed.");

pub mod lb;

pub use lb as zk_vrf_impl;

/// Compact representation of a VRF proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof {
    pub bytes: Vec<u8>,
}

/// 32-byte digest used to bind branch-side masks in the ZK proof.
pub type MaskDigest = [u8; 32];

/// Challenge context bound into the VRF proof.
/// This structure represents the complete bind_fs context as specified in Section 11
/// of the unified specification.
#[derive(Clone, Copy)]
pub struct VrfCtx<'a> {
    pub xk_hash: &'a [u8; 32],             // H_L("msphf/xk", [CBOR_det(X_k)])
    pub rho_commit: &'a [u8; 32],          // 93
    pub seed_bundle_commit: &'a [u8; 32],  // 94
    pub crs_id: &'a str,                   // 98
    pub hp_commit: &'a [u8; 32],           // 99
    pub params_id: &'a str,                // 106
    pub parent_root: &'a [u8],             // 110
    pub join_delta_root: &'a [u8],         // 111
    pub revoked_since_prev_root: &'a [u8], // 112
    pub revoked_root: &'a [u8],            // 113
    pub proof_mode: &'a str,               // proof_mode
    pub fs_policy_version: &'a str,        // fs_policy_version (139)
    pub meor_vrf_id: &'a str,              // 116
    pub fs_epoch_commit: &'a [u8; 32],     // 141
    pub fs_ec: u64,                        // 140
    pub fs_dev_prev_commit: &'a [u8; 32],  // 152
    pub fs_dev_commit: &'a [u8; 32],       // 153
    pub srx_root_sw: Option<&'a [u8; 32]>, // 160 (when SRX applies)
    pub we_epoch_id: &'a [u8; 32],         // Derived from gid, parent_root, seed_ctx_hash
}
