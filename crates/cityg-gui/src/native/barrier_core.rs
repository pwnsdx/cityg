use super::*;
#[allow(unused_imports)]
pub(super) use cityg_client::barrier_build::{BarrierWrapAadPreimage, BarrierWrapNoncePreimage};
#[allow(unused_imports)]
pub(super) use cityg_client::barrier_crypto::{
    ML_KEM_EXPANDED_DK_BYTES, decapsulate_internal_node_shared_secret,
    derive_internal_node_key_material, derive_k_fs_after_pcs,
};
#[allow(unused_imports)]
pub(super) use cityg_client::barrier_update::{
    BarrierUpdateWire, KemTreeCoverPayloadWire, NewPublicKeyWire, NodeCiphertextWire,
    ParsedBarrierUpdate, ParsedNodeCiphertext, compute_barrier_update_digest,
    normalize_max_barrier_update_bytes, parse_barrier_update_for_recover,
};

pub(super) const BARRIER_CODE_RECOVER_NO_MATCH: u32 = 9606;
pub(super) const BARRIER_CODE_SNAPSHOT_AUTH_FAILURE: u32 = 9609;

#[derive(Clone, Debug)]
pub(super) struct BarrierRecoverResult {
    pub(super) barrier_version: u64,
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    pub(super) derived_node_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone, Debug)]
pub(super) struct BarrierUpdateBuildResult {
    pub(super) raw_update: Vec<u8>,
    pub(super) barrier_update_digest: [u8; 32],
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pub(super) snapshot_post: Arc<BarrierPublicTree>,
}
