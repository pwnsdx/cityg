//! Representation of the public instance `X_k` and helpers to encode/hash it.

use serde::Serialize;

use crate::{MsphfError, ds::MSPHF_TSWE_SALT, hash, serde_utils::to_cbor_vec};

/// Lightweight view over the anchor instance fields.
#[derive(Debug, Clone)]
pub struct AnchorInstance<'a> {
    pub gid: &'a [u8],
    pub cat: &'a [u8],
    pub we_epoch_id: [u8; 32],
    pub anchor_hdr_ctx: &'a [u8],
    pub tswe_salt_hash: &'a [u8],
    pub parent_root: &'a [u8],
    pub join_delta_root: &'a [u8],
    pub revoked_since_prev_root: &'a [u8],
    pub revoked_root: &'a [u8],
    pub pox_r_commit: Option<&'a [u8]>,
    pub msphf_hp_commit: Option<&'a [u8]>,
}

#[derive(Serialize)]
struct AnchorArray<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] Option<&'a [u8]>,
);

impl<'a> AnchorInstance<'a> {
    fn as_cbor_tuple(&self) -> AnchorArray<'_> {
        AnchorArray(
            self.gid,
            self.cat,
            &self.we_epoch_id,
            self.anchor_hdr_ctx,
            self.tswe_salt_hash,
            self.parent_root,
            self.join_delta_root,
            self.revoked_since_prev_root,
            self.revoked_root,
            self.pox_r_commit,
        )
    }

    /// Serialize `X_k` to deterministically encoded CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, MsphfError> {
        to_cbor_vec(&self.as_cbor_tuple())
    }

    /// Compute `xk_hash := H_L("msphf/xk", [ CBOR_det(X_k) ])`.
    pub fn xk_hash(&self) -> Result<[u8; 32], MsphfError> {
        hash::h_l(crate::ds::MSPHF_XK, &self.as_cbor_tuple())
    }
}

/// Helper to compute the epoch hash `H_epoch(X_k, Y)` once the digest is known.
pub fn epoch_key(instance: &AnchorInstance<'_>, y_star: &[u8]) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Y<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    hash::h_epoch(&instance.as_cbor_tuple(), &Y(y_star))
}

/// Compute `tswe_salt_hash := H_L("tswe/salt", [ gid, parent_root ])`.
pub fn tswe_salt_hash(gid: &[u8], parent_root: &[u8]) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Salt<'a> {
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8],
    }

    hash::h_l(MSPHF_TSWE_SALT, &Salt { gid, parent_root })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ds, hash};

    #[test]
    fn xk_hash_matches_manual_cbor() {
        let hdr_ctx = b"ctx";
        let inst = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x07; 32],
            anchor_hdr_ctx: hdr_ctx,
            tswe_salt_hash: b"salt",
            parent_root: &[0xAA; 32],
            join_delta_root: &[0xBB; 32],
            revoked_since_prev_root: &[0xCC; 32],
            revoked_root: &[0xDD; 32],
            pox_r_commit: None,
            msphf_hp_commit: None,
        };
        let hash_via_instance = match inst.xk_hash() {
            Ok(hash) => hash,
            Err(_) => unreachable!("instance hash should not fail in test"),
        };
        let manual = match hash::h_l(
            ds::MSPHF_XK,
            &super::AnchorArray(
                inst.gid,
                inst.cat,
                &inst.we_epoch_id,
                inst.anchor_hdr_ctx,
                inst.tswe_salt_hash,
                inst.parent_root,
                inst.join_delta_root,
                inst.revoked_since_prev_root,
                inst.revoked_root,
                inst.pox_r_commit,
            ),
        ) {
            Ok(hash) => hash,
            Err(_) => unreachable!("manual hash should not fail in test"),
        };
        assert_eq!(hash_via_instance, manual);
    }
}
