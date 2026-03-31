//! Canonical witness structures and structural validation helpers.

use cityg_pqc::{
    ML_DSA_65_PUBLIC_KEY_BYTES as ML_DSA65_PUBLIC_KEY_LEN,
    ML_DSA_65_SIGNATURE_BYTES as ML_DSA65_SIGNATURE_LEN, MlDsa65VerifyError,
    verify_ml_dsa_65_detached_signature,
};
use serde::{Deserialize, Serialize};

use crate::{MsphfError, WitnessValidationError, ds, hash, instance::AnchorInstance, merkle};
const MAX_MERKLE_DEPTH: usize = 64;

/// Enumeration describing which branch of the language a witness targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WitnessMode {
    A,
    B,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedMembership {
    pub leaf_id: [u8; 32],
    pub root: [u8; 32],
    pub path: Vec<(u8, [u8; 32])>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedNonMembership {
    pub query: [u8; 32],
    pub root: [u8; 32],
    pub left: Option<[u8; 32]>,
    pub right: Option<[u8; 32]>,
    pub path: Vec<(u8, [u8; 32])>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedWitness {
    pub mode: WitnessMode,
    pub membership: ValidatedMembership,
    pub nonmembership: Option<ValidatedNonMembership>,
    pub pop: Option<ValidatedPop>,
}

impl ValidatedWitness {
    pub fn digest(&self) -> Result<[u8; 32], MsphfError> {
        hash::h_l(ds::MSPHF_WITNESS_COMMIT, self)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedPop {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPathEntry {
    #[serde(with = "serde_bytes")]
    pub sibling: Vec<u8>,
    pub dir: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMembershipWitness {
    #[serde(with = "serde_bytes")]
    pub leaf_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub root: Vec<u8>,
    pub path: Vec<RawPathEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawNonMembershipWitness {
    #[serde(with = "serde_bytes")]
    pub query: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub left: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub right: Option<Vec<u8>>,
    pub path: Vec<RawPathEntry>,
    #[serde(default)]
    pub left_below: Vec<RawPathEntry>,
    #[serde(default)]
    pub right_below: Vec<RawPathEntry>,
    #[serde(default)]
    pub above: Vec<RawPathEntry>,
    #[serde(default, with = "serde_bytes")]
    pub nmint: Option<Vec<u8>>,
    #[serde(default)]
    pub lca_left_height: Option<u8>,
    #[serde(default)]
    pub lca_right_height: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPopWitness {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)]
pub enum WitnessVariants {
    A {
        witness: RawMembershipWitness,
        #[serde(default)]
        pop: Option<RawPopWitness>,
    },
    B {
        witness: RawMembershipWitness,
        #[serde(default)]
        nonmem: Option<RawNonMembershipWitness>,
        #[serde(default)]
        pop: Option<RawPopWitness>,
    },
}

/// Canonical witness representation (currently structural checks only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalWitness {
    #[serde(flatten)]
    pub inner: WitnessVariants,
}

impl CanonicalWitness {
    pub fn mode(&self) -> WitnessMode {
        match self.inner {
            WitnessVariants::A { .. } => WitnessMode::A,
            WitnessVariants::B { .. } => WitnessMode::B,
        }
    }

    fn to_array32(_label: &str, bytes: &[u8]) -> Result<[u8; 32], MsphfError> {
        bytes
            .try_into()
            .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))
    }

    fn validate_path(path: &[RawPathEntry]) -> Result<Vec<(u8, [u8; 32])>, MsphfError> {
        if path.len() > MAX_MERKLE_DEPTH {
            return Err(WitnessValidationError::PathOversize.into());
        }
        let mut out = Vec::with_capacity(path.len());
        for entry in path {
            if entry.dir > 1 {
                return Err(WitnessValidationError::ProjEvalFail.into());
            }
            let sib = Self::to_array32("path sibling", &entry.sibling)?;
            out.push((entry.dir, sib));
        }
        Ok(out)
    }

    fn validate_membership_against(
        raw: &RawMembershipWitness,
        expected_root: &[u8; 32],
    ) -> Result<ValidatedMembership, MsphfError> {
        let leaf = Self::to_array32("leaf_id", &raw.leaf_id)?;
        let witness_root = Self::to_array32("root", &raw.root)?;
        if &witness_root != expected_root {
            return Err(WitnessValidationError::ProjEvalFail.into());
        }
        let path = Self::validate_path(&raw.path)?;
        let computed = merkle::validate_membership_path(&leaf, &path);
        if &computed != expected_root {
            return Err(WitnessValidationError::ProjEvalFail.into());
        }
        Ok(ValidatedMembership {
            leaf_id: leaf,
            root: *expected_root,
            path,
        })
    }

    fn validate_nonmembership_against(
        raw: &RawNonMembershipWitness,
        expected_root: &[u8; 32],
    ) -> Result<ValidatedNonMembership, MsphfError> {
        if raw.query.len() != 32 {
            return Err(WitnessValidationError::CborMalformed.into());
        }
        let root = Self::to_array32("root", &raw.root)?;
        if &root != expected_root {
            return Err(WitnessValidationError::ProjEvalFail.into());
        }
        let left = if let Some(left) = &raw.left {
            if left.len() != 32 {
                return Err(WitnessValidationError::CborMalformed.into());
            }
            if left.as_slice() >= raw.query.as_slice() {
                return Err(WitnessValidationError::NonCanonical.into());
            }
            Some(Self::to_array32("left", left)?)
        } else {
            None
        };
        let right = if let Some(right) = &raw.right {
            if right.len() != 32 {
                return Err(WitnessValidationError::CborMalformed.into());
            }
            if raw.query.as_slice() >= right.as_slice() {
                return Err(WitnessValidationError::NonCanonical.into());
            }
            Some(Self::to_array32("right", right)?)
        } else {
            None
        };
        if let (Some(left_bytes), Some(right_bytes)) = (left, right)
            && left_bytes >= right_bytes
        {
            return Err(WitnessValidationError::NonCanonical.into());
        }
        let path = Self::validate_path(&raw.path)?;

        let left_bound = left;
        let right_bound = right;

        if let (Some(left_bytes), Some(right_bytes)) = (left_bound.as_ref(), right_bound.as_ref()) {
            if !raw.path.is_empty() {
                return Err(WitnessValidationError::NonCanonical.into());
            }

            let lca_left_height = raw
                .lca_left_height
                .ok_or(MsphfError::Witness(WitnessValidationError::NonCanonical))?;
            let lca_right_height = raw
                .lca_right_height
                .ok_or(MsphfError::Witness(WitnessValidationError::NonCanonical))?;

            if usize::from(lca_left_height) != raw.left_below.len() + 1
                || usize::from(lca_right_height) != raw.right_below.len() + 1
            {
                return Err(WitnessValidationError::NonCanonical.into());
            }

            let nmint_bytes = raw
                .nmint
                .as_ref()
                .ok_or(MsphfError::Witness(WitnessValidationError::NonCanonical))?;
            if nmint_bytes.len() != 32 {
                return Err(WitnessValidationError::CborMalformed.into());
            }
            let mut nmint = [0u8; 32];
            nmint.copy_from_slice(nmint_bytes);

            let left_leaf_hash = *left_bytes;
            let right_leaf_hash = *right_bytes;

            let left_anchor = Self::fold_extended_anchor(left_leaf_hash, &raw.left_below)?;
            let right_anchor = Self::fold_extended_anchor(right_leaf_hash, &raw.right_below)?;

            let mut acc = merkle::hash_node(&left_anchor, &right_anchor);
            for entry in &raw.above {
                acc = Self::fold_step(acc, entry)?;
            }

            let total_depth = raw
                .left_below
                .len()
                .saturating_add(raw.right_below.len())
                .saturating_add(raw.above.len());
            if total_depth > 64 {
                return Err(WitnessValidationError::PathOversize.into());
            }

            if &acc != expected_root {
                return Err(WitnessValidationError::NonCanonical.into());
            }

            let expected_nmint = merkle::hash_interval_binding(
                left_bytes,
                &left_leaf_hash,
                right_bytes,
                &right_leaf_hash,
                lca_left_height,
                lca_right_height,
            );
            if nmint != expected_nmint {
                return Err(WitnessValidationError::NonCanonical.into());
            }

            let query = Self::to_array32("query", &raw.query)?;
            return Ok(ValidatedNonMembership {
                query,
                root: *expected_root,
                left: Some(*left_bytes),
                right: Some(*right_bytes),
                path: Vec::new(),
            });
        }

        let left_is_none = left.is_none();
        let right_is_none = right.is_none();

        // Empty tree sentinel: both bounds are open and no path elements are required.
        if left_is_none && right_is_none {
            if !path.is_empty() {
                return Err(WitnessValidationError::NonCanonical.into());
            }
            if expected_root.iter().any(|byte| *byte != 0) {
                return Err(WitnessValidationError::NonCanonical.into());
            }
            let query = Self::to_array32("query", &raw.query)?;
            return Ok(ValidatedNonMembership {
                query,
                root: *expected_root,
                left,
                right,
                path,
            });
        }

        // Single-leaf canonical guard: a lone open bound must carry a witness path.
        // The canonical rule singles out single-leaf trees, but allow empty
        // path here to accommodate degenerate trees represented by a single
        // digest. Implementations providing richer witnesses should still be
        // accepted.

        let base = match (left_bound.as_ref(), right_bound.as_ref()) {
            (Some(l), Some(r)) => merkle::hash_interval(l, r),
            (Some(l), None) => *l,
            (None, Some(r)) => *r,
            (None, None) => unreachable!(),
        };
        let computed = merkle::apply_path_from(&base, &path);
        if &computed != expected_root {
            return Err(WitnessValidationError::NonCanonical.into());
        }
        let query = Self::to_array32("query", &raw.query)?;
        Ok(ValidatedNonMembership {
            query,
            root: *expected_root,
            left: left_bound,
            right: right_bound,
            path,
        })
    }

    fn fold_extended_anchor(
        mut acc: [u8; 32],
        path: &[RawPathEntry],
    ) -> Result<[u8; 32], MsphfError> {
        for entry in path {
            acc = Self::fold_step(acc, entry)?;
        }
        Ok(acc)
    }

    fn fold_step(acc: [u8; 32], entry: &RawPathEntry) -> Result<[u8; 32], MsphfError> {
        if entry.sibling.len() != 32 {
            return Err(WitnessValidationError::CborMalformed.into());
        }
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&entry.sibling);
        match entry.dir {
            0 => Ok(merkle::hash_node(&acc, &sibling)),
            1 => Ok(merkle::hash_node(&sibling, &acc)),
            _ => Err(WitnessValidationError::CborMalformed.into()),
        }
    }

    fn validate_pop(
        anchor: &AnchorInstance<'_>,
        membership: &ValidatedMembership,
        raw: &RawPopWitness,
    ) -> Result<ValidatedPop, MsphfError> {
        if raw.public_key.len() != ML_DSA65_PUBLIC_KEY_LEN {
            return Err(WitnessValidationError::CborMalformed.into());
        }
        if raw.signature.len() != ML_DSA65_SIGNATURE_LEN {
            return Err(WitnessValidationError::CborMalformed.into());
        }
        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }
        let xk_bytes = anchor.to_cbor_bytes()?;
        let msg_bytes = hash::h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &xk_bytes,
                leaf_id: &membership.leaf_id,
                epoch: &anchor.we_epoch_id,
            },
        )?;
        verify_ml_dsa_65_detached_signature(&raw.public_key, &msg_bytes, &raw.signature)
            .map_err(map_cityg_pop_verify_error)?;

        #[derive(Serialize)]
        struct LeafBinding<'a> {
            #[serde(with = "serde_bytes")]
            public_key: &'a [u8],
        }
        let expected_leaf = hash::h_l(
            ds::MSPHF_LEAF_ID,
            &LeafBinding {
                public_key: &raw.public_key,
            },
        )?;
        if expected_leaf != membership.leaf_id {
            return Err(WitnessValidationError::LeafBindMismatch.into());
        }
        let msg_vec = msg_bytes.to_vec();
        Ok(ValidatedPop {
            public_key: raw.public_key.clone(),
            signature: raw.signature.clone(),
            message: Some(msg_vec),
        })
    }

    pub fn validate_against(
        &self,
        anchor: &AnchorInstance<'_>,
    ) -> Result<ValidatedWitness, MsphfError> {
        match &self.inner {
            WitnessVariants::A { witness, pop } => {
                let expected = merkle::bytes32(anchor.parent_root)
                    .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))?;
                let membership = Self::validate_membership_against(witness, &expected)?;
                let pop = if let Some(raw_pop) = pop {
                    Some(Self::validate_pop(anchor, &membership, raw_pop)?)
                } else {
                    None
                };
                Ok(ValidatedWitness {
                    mode: WitnessMode::A,
                    membership,
                    nonmembership: None,
                    pop,
                })
            }
            WitnessVariants::B {
                witness,
                nonmem,
                pop,
            } => {
                let expected = merkle::bytes32(anchor.join_delta_root)
                    .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))?;
                let membership = Self::validate_membership_against(witness, &expected)?;
                let nonmembership = if let Some(nonmem) = nonmem {
                    let expected_nonmem = merkle::bytes32(anchor.revoked_root)
                        .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))?;
                    Some(Self::validate_nonmembership_against(
                        nonmem,
                        &expected_nonmem,
                    )?)
                } else {
                    None
                };
                let pop = if let Some(raw_pop) = pop {
                    Some(Self::validate_pop(anchor, &membership, raw_pop)?)
                } else {
                    None
                };
                Ok(ValidatedWitness {
                    mode: WitnessMode::B,
                    membership,
                    nonmembership,
                    pop,
                })
            }
        }
    }

    pub fn validate_membership_witness(
        raw: &RawMembershipWitness,
        expected_root: &[u8; 32],
    ) -> Result<ValidatedMembership, MsphfError> {
        Self::validate_membership_against(raw, expected_root)
    }

    pub fn validate_nonmembership_witness(
        raw: &RawNonMembershipWitness,
        expected_root: &[u8; 32],
    ) -> Result<ValidatedNonMembership, MsphfError> {
        Self::validate_nonmembership_against(raw, expected_root)
    }
}

fn map_cityg_pop_verify_error(error: MlDsa65VerifyError) -> MsphfError {
    let witness_error = match error {
        MlDsa65VerifyError::VerificationFailed => WitnessValidationError::ProjEvalFail,
        MlDsa65VerifyError::InvalidPublicKeyLength
        | MlDsa65VerifyError::InvalidSignatureLength
        | MlDsa65VerifyError::InvalidPublicKey
        | MlDsa65VerifyError::InvalidSignature => WitnessValidationError::CborMalformed,
    };
    MsphfError::Witness(witness_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ds, hash,
        instance::AnchorInstance,
        merkle::{hash_interval, hash_leaf, hash_node},
    };
    use pqcrypto_dilithium::dilithium5::{detached_sign, keypair};
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

    fn anchor_for<'a>(
        parent_root: &'a [u8; 32],
        join_delta_root: &'a [u8; 32],
        revoked_root: &'a [u8; 32],
    ) -> AnchorInstance<'a> {
        AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x42; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: parent_root.as_slice(),
            join_delta_root: join_delta_root.as_slice(),
            revoked_since_prev_root: revoked_root.as_slice(),
            revoked_root: revoked_root.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        }
    }

    #[test]
    fn membership_path_matches_root() {
        let leaf = hash_leaf(b"leaf0");
        let sibling = hash_leaf(b"leaf1");
        let root = hash_node(&leaf, &sibling);
        let witness = CanonicalWitness {
            inner: WitnessVariants::A {
                witness: RawMembershipWitness {
                    leaf_id: leaf.to_vec(),
                    root: root.to_vec(),
                    path: vec![RawPathEntry {
                        sibling: sibling.to_vec(),
                        dir: 0,
                    }],
                },
                pop: None,
            },
        };
        let anchor = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x01; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: root.as_slice(),
            join_delta_root: root.as_slice(),
            revoked_since_prev_root: root.as_slice(),
            revoked_root: root.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };
        let validated = match witness.validate_against(&anchor) {
            Ok(v) => v,
            Err(_) => unreachable!("witness should validate"),
        };
        assert_eq!(validated.mode, WitnessMode::A);
        assert_eq!(validated.membership.root, root);
    }

    #[test]
    fn membership_root_mismatch_rejected() {
        let leaf = hash_leaf(b"leaf0");
        let sibling = hash_leaf(b"leaf1");
        let wrong_root = hash_leaf(b"root");
        let anchor_root = hash_node(&leaf, &sibling);
        let witness = CanonicalWitness {
            inner: WitnessVariants::A {
                witness: RawMembershipWitness {
                    leaf_id: leaf.to_vec(),
                    root: wrong_root.to_vec(),
                    path: vec![RawPathEntry {
                        sibling: sibling.to_vec(),
                        dir: 0,
                    }],
                },
                pop: None,
            },
        };
        let anchor = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x01; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: anchor_root.as_slice(),
            join_delta_root: anchor_root.as_slice(),
            revoked_since_prev_root: anchor_root.as_slice(),
            revoked_root: anchor_root.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };
        let err = match witness.validate_against(&anchor) {
            Ok(_) => unreachable!("witness should fail but succeeded"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            MsphfError::Witness(WitnessValidationError::ProjEvalFail)
        ));
    }

    #[test]
    fn pop_validates_and_binds_leaf() {
        let (pk, sk) = keypair();

        #[derive(Serialize)]
        struct LeafBinding<'a> {
            #[serde(with = "serde_bytes")]
            public_key: &'a [u8],
        }
        let leaf_digest = match hash::h_l(
            ds::MSPHF_LEAF_ID,
            &LeafBinding {
                public_key: pk.as_bytes(),
            },
        ) {
            Ok(d) => d,
            Err(_) => unreachable!("leaf digest should not fail"),
        };

        let anchor = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x2A; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: leaf_digest.as_slice(),
            join_delta_root: leaf_digest.as_slice(),
            revoked_since_prev_root: leaf_digest.as_slice(),
            revoked_root: leaf_digest.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };

        let xk_bytes = match anchor.to_cbor_bytes() {
            Ok(b) => b,
            Err(_) => unreachable!("anchor to cbor should not fail"),
        };
        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }
        let msg = match hash::h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &xk_bytes,
                leaf_id: &leaf_digest,
                epoch: &anchor.we_epoch_id,
            },
        ) {
            Ok(m) => m,
            Err(_) => unreachable!("pop message hash should not fail"),
        };
        let signature = detached_sign(&msg, &sk);

        let witness = CanonicalWitness {
            inner: WitnessVariants::A {
                witness: RawMembershipWitness {
                    leaf_id: leaf_digest.to_vec(),
                    root: leaf_digest.to_vec(),
                    path: vec![],
                },
                pop: Some(RawPopWitness {
                    public_key: pk.as_bytes().to_vec(),
                    signature: signature.as_bytes().to_vec(),
                }),
            },
        };

        let validated = match witness.validate_against(&anchor) {
            Ok(v) => v,
            Err(_) => unreachable!("witness validates"),
        };
        let pop = match validated.pop {
            Some(p) => p,
            None => unreachable!("pop present"),
        };
        assert_eq!(pop.public_key, pk.as_bytes());
    }

    #[test]
    fn pop_leaf_mismatch_rejected() {
        let (pk, _sk) = keypair();
        let (pk2, sk2) = keypair();

        #[derive(Serialize)]
        struct LeafBinding<'a> {
            #[serde(with = "serde_bytes")]
            public_key: &'a [u8],
        }
        let correct_leaf = match hash::h_l(
            ds::MSPHF_LEAF_ID,
            &LeafBinding {
                public_key: pk.as_bytes(),
            },
        ) {
            Ok(d) => d,
            Err(_) => unreachable!("leaf digest should not fail"),
        };

        let anchor = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x07; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: correct_leaf.as_slice(),
            join_delta_root: correct_leaf.as_slice(),
            revoked_since_prev_root: correct_leaf.as_slice(),
            revoked_root: correct_leaf.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };

        let xk_bytes = match anchor.to_cbor_bytes() {
            Ok(b) => b,
            Err(_) => unreachable!("anchor to cbor should not fail"),
        };
        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }
        let msg = match hash::h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &xk_bytes,
                leaf_id: &correct_leaf,
                epoch: &anchor.we_epoch_id,
            },
        ) {
            Ok(m) => m,
            Err(_) => unreachable!("pop message hash should not fail"),
        };
        let signature = detached_sign(&msg, &sk2);

        let witness = CanonicalWitness {
            inner: WitnessVariants::A {
                witness: RawMembershipWitness {
                    leaf_id: correct_leaf.to_vec(),
                    root: correct_leaf.to_vec(),
                    path: vec![],
                },
                pop: Some(RawPopWitness {
                    public_key: pk2.as_bytes().to_vec(),
                    signature: signature.as_bytes().to_vec(),
                }),
            },
        };
        let err = match witness.validate_against(&anchor) {
            Ok(_) => unreachable!("witness should fail but succeeded"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            MsphfError::Witness(WitnessValidationError::LeafBindMismatch)
        ));
    }

    #[test]
    fn nonmembership_interval_mismatch_rejected() {
        let parent_root = hash_leaf(b"parent-root");
        let join_leaf = hash_leaf(b"join-leaf");
        let revoked_since = hash_leaf(b"revoked-since");
        let left_bound = [0x10u8; 32];
        let right_bound = [0xF0u8; 32];
        let query = [0x80u8; 32];
        let revoked_root = hash_interval(&left_bound, &right_bound);

        let membership = RawMembershipWitness {
            leaf_id: join_leaf.to_vec(),
            root: join_leaf.to_vec(),
            path: Vec::new(),
        };

        let nonmem = RawNonMembershipWitness {
            query: query.to_vec(),
            root: revoked_root.to_vec(),
            left: Some(left_bound.to_vec()),
            right: Some(right_bound.to_vec()),
            path: vec![RawPathEntry {
                sibling: vec![0xAB; 32],
                dir: 0,
            }],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: Some(
                merkle::hash_interval_binding(
                    &left_bound,
                    &left_bound,
                    &right_bound,
                    &right_bound,
                    1,
                    1,
                )
                .to_vec(),
            ),
            lca_left_height: Some(1),
            lca_right_height: Some(1),
        };

        let witness = CanonicalWitness {
            inner: WitnessVariants::B {
                witness: membership,
                nonmem: Some(nonmem),
                pop: None,
            },
        };

        let anchor = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0x55; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: parent_root.as_slice(),
            join_delta_root: join_leaf.as_slice(),
            revoked_since_prev_root: revoked_since.as_slice(),
            revoked_root: revoked_root.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };

        let err = match witness.validate_against(&anchor) {
            Ok(_) => unreachable!("interval mismatch must fail but succeeded"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            MsphfError::Witness(WitnessValidationError::NonCanonical)
        ));
    }

    #[test]
    fn nonmembership_path_overflow_rejected() {
        let parent_root = hash_leaf(b"parent-root-2");
        let join_leaf = hash_leaf(b"join-leaf-2");
        let revoked_since = hash_leaf(b"revoked-since-2");
        let left_bound = [0x10u8; 32];
        let right_bound = [0xF0u8; 32];
        let query = [0x80u8; 32];
        let revoked_root = hash_interval(&left_bound, &right_bound);

        let membership = RawMembershipWitness {
            leaf_id: join_leaf.to_vec(),
            root: join_leaf.to_vec(),
            path: Vec::new(),
        };

        let mut path = Vec::with_capacity(65);
        for idx in 0..65 {
            path.push(RawPathEntry {
                sibling: vec![idx as u8; 32],
                dir: (idx & 1) as u8,
            });
        }

        let nonmem = RawNonMembershipWitness {
            query: query.to_vec(),
            root: revoked_root.to_vec(),
            left: Some(left_bound.to_vec()),
            right: Some(right_bound.to_vec()),
            path,
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: Some(
                merkle::hash_interval_binding(
                    &left_bound,
                    &left_bound,
                    &right_bound,
                    &right_bound,
                    1,
                    1,
                )
                .to_vec(),
            ),
            lca_left_height: Some(1),
            lca_right_height: Some(1),
        };

        let witness = CanonicalWitness {
            inner: WitnessVariants::B {
                witness: membership,
                nonmem: Some(nonmem),
                pop: None,
            },
        };

        let anchor = AnchorInstance {
            gid: b"gid",
            cat: b"cat",
            we_epoch_id: [0xAA; 32],
            anchor_hdr_ctx: b"ctx",
            tswe_salt_hash: b"salt",
            parent_root: parent_root.as_slice(),
            join_delta_root: join_leaf.as_slice(),
            revoked_since_prev_root: revoked_since.as_slice(),
            revoked_root: revoked_root.as_slice(),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };

        let err = match witness.validate_against(&anchor) {
            Ok(_) => unreachable!("path oversize must fail but succeeded"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            MsphfError::Witness(WitnessValidationError::PathOversize)
        ));
    }

    #[test]
    fn membership_witness_rejects_invalid_dir_or_oversize_path() {
        let root = hash_leaf(b"path-root");

        let invalid_dir = RawMembershipWitness {
            leaf_id: root.to_vec(),
            root: root.to_vec(),
            path: vec![RawPathEntry {
                sibling: vec![0x11; 32],
                dir: 2,
            }],
        };
        let err = match CanonicalWitness::validate_membership_witness(&invalid_dir, &root) {
            Ok(_) => unreachable!("dir > 1 must fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            MsphfError::Witness(WitnessValidationError::ProjEvalFail)
        ));

        let oversize = RawMembershipWitness {
            leaf_id: root.to_vec(),
            root: root.to_vec(),
            path: (0..65)
                .map(|idx| RawPathEntry {
                    sibling: vec![idx as u8; 32],
                    dir: (idx & 1) as u8,
                })
                .collect(),
        };
        let err = match CanonicalWitness::validate_membership_witness(&oversize, &root) {
            Ok(_) => unreachable!("oversize membership path must fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            MsphfError::Witness(WitnessValidationError::PathOversize)
        ));
    }

    #[test]
    fn empty_tree_nonmembership_witness_accepts_zero_root() {
        let witness = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: vec![0x00; 32],
            left: None,
            right: None,
            path: Vec::new(),
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };

        let validated = match CanonicalWitness::validate_nonmembership_witness(&witness, &[0u8; 32])
        {
            Ok(validated) => validated,
            Err(err) => unreachable!("empty-tree sentinel should validate: {err}"),
        };
        assert_eq!(validated.query, [0x44; 32]);
        assert_eq!(validated.root, [0u8; 32]);
        assert!(validated.left.is_none());
        assert!(validated.right.is_none());
        assert!(validated.path.is_empty());
    }

    #[test]
    fn nonmembership_extended_interval_witness_validates() {
        let left_bound = [0x10u8; 32];
        let right_bound = [0xF0u8; 32];
        let query = [0x80u8; 32];

        let left_sibling = [0x21u8; 32];
        let right_sibling = [0x22u8; 32];
        let above_sibling = [0x23u8; 32];

        let left_anchor = hash_node(&left_bound, &left_sibling);
        let right_anchor = hash_node(&right_sibling, &right_bound);
        let lca = hash_node(&left_anchor, &right_anchor);
        let expected_root = hash_node(&lca, &above_sibling);

        let witness = RawNonMembershipWitness {
            query: query.to_vec(),
            root: expected_root.to_vec(),
            left: Some(left_bound.to_vec()),
            right: Some(right_bound.to_vec()),
            path: Vec::new(),
            left_below: vec![RawPathEntry {
                sibling: left_sibling.to_vec(),
                dir: 0,
            }],
            right_below: vec![RawPathEntry {
                sibling: right_sibling.to_vec(),
                dir: 1,
            }],
            above: vec![RawPathEntry {
                sibling: above_sibling.to_vec(),
                dir: 0,
            }],
            nmint: Some(
                merkle::hash_interval_binding(
                    &left_bound,
                    &left_bound,
                    &right_bound,
                    &right_bound,
                    2,
                    2,
                )
                .to_vec(),
            ),
            lca_left_height: Some(2),
            lca_right_height: Some(2),
        };

        let validated =
            match CanonicalWitness::validate_nonmembership_witness(&witness, &expected_root) {
                Ok(validated) => validated,
                Err(err) => unreachable!("extended interval witness should validate: {err}"),
            };
        assert_eq!(validated.query, query);
        assert_eq!(validated.root, expected_root);
        assert_eq!(validated.left, Some(left_bound));
        assert_eq!(validated.right, Some(right_bound));
        assert!(validated.path.is_empty());
    }

    #[test]
    fn validated_witness_digest_and_mode_cover_b_variant() -> Result<(), MsphfError> {
        let membership = ValidatedMembership {
            leaf_id: [0x11; 32],
            root: [0x22; 32],
            path: vec![(0, [0x33; 32])],
        };
        let witness_a = ValidatedWitness {
            mode: WitnessMode::A,
            membership: membership.clone(),
            nonmembership: None,
            pop: None,
        };
        let witness_b = ValidatedWitness {
            mode: WitnessMode::B,
            membership,
            nonmembership: Some(ValidatedNonMembership {
                query: [0x44; 32],
                root: [0x55; 32],
                left: Some([0x10; 32]),
                right: Some([0xF0; 32]),
                path: Vec::new(),
            }),
            pop: None,
        };

        assert_ne!(witness_a.digest()?, witness_b.digest()?);
        assert_eq!(
            CanonicalWitness {
                inner: WitnessVariants::B {
                    witness: RawMembershipWitness {
                        leaf_id: vec![0x11; 32],
                        root: vec![0x22; 32],
                        path: Vec::new(),
                    },
                    nonmem: None,
                    pop: None,
                },
            }
            .mode(),
            WitnessMode::B
        );
        Ok(())
    }

    #[test]
    fn nonmembership_witness_rejects_malformed_query_root_and_bounds() {
        let expected_root = [0xAA; 32];

        let bad_query = RawNonMembershipWitness {
            query: vec![0x44; 31],
            root: expected_root.to_vec(),
            left: None,
            right: None,
            path: Vec::new(),
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&bad_query, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let bad_root = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: vec![0xAA; 31],
            ..bad_query.clone()
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&bad_root, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let root_mismatch = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: vec![0xBB; 32],
            ..bad_query.clone()
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&root_mismatch, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::ProjEvalFail))
        ));

        let left_bad_len = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: expected_root.to_vec(),
            left: Some(vec![0x10; 31]),
            ..bad_query.clone()
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&left_bad_len, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let left_noncanonical = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: expected_root.to_vec(),
            left: Some(vec![0x44; 32]),
            ..bad_query.clone()
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&left_noncanonical, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        let right_bad_len = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: expected_root.to_vec(),
            right: Some(vec![0x55; 31]),
            ..bad_query.clone()
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&right_bad_len, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let right_noncanonical = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: expected_root.to_vec(),
            right: Some(vec![0x44; 32]),
            ..bad_query.clone()
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&right_noncanonical, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        let crossed_bounds = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: expected_root.to_vec(),
            left: Some(vec![0x60; 32]),
            right: Some(vec![0x50; 32]),
            ..bad_query
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&crossed_bounds, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));
    }

    #[test]
    fn nonmembership_extended_interval_rejects_lca_binding_and_depth_errors() {
        let left_bound = [0x10u8; 32];
        let right_bound = [0xF0u8; 32];
        let left_sibling = [0x21u8; 32];
        let right_sibling = [0x22u8; 32];
        let above_sibling = [0x23u8; 32];
        let left_anchor = hash_node(&left_bound, &left_sibling);
        let right_anchor = hash_node(&right_sibling, &right_bound);
        let lca = hash_node(&left_anchor, &right_anchor);
        let expected_root = hash_node(&lca, &above_sibling);

        let base = RawNonMembershipWitness {
            query: vec![0x80; 32],
            root: expected_root.to_vec(),
            left: Some(left_bound.to_vec()),
            right: Some(right_bound.to_vec()),
            path: Vec::new(),
            left_below: vec![RawPathEntry {
                sibling: left_sibling.to_vec(),
                dir: 0,
            }],
            right_below: vec![RawPathEntry {
                sibling: right_sibling.to_vec(),
                dir: 1,
            }],
            above: vec![RawPathEntry {
                sibling: above_sibling.to_vec(),
                dir: 0,
            }],
            nmint: Some(
                merkle::hash_interval_binding(
                    &left_bound,
                    &left_bound,
                    &right_bound,
                    &right_bound,
                    2,
                    2,
                )
                .to_vec(),
            ),
            lca_left_height: Some(2),
            lca_right_height: Some(2),
        };

        let mut missing_lca = base.clone();
        missing_lca.lca_left_height = None;
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&missing_lca, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        let mut wrong_lca = base.clone();
        wrong_lca.lca_right_height = Some(3);
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&wrong_lca, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        let mut bad_nmint_len = base.clone();
        bad_nmint_len.nmint = Some(vec![0xAA; 31]);
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&bad_nmint_len, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let mut too_deep = base.clone();
        too_deep.above = (0..64)
            .map(|_| RawPathEntry {
                sibling: vec![0x33; 32],
                dir: 0,
            })
            .collect();
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&too_deep, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::PathOversize))
        ));

        let mut wrong_root = base.clone();
        wrong_root.root = vec![0x99; 32];
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&wrong_root, &[0x99; 32]),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        let mut wrong_nmint = base;
        wrong_nmint.nmint = Some(vec![0xAB; 32]);
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&wrong_nmint, &expected_root),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));
    }

    #[test]
    fn nonmembership_empty_and_open_bound_guards_reject_noncanonical_shapes() {
        let mut empty_with_path = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: vec![0x00; 32],
            left: None,
            right: None,
            path: vec![RawPathEntry {
                sibling: vec![0x11; 32],
                dir: 0,
            }],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&empty_with_path, &[0u8; 32]),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        empty_with_path.path.clear();
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&empty_with_path, &[0x11; 32]),
            Err(MsphfError::Witness(WitnessValidationError::ProjEvalFail))
        ));

        let open_left = RawNonMembershipWitness {
            query: vec![0x44; 32],
            root: vec![0xAA; 32],
            left: Some(vec![0x10; 32]),
            right: None,
            path: Vec::new(),
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&open_left, &[0xAA; 32]),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        let mut both_bounds_with_path = RawNonMembershipWitness {
            query: vec![0x55; 32],
            root: vec![0xAA; 32],
            left: Some(vec![0x10; 32]),
            right: Some(vec![0xF0; 32]),
            path: vec![RawPathEntry {
                sibling: vec![0x11; 32],
                dir: 0,
            }],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: Some(vec![0x22; 32]),
            lca_left_height: Some(1),
            lca_right_height: Some(1),
        };
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&both_bounds_with_path, &[0xAA; 32]),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));

        both_bounds_with_path.path.clear();
        both_bounds_with_path.nmint = None;
        assert!(matches!(
            CanonicalWitness::validate_nonmembership_witness(&both_bounds_with_path, &[0xAA; 32]),
            Err(MsphfError::Witness(WitnessValidationError::NonCanonical))
        ));
    }

    #[test]
    fn nonmembership_single_open_bound_witness_validates() {
        let right_bound = [0x66u8; 32];
        let sibling = [0x24u8; 32];
        let expected_root = hash_node(&sibling, &right_bound);
        let query = [0x55u8; 32];

        let witness = RawNonMembershipWitness {
            query: query.to_vec(),
            root: expected_root.to_vec(),
            left: None,
            right: Some(right_bound.to_vec()),
            path: vec![RawPathEntry {
                sibling: sibling.to_vec(),
                dir: 1,
            }],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };

        let validated =
            match CanonicalWitness::validate_nonmembership_witness(&witness, &expected_root) {
                Ok(validated) => validated,
                Err(err) => unreachable!("single-open-bound witness should validate: {err}"),
            };
        assert_eq!(validated.query, query);
        assert_eq!(validated.root, expected_root);
        assert_eq!(validated.left, None);
        assert_eq!(validated.right, Some(right_bound));
        assert_eq!(validated.path, vec![(1, sibling)]);
    }

    #[test]
    fn nonmembership_single_left_bound_witness_validates() {
        let left_bound = [0x33u8; 32];
        let sibling = [0x81u8; 32];
        let expected_root = hash_node(&left_bound, &sibling);
        let query = [0x44u8; 32];

        let witness = RawNonMembershipWitness {
            query: query.to_vec(),
            root: expected_root.to_vec(),
            left: Some(left_bound.to_vec()),
            right: None,
            path: vec![RawPathEntry {
                sibling: sibling.to_vec(),
                dir: 0,
            }],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };

        let validated =
            match CanonicalWitness::validate_nonmembership_witness(&witness, &expected_root) {
                Ok(validated) => validated,
                Err(err) => unreachable!("single-left-bound witness should validate: {err}"),
            };
        assert_eq!(validated.query, query);
        assert_eq!(validated.root, expected_root);
        assert_eq!(validated.left, Some(left_bound));
        assert_eq!(validated.right, None);
        assert_eq!(validated.path, vec![(0, sibling)]);
    }

    #[test]
    fn fold_step_and_pop_validation_cover_error_paths() -> Result<(), MsphfError> {
        assert!(matches!(
            CanonicalWitness::fold_step(
                [0x11; 32],
                &RawPathEntry {
                    sibling: vec![0x22; 31],
                    dir: 0,
                }
            ),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));
        assert!(matches!(
            CanonicalWitness::fold_step(
                [0x11; 32],
                &RawPathEntry {
                    sibling: vec![0x22; 32],
                    dir: 2,
                }
            ),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let membership = ValidatedMembership {
            leaf_id: [0x33; 32],
            root: [0x44; 32],
            path: Vec::new(),
        };
        let anchor = anchor_for(&membership.root, &membership.root, &[0u8; 32]);
        assert!(matches!(
            CanonicalWitness::validate_pop(
                &anchor,
                &membership,
                &RawPopWitness {
                    public_key: vec![0x11; ML_DSA65_PUBLIC_KEY_LEN - 1],
                    signature: vec![0x22; ML_DSA65_SIGNATURE_LEN],
                }
            ),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));
        assert!(matches!(
            CanonicalWitness::validate_pop(
                &anchor,
                &membership,
                &RawPopWitness {
                    public_key: vec![0x11; ML_DSA65_PUBLIC_KEY_LEN],
                    signature: vec![0x22; ML_DSA65_SIGNATURE_LEN - 1],
                }
            ),
            Err(MsphfError::Witness(WitnessValidationError::CborMalformed))
        ));

        let (pk, sk) = keypair();
        let anchor = anchor_for(&membership.root, &membership.root, &[0u8; 32]);
        let xk_bytes = anchor.to_cbor_bytes()?;
        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }
        let mut msg = hash::h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &xk_bytes,
                leaf_id: &membership.leaf_id,
                epoch: &anchor.we_epoch_id,
            },
        )?;
        msg[0] ^= 0xFF;
        let signature = detached_sign(&msg, &sk);
        assert!(matches!(
            CanonicalWitness::validate_pop(
                &anchor,
                &membership,
                &RawPopWitness {
                    public_key: pk.as_bytes().to_vec(),
                    signature: signature.as_bytes().to_vec(),
                }
            ),
            Err(MsphfError::Witness(WitnessValidationError::ProjEvalFail))
        ));
        Ok(())
    }

    #[test]
    fn variant_b_with_pop_without_nonmembership_validates() -> Result<(), MsphfError> {
        let (pk, sk) = keypair();
        #[derive(Serialize)]
        struct LeafBinding<'a> {
            #[serde(with = "serde_bytes")]
            public_key: &'a [u8],
        }
        let leaf_digest = hash::h_l(
            ds::MSPHF_LEAF_ID,
            &LeafBinding {
                public_key: pk.as_bytes(),
            },
        )?;
        let anchor = anchor_for(&leaf_digest, &leaf_digest, &[0u8; 32]);
        let xk_bytes = anchor.to_cbor_bytes()?;
        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }
        let msg = hash::h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &xk_bytes,
                leaf_id: &leaf_digest,
                epoch: &anchor.we_epoch_id,
            },
        )?;
        let signature = detached_sign(&msg, &sk);
        let witness = CanonicalWitness {
            inner: WitnessVariants::B {
                witness: RawMembershipWitness {
                    leaf_id: leaf_digest.to_vec(),
                    root: leaf_digest.to_vec(),
                    path: Vec::new(),
                },
                nonmem: None,
                pop: Some(RawPopWitness {
                    public_key: pk.as_bytes().to_vec(),
                    signature: signature.as_bytes().to_vec(),
                }),
            },
        };
        let validated = witness.validate_against(&anchor)?;
        assert_eq!(validated.mode, WitnessMode::B);
        assert!(validated.nonmembership.is_none());
        assert!(validated.pop.is_some());
        Ok(())
    }
}
