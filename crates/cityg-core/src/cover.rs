//! Cover-failure reports (audit P-3.h).
//!
//! ```text
//! CoverFailureReport := ["city-g/cover-failure/v1", gid, epoch,
//!                        reporter_leaf_id, reason]
//! Signed := [CoverFailureReport..., signature]  ctx "city-g/cover-failure/v1"
//! ```
//!
//! A member that cannot process the commit of epoch `epoch` (no decryptable
//! path secret, a path key mismatch or a wrong confirmation tag) signs a
//! report naming the epoch. The delivery service records it next to the
//! commit, so the failure and the author of the faulty commit are visible to
//! every member. The reporter then re-enters the group with a resync
//! external commit: with a chained key schedule, a member that missed an
//! epoch can only come back through the external init.

use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes32, expect_uint, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::hash::Digest;
use crate::identity::DeviceIdentity;
use crate::roster::Roster;
use crate::signed::{open_signed, sign_fields};

/// Label of a cover-failure report.
pub const COVER_FAILURE_LABEL: &str = "city-g/cover-failure/v1";
/// Upper bound on an encoded report.
pub const MAX_COVER_FAILURE_BYTES: usize = 8 * 1024;

/// Why a member could not process a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverFailureReason {
    /// No path secret was encrypted to a node this member holds.
    NotCovered,
    /// A derivable path public key differs from the published one.
    PathKeyMismatch,
    /// The confirmation tag does not match the derived epoch secrets.
    ConfirmationTagMismatch,
    /// The member lost its state.
    StateLost,
}

impl CoverFailureReason {
    fn code(self) -> u64 {
        match self {
            Self::NotCovered => 1,
            Self::PathKeyMismatch => 2,
            Self::ConfirmationTagMismatch => 3,
            Self::StateLost => 4,
        }
    }

    fn from_code(code: u64) -> CoreResult<Self> {
        match code {
            1 => Ok(Self::NotCovered),
            2 => Ok(Self::PathKeyMismatch),
            3 => Ok(Self::ConfirmationTagMismatch),
            4 => Ok(Self::StateLost),
            _ => Err(CoreError::Malformed("cover failure reason")),
        }
    }
}

/// A signed cover-failure report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverFailureReport {
    pub gid: Digest,
    pub epoch: u64,
    pub reporter_leaf_id: Digest,
    pub reason: CoverFailureReason,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    encoded: Vec<u8>,
}

impl CoverFailureReport {
    /// Sign a report as `reporter`.
    pub fn sign(
        gid: &Digest,
        epoch: u64,
        reason: CoverFailureReason,
        reporter: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let encoded = sign_fields(
            vec![
                text(COVER_FAILURE_LABEL),
                bytes(gid),
                uint(epoch),
                bytes(&reporter.leaf_id(gid)?),
                uint(reason.code()),
            ],
            reporter,
            SignatureContext::COVER_FAILURE,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Decode a report (its signature is checked by [`Self::verify`]).
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            COVER_FAILURE_LABEL,
            5,
            MAX_COVER_FAILURE_BYTES,
            "cover failure",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("cover failure"));
        let gid = expect_bytes32(next()?, "cover failure gid")?;
        let epoch = expect_uint(&next()?, "cover failure epoch")?;
        let reporter_leaf_id = expect_bytes32(next()?, "cover failure reporter")?;
        let reason = CoverFailureReason::from_code(expect_uint(&next()?, "cover failure reason")?)?;
        Ok(Self {
            gid,
            epoch,
            reporter_leaf_id,
            reason,
            tbs: opened.tbs,
            signature: opened.signature,
            encoded: encoded.to_vec(),
        })
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Check the report against `roster`: same group, reporter is a member
    /// and signed it.
    pub fn verify(&self, gid: &Digest, roster: &Roster) -> CoreResult<()> {
        if &self.gid != gid {
            return Err(CoreError::Invalid("cover failure for another group"));
        }
        let reporter =
            roster
                .member_by_leaf(&self.reporter_leaf_id)
                .ok_or(CoreError::Unauthorized(
                    "cover failure reporter is not a member",
                ))?;
        crate::identity::verify_signature(
            &reporter.device_pk,
            SignatureContext::COVER_FAILURE,
            &self.tbs,
            &self.signature,
            "cover failure",
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn reports_verify_against_the_roster() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [3; 32];
        let roster = Roster::genesis(&gid, alice.public_key()).unwrap();
        for reason in [
            CoverFailureReason::NotCovered,
            CoverFailureReason::PathKeyMismatch,
            CoverFailureReason::ConfirmationTagMismatch,
            CoverFailureReason::StateLost,
        ] {
            let report = CoverFailureReport::sign(&gid, 4, reason, &alice, &mut rng).unwrap();
            report.verify(&gid, &roster).unwrap();
            let decoded = CoverFailureReport::decode(report.encoded()).unwrap();
            assert_eq!(decoded, report);
            assert_eq!(decoded.reason, reason);
        }
        let outsider =
            CoverFailureReport::sign(&gid, 4, CoverFailureReason::NotCovered, &bob, &mut rng)
                .unwrap();
        assert!(outsider.verify(&gid, &roster).is_err());
        let report =
            CoverFailureReport::sign(&gid, 4, CoverFailureReason::NotCovered, &alice, &mut rng)
                .unwrap();
        assert!(report.verify(&[9; 32], &roster).is_err());
        assert!(CoverFailureReason::from_code(9).is_err());
        assert!(CoverFailureReport::decode(&[0x80]).is_err());
    }
}
