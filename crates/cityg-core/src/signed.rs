//! Signed CBOR arrays.
//!
//! Every signed object of the profile except the commit (whose map form is
//! kept for its registry) is encoded as
//!
//! ```text
//! Signed := CBOR_det([field_1, ..., field_k, signature])
//! signature := ML-DSA-87.Sign(sk, CBOR_det([field_1, ..., field_k]), ctx)
//! ```
//!
//! `field_1` is always the text label naming the object and its version, so
//! the signed bytes of two object types never coincide; the FIPS 204 context
//! string separates them a second time.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{array, bytes, decode, encode, expect_array, expect_bytes, expect_label};
use crate::error::{CoreError, CoreResult};
use crate::identity::{DeviceIdentity, verify_signature};

/// Sign `fields` with `identity` under `context`; returns the encoding of
/// `[fields..., signature]`.
pub(crate) fn sign_fields(
    fields: Vec<Value>,
    identity: &DeviceIdentity,
    context: SignatureContext,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Vec<u8>> {
    let mut items = fields;
    let tbs = encode(&array(items.clone()))?;
    let signature = identity.sign(context, &tbs, rng)?;
    items.push(bytes(&signature));
    encode(&array(items))
}

/// Parsed signed array: its fields (label included), the to-be-signed bytes
/// and the signature. The signature is not verified yet.
pub(crate) struct Opened {
    pub fields: Vec<Value>,
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Opened {
    /// Verify the signature under `public_key`.
    pub(crate) fn verify(
        &self,
        public_key: &[u8],
        context: SignatureContext,
        what: &'static str,
    ) -> CoreResult<()> {
        verify_signature(public_key, context, &self.tbs, &self.signature, what)
    }
}

/// Decode a signed array of `field_count` fields (label included) whose
/// first field is the text `label`.
pub(crate) fn open_signed(
    encoded: &[u8],
    label: &str,
    field_count: usize,
    max_len: usize,
    what: &'static str,
) -> CoreResult<Opened> {
    let mut items = expect_array(decode(encoded, max_len, what)?, field_count + 1, what)?;
    let signature = expect_bytes(items.pop().ok_or(CoreError::Malformed(what))?, what)?;
    let first = items.first().ok_or(CoreError::Malformed(what))?;
    expect_label(first, label, what)?;
    let tbs = encode(&array(items.clone()))?;
    Ok(Opened {
        fields: items,
        tbs,
        signature,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::cbor::{text, uint};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn signed_arrays_round_trip_and_bind_label_and_fields() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let encoded = sign_fields(
            vec![text("city-g/test/v1"), uint(7)],
            &alice,
            SignatureContext::POLICY,
            &mut rng,
        )
        .unwrap();
        let opened = open_signed(&encoded, "city-g/test/v1", 2, 10_000, "test").unwrap();
        assert_eq!(opened.fields, vec![text("city-g/test/v1"), uint(7)]);
        opened
            .verify(alice.public_key(), SignatureContext::POLICY, "test")
            .unwrap();
        assert!(
            opened
                .verify(alice.public_key(), SignatureContext::ANCHOR, "test")
                .is_err()
        );
        assert!(open_signed(&encoded, "city-g/other/v1", 2, 10_000, "test").is_err());
        assert!(open_signed(&encoded, "city-g/test/v1", 3, 10_000, "test").is_err());
        assert!(open_signed(&encoded, "city-g/test/v1", 2, 10, "test").is_err());
    }
}
