//! Signed CBOR arrays and small decoding helpers.
//!
//! Every signed object of the profile is encoded as
//!
//! ```text
//! Signed := CBOR_det([field_1, ..., field_k, signature])
//! signature := ML-DSA-65.Sign(sk, CBOR_det([field_1, ..., field_k]), ctx)
//! ```
//!
//! `field_1` is the text label naming the object and its version (all
//! `.../v4` in this profile), so the signed bytes of two object types never
//! coincide; the FIPS 204 context string separates them a second time.

use ciborium::value::Value;
use cityg_core::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_uint,
};
use cityg_core::error::{CoreError, CoreResult};
use cityg_core::hash::Digest;
use cityg_core::identity::{DeviceIdentity, verify_signature};
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::tree::Occupancy;

/// Sign `fields` with `identity` under `context`; returns the encoding of
/// `[fields..., signature]`, the to-be-signed bytes and the signature.
pub(crate) fn sign_fields(
    fields: Vec<Value>,
    identity: &DeviceIdentity,
    context: SignatureContext,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Signed> {
    let tbs = encode(&array(fields.clone()))?;
    let signature = identity.sign(context, &tbs, rng)?;
    let mut items = fields;
    items.push(bytes(&signature));
    Ok(Signed {
        encoded: encode(&array(items))?,
        tbs,
        signature,
    })
}

/// The three views of a signed array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signed {
    pub encoded: Vec<u8>,
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Signed {
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
/// first field is the text `label`. Returns the fields after the label.
pub(crate) fn open_signed(
    encoded: &[u8],
    label: &str,
    field_count: usize,
    max_len: usize,
    what: &'static str,
) -> CoreResult<(Fields, Signed)> {
    let mut items = expect_array(decode(encoded, max_len, what)?, field_count + 1, what)?;
    let signature = expect_bytes(items.pop().ok_or(CoreError::Malformed(what))?, what)?;
    let first = items.first().ok_or(CoreError::Malformed(what))?;
    expect_label(first, label, what)?;
    let tbs = encode(&array(items.clone()))?;
    let mut fields = Fields::new(items, what);
    fields.next()?;
    Ok((
        fields,
        Signed {
            encoded: encoded.to_vec(),
            tbs,
            signature,
        },
    ))
}

/// Decode an unsigned array of `field_count` fields whose first field is
/// the text `label`. Returns the fields after the label.
pub(crate) fn open_unsigned(
    encoded: &[u8],
    label: &str,
    field_count: usize,
    max_len: usize,
    what: &'static str,
) -> CoreResult<Fields> {
    let items = expect_array(decode(encoded, max_len, what)?, field_count, what)?;
    let first = items.first().ok_or(CoreError::Malformed(what))?;
    expect_label(first, label, what)?;
    let mut fields = Fields::new(items, what);
    fields.next()?;
    Ok(fields)
}

/// Sequential reader of the fields of an array.
pub(crate) struct Fields {
    items: std::vec::IntoIter<Value>,
    what: &'static str,
}

impl Fields {
    pub(crate) fn new(items: Vec<Value>, what: &'static str) -> Self {
        Self {
            items: items.into_iter(),
            what,
        }
    }

    pub(crate) fn next(&mut self) -> CoreResult<Value> {
        self.items.next().ok_or(CoreError::Malformed(self.what))
    }

    pub(crate) fn uint(&mut self) -> CoreResult<u64> {
        expect_uint(&self.next()?, self.what)
    }

    pub(crate) fn u32(&mut self) -> CoreResult<u32> {
        u32::try_from(self.uint()?).map_err(|_| CoreError::Malformed(self.what))
    }

    pub(crate) fn u8(&mut self) -> CoreResult<u8> {
        u8::try_from(self.uint()?).map_err(|_| CoreError::Malformed(self.what))
    }

    pub(crate) fn bytes(&mut self) -> CoreResult<Vec<u8>> {
        expect_bytes(self.next()?, self.what)
    }

    pub(crate) fn digest(&mut self) -> CoreResult<Digest> {
        expect_bytes32(self.next()?, self.what)
    }

    pub(crate) fn occupancy(&mut self) -> CoreResult<Occupancy> {
        Occupancy::from_value(self.next()?, self.what)
    }

    pub(crate) fn list(&mut self) -> CoreResult<Vec<Value>> {
        expect_list(self.next()?, self.what)
    }

    /// A field that is `null` or something else.
    pub(crate) fn optional(&mut self) -> CoreResult<Option<Value>> {
        match self.next()? {
            Value::Null => Ok(None),
            value => Ok(Some(value)),
        }
    }

    pub(crate) fn optional_bytes(&mut self) -> CoreResult<Option<Vec<u8>>> {
        self.optional()?
            .map(|value| expect_bytes(value, self.what))
            .transpose()
    }

    pub(crate) fn optional_occupancy(&mut self) -> CoreResult<Option<Occupancy>> {
        self.optional()?
            .map(|value| Occupancy::from_value(value, self.what))
            .transpose()
    }
}

/// `null` or `f(value)`.
pub(crate) fn nullable<T>(value: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    value.map_or(Value::Null, f)
}
