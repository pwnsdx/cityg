//! Deployment binding objects.
//!
//! These signed objects are not part of the group protocol (they change no
//! group state and no key): they bind a delivery-service deployment to the
//! group's device keys (audit P-7, separation of core and deployment).
//!
//! ```text
//! AliasBinding := ["city-g/alias/v1", gid, device_pk, alias]
//!                 signed by device_pk, ctx "city-g/identity-binding/v1"
//! SessionAuth  := ["city-g/session-auth/v1", gid, device_pk, issued_at_ms]
//!                 signed by device_pk, ctx "city-g/session-auth/v1"
//! ```
//!
//! An alias is a display name a member claims for itself; it is self-asserted
//! and only as trustworthy as the device key that signed it. A session
//! authentication proves to the delivery service that a request comes from
//! the holder of a member's device key, in exchange for a short-lived bearer
//! token.

use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes, expect_bytes32, expect_uint, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::hash::Digest;
use crate::identity::{DeviceIdentity, check_device_key, device_id};
use crate::signed::{open_signed, sign_fields};

/// Label of an alias binding.
pub const ALIAS_LABEL: &str = "city-g/alias/v1";
/// Label of a session authentication.
pub const SESSION_AUTH_LABEL: &str = "city-g/session-auth/v1";
/// Longest alias, in bytes of its UTF-8 encoding.
pub const MAX_ALIAS_BYTES: usize = 64;
const MAX_BINDING_BYTES: usize = 12 * 1024;

/// Check an alias: non-empty, at most [`MAX_ALIAS_BYTES`] bytes, no control
/// characters and no leading or trailing whitespace.
pub fn validate_alias(alias: &str) -> CoreResult<()> {
    if alias.is_empty()
        || alias.len() > MAX_ALIAS_BYTES
        || alias.chars().any(char::is_control)
        || alias.trim() != alias
    {
        return Err(CoreError::Invalid("alias"));
    }
    Ok(())
}

/// A display name signed by a device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasBinding {
    pub gid: Digest,
    pub device_pk: Vec<u8>,
    pub alias: String,
    encoded: Vec<u8>,
}

impl AliasBinding {
    /// Sign `alias` for `identity` in group `gid`.
    pub fn sign(
        gid: &Digest,
        alias: &str,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        validate_alias(alias)?;
        let encoded = sign_fields(
            vec![
                text(ALIAS_LABEL),
                bytes(gid),
                bytes(identity.public_key()),
                text(alias),
            ],
            identity,
            SignatureContext::IDENTITY_BINDING,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Decode a binding and verify its signature.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(encoded, ALIAS_LABEL, 4, MAX_BINDING_BYTES, "alias binding")?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("alias binding"));
        let gid = expect_bytes32(next()?, "alias binding gid")?;
        let device_pk = expect_bytes(next()?, "alias binding key")?;
        check_device_key(&device_pk, "alias binding key")?;
        let alias = match next()? {
            ciborium::value::Value::Text(alias) => alias,
            _ => return Err(CoreError::Malformed("alias binding alias")),
        };
        validate_alias(&alias)?;
        opened.verify(
            &device_pk,
            SignatureContext::IDENTITY_BINDING,
            "alias binding",
        )?;
        Ok(Self {
            gid,
            device_pk,
            alias,
            encoded: encoded.to_vec(),
        })
    }

    /// `device_id` of the binding's device in its group.
    pub fn device_id(&self) -> CoreResult<Digest> {
        device_id(&self.gid, &self.device_pk)
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

/// Proof that a request comes from the holder of a device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAuth {
    pub gid: Digest,
    pub device_pk: Vec<u8>,
    pub issued_at_ms: u64,
    encoded: Vec<u8>,
}

impl SessionAuth {
    /// Sign a session request for `identity` in group `gid` at `now_ms`.
    pub fn sign(
        gid: &Digest,
        now_ms: u64,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let encoded = sign_fields(
            vec![
                text(SESSION_AUTH_LABEL),
                bytes(gid),
                bytes(identity.public_key()),
                uint(now_ms),
            ],
            identity,
            SignatureContext::SESSION_AUTH,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Decode a session request and verify its signature.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            SESSION_AUTH_LABEL,
            4,
            MAX_BINDING_BYTES,
            "session auth",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("session auth"));
        let gid = expect_bytes32(next()?, "session auth gid")?;
        let device_pk = expect_bytes(next()?, "session auth key")?;
        check_device_key(&device_pk, "session auth key")?;
        let issued_at_ms = expect_uint(&next()?, "session auth time")?;
        opened.verify(&device_pk, SignatureContext::SESSION_AUTH, "session auth")?;
        Ok(Self {
            gid,
            device_pk,
            issued_at_ms,
            encoded: encoded.to_vec(),
        })
    }

    /// Check freshness: `issued_at_ms` within `max_skew_ms` of `now_ms`.
    pub fn check_fresh(&self, now_ms: u64, max_skew_ms: u64) -> CoreResult<()> {
        if self.issued_at_ms.abs_diff(now_ms) > max_skew_ms {
            return Err(CoreError::Invalid("stale session auth"));
        }
        Ok(())
    }

    /// `device_id` of the requesting device in its group.
    pub fn device_id(&self) -> CoreResult<Digest> {
        device_id(&self.gid, &self.device_pk)
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn aliases_are_signed_and_validated() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let gid = [2; 32];
        let binding = AliasBinding::sign(&gid, "Alice", &alice, &mut rng).unwrap();
        assert_eq!(AliasBinding::decode(binding.encoded()).unwrap(), binding);
        assert_eq!(binding.device_id().unwrap(), alice.device_id(&gid).unwrap());
        for bad in ["", " padded", "tab\there", &"x".repeat(MAX_ALIAS_BYTES + 1)] {
            assert!(AliasBinding::sign(&gid, bad, &alice, &mut rng).is_err());
        }
        let mut tampered = binding.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(AliasBinding::decode(&tampered).is_err());
    }

    #[test]
    fn session_auth_is_signed_and_fresh() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let gid = [3; 32];
        let auth = SessionAuth::sign(&gid, 10_000, &alice, &mut rng).unwrap();
        assert_eq!(SessionAuth::decode(auth.encoded()).unwrap(), auth);
        assert_eq!(auth.device_id().unwrap(), alice.device_id(&gid).unwrap());
        auth.check_fresh(10_500, 1_000).unwrap();
        auth.check_fresh(9_500, 1_000).unwrap();
        assert!(auth.check_fresh(20_000, 1_000).is_err());
        assert!(SessionAuth::decode(&[0x80]).is_err());
    }
}
