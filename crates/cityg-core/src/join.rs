//! Batched joins: join requests and welcomes.
//!
//! ```text
//! JoinRequest       := ["city-g/join-request/v1", gid, device_pk, encryption_key,
//!                       init_key, SignedAdmission]
//! SignedJoinRequest := [JoinRequest..., signature]
//!     signature := ML-DSA-65.Sign(device_sk, CBOR_det(JoinRequest),
//!                                 ctx = "city-g/join-request/v1")
//! request_ref := H_L("proposal-ref", [SignedJoinRequest])
//!
//! Welcome := ["city-g/welcome/v1", gid, epoch, request_ref, kem_ciphertext, wrapped]
//!     (kem_ciphertext, shared) := X-Wing.Encaps(init_key)
//!     context := CBOR_det([gid, epoch, request_ref, H_pk(init_key)])
//!     wrapped := ChaCha20-Poly1305(ExpandLabel(shared, "welcome key", context, 32),
//!                                  ExpandLabel(shared, "welcome nonce", context, 12),
//!                                  aad = context, pt = joiner_secret_epoch)
//! ```
//!
//! A joiner publishes a signed request: its device key, the X-Wing key of
//! its future leaf (`encryption_key`), a one-time X-Wing key for its welcome
//! (`init_key`) and its admission. The delivery service records requests
//! concurrently; the next commit, by any member or by a joiner through an
//! external commit, places all of them in the tree. Each joiner then
//! receives a welcome: the epoch's `joiner_secret`, encrypted to its
//! `init_key`. It learns the path secrets of the commit with its leaf key,
//! like any member. Keeping the init key apart from the leaf key, and
//! erasing it once the welcome is open, keeps the join epoch secret when the
//! leaf key leaks later.
//!
//! A welcome is not signed: the joiner checks the secret it carries against
//! the confirmation tag of the epoch, which the author's signed GroupInfo
//! states.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::admission::SignedAdmission;
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_uint, text, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, expand_label_into};
use crate::identity::{DeviceIdentity, check_device_key, device_id};
use crate::kem::{
    KEM_CIPHERTEXT_BYTES, KEM_SEED_BYTES, KemSecret, encapsulate, pk_hash, validate_public_key,
};
use crate::proposal::proposal_ref;
use crate::registry::Membership;
use crate::signed::{open_signed, sign_fields};
use crate::tree::next;

/// Label of a join request.
pub const JOIN_REQUEST_LABEL: &str = "city-g/join-request/v1";
/// Label of a welcome.
pub const WELCOME_LABEL: &str = "city-g/welcome/v1";
/// Upper bound on an encoded signed join request.
pub const MAX_JOIN_REQUEST_BYTES: usize = 32 * 1024;
/// Upper bound on an encoded welcome.
pub const MAX_WELCOME_BYTES: usize = 2 * 1024;
/// Size of a wrapped joiner secret (32-byte secret + 16-byte tag).
pub const WRAPPED_JOINER_SECRET_BYTES: usize = 48;

/// Private keys of a pending join request, kept by the joiner until its
/// welcome arrives.
#[derive(Clone)]
pub struct JoinSecrets {
    /// Private key of the joiner's leaf.
    pub encryption_key: KemSecret,
    /// One-time key the welcome is encrypted to.
    pub init_key: KemSecret,
}

impl core::fmt::Debug for JoinSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JoinSecrets(..)")
    }
}

impl JoinSecrets {
    /// Fresh keys.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            encryption_key: KemSecret::generate(rng),
            init_key: KemSecret::generate(rng),
        }
    }

    /// Encoding for persistence by the joiner (secrets included).
    pub fn export(&self) -> CoreResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(encode(&array(vec![
            bytes(self.encryption_key.seed()),
            bytes(self.init_key.seed()),
        ]))?))
    }

    /// Restore exported keys.
    pub fn import(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 256, "join secrets")?, 2, "join secrets")?.into_iter();
        let mut key = || -> CoreResult<KemSecret> {
            let seed: [u8; KEM_SEED_BYTES] =
                expect_bytes(next(&mut items, "join secrets")?, "join secret")?
                    .try_into()
                    .map_err(|_| CoreError::Malformed("join secret"))?;
            Ok(KemSecret::from_seed(seed))
        };
        Ok(Self {
            encryption_key: key()?,
            init_key: key()?,
        })
    }
}

/// A join request whose signature and admission verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedJoinRequest {
    pub gid: Digest,
    pub device_pk: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub init_key: Vec<u8>,
    pub admission: SignedAdmission,
    encoded: Vec<u8>,
}

impl SignedJoinRequest {
    /// Sign a request of `identity`, with the public keys of `secrets` and
    /// `admission`.
    pub fn create(
        identity: &DeviceIdentity,
        secrets: &JoinSecrets,
        admission: &SignedAdmission,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let encoded = sign_fields(
            vec![
                text(JOIN_REQUEST_LABEL),
                bytes(&admission.gid),
                bytes(identity.public_key()),
                bytes(&secrets.encryption_key.public_key()),
                bytes(&secrets.init_key.public_key()),
                bytes(admission.encoded()),
            ],
            identity,
            SignatureContext::JOIN_REQUEST,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Decode a request and verify its signature and the signatures of its
    /// admission; the admission must name the requesting device.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            JOIN_REQUEST_LABEL,
            6,
            MAX_JOIN_REQUEST_BYTES,
            "join request",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut field =
            || -> CoreResult<Value> { fields.next().ok_or(CoreError::Malformed("join request")) };
        let gid = expect_bytes32(field()?, "join request gid")?;
        let device_pk = expect_bytes(field()?, "join request device key")?;
        check_device_key(&device_pk, "join request device key")?;
        let encryption_key = expect_bytes(field()?, "join request leaf key")?;
        validate_public_key(&encryption_key)?;
        let init_key = expect_bytes(field()?, "join request init key")?;
        validate_public_key(&init_key)?;
        if init_key == encryption_key {
            return Err(CoreError::Invalid("join request reuses its leaf key"));
        }
        let admission =
            SignedAdmission::decode(&expect_bytes(field()?, "join request admission")?)?;
        if admission.gid != gid || admission.device_id != device_id(&gid, &device_pk)? {
            return Err(CoreError::Invalid("admission does not match the request"));
        }
        opened.verify(&device_pk, SignatureContext::JOIN_REQUEST, "join request")?;
        Ok(Self {
            gid,
            device_pk,
            encryption_key,
            init_key,
            admission,
            encoded: encoded.to_vec(),
        })
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `request_ref := H_L("proposal-ref", [SignedJoinRequest])`.
    pub fn reference(&self) -> CoreResult<Digest> {
        proposal_ref(&self.encoded)
    }

    /// Check that the request can enter epoch `epoch` of group `gid`: the
    /// device is not a member and its admission is authorized.
    pub fn authorize(
        &self,
        gid: &Digest,
        epoch: u64,
        membership: &Membership<'_>,
    ) -> CoreResult<()> {
        if &self.gid != gid {
            return Err(CoreError::Invalid("join request for another group"));
        }
        if membership.member_by_device(&self.device_pk).is_some() {
            return Err(CoreError::Invalid("joiner is already a member"));
        }
        self.admission
            .authorize(gid, &self.admission.device_id, epoch, membership)
    }
}

fn welcome_context(
    gid: &Digest,
    epoch: u64,
    request_ref: &Digest,
    init_key: &[u8],
) -> CoreResult<Vec<u8>> {
    encode(&array(vec![
        bytes(gid),
        uint(epoch),
        bytes(request_ref),
        bytes(&pk_hash(init_key)?),
    ]))
}

fn welcome_cipher(shared: &[u8; 32], context: &[u8]) -> CoreResult<(ChaCha20Poly1305, [u8; 12])> {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_label_into(shared, "welcome key", context, key.as_mut())?;
    let mut nonce = [0u8; 12];
    expand_label_into(shared, "welcome nonce", context, &mut nonce)?;
    Ok((
        ChaCha20Poly1305::new(Key::from_slice(key.as_slice())),
        nonce,
    ))
}

/// The joiner secret of one epoch, encrypted to one joiner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub gid: Digest,
    pub epoch: u64,
    pub request_ref: Digest,
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_joiner_secret: Vec<u8>,
}

impl Welcome {
    /// Encrypt `joiner_secret` of `epoch` to the init key of `request`.
    pub fn seal(
        epoch: u64,
        request: &SignedJoinRequest,
        joiner_secret: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let request_ref = request.reference()?;
        let context = welcome_context(&request.gid, epoch, &request_ref, &request.init_key)?;
        let (kem_ciphertext, shared) = encapsulate(&request.init_key, rng)?;
        let (cipher, nonce) = welcome_cipher(&shared, &context)?;
        let wrapped_joiner_secret = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: joiner_secret,
                    aad: &context,
                },
            )
            .map_err(|_| CoreError::Crypto("welcome wrap"))?;
        Ok(Self {
            gid: request.gid,
            epoch,
            request_ref,
            kem_ciphertext,
            wrapped_joiner_secret,
        })
    }

    /// Recover the joiner secret with the init key of the request.
    pub fn open(&self, init_key: &KemSecret) -> CoreResult<Zeroizing<[u8; 32]>> {
        let context = welcome_context(
            &self.gid,
            self.epoch,
            &self.request_ref,
            &init_key.public_key(),
        )?;
        let shared = init_key.decapsulate(&self.kem_ciphertext)?;
        let (cipher, nonce) = welcome_cipher(&shared, &context)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &self.wrapped_joiner_secret,
                        aad: &context,
                    },
                )
                .map_err(|_| CoreError::Decrypt("welcome"))?,
        );
        let mut secret = Zeroizing::new([0u8; 32]);
        if plaintext.len() != 32 {
            return Err(CoreError::Decrypt("welcome length"));
        }
        secret.copy_from_slice(&plaintext);
        Ok(secret)
    }

    /// Deterministic encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(WELCOME_LABEL),
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.request_ref),
            bytes(&self.kem_ciphertext),
            bytes(&self.wrapped_joiner_secret),
        ]))
    }

    /// Decode a welcome (its content is checked when it is opened).
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, MAX_WELCOME_BYTES, "welcome")?, 6, "welcome")?.into_iter();
        expect_label(&next(&mut items, "welcome")?, WELCOME_LABEL, "welcome")?;
        let gid = expect_bytes32(next(&mut items, "welcome")?, "welcome gid")?;
        let epoch = expect_uint(&next(&mut items, "welcome")?, "welcome epoch")?;
        let request_ref = expect_bytes32(next(&mut items, "welcome")?, "welcome request")?;
        let kem_ciphertext = expect_bytes(next(&mut items, "welcome")?, "welcome ciphertext")?;
        let wrapped_joiner_secret = expect_bytes(next(&mut items, "welcome")?, "welcome secret")?;
        if kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
            || wrapped_joiner_secret.len() != WRAPPED_JOINER_SECRET_BYTES
        {
            return Err(CoreError::Malformed("welcome ciphertext"));
        }
        Ok(Self {
            gid,
            epoch,
            request_ref,
            kem_ciphertext,
            wrapped_joiner_secret,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use crate::tree::{LeafNode, PublicTree};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn request(
        gid: &Digest,
        admin: &DeviceIdentity,
        joiner: &DeviceIdentity,
        rng: &mut ChaCha20Rng,
    ) -> (SignedJoinRequest, JoinSecrets) {
        let admission =
            SignedAdmission::by_admin(gid, &joiner.device_id(gid).unwrap(), 10, admin, rng)
                .unwrap();
        let secrets = JoinSecrets::generate(rng);
        let request = SignedJoinRequest::create(joiner, &secrets, &admission, rng).unwrap();
        (request, secrets)
    }

    #[test]
    fn requests_verify_and_are_authorized() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [3; 32];
        let mut tree = PublicTree::new(4).unwrap();
        tree.add_leaf(
            0,
            LeafNode {
                device_pk: alice.public_key().to_vec(),
                since: 0,
                encryption_key: KemSecret::generate(&mut rng).public_key(),
                admission_hash: [0; 32],
            },
        )
        .unwrap();
        let registry = Registry::genesis(4).unwrap();
        let (request, secrets) = request(&gid, &alice, &bob, &mut rng);
        assert_eq!(
            SignedJoinRequest::decode(request.encoded()).unwrap(),
            request
        );
        assert_eq!(request.encryption_key, secrets.encryption_key.public_key());
        let membership = Membership::new(&tree, &registry);
        request.authorize(&gid, 1, &membership).unwrap();
        assert!(request.authorize(&[4; 32], 1, &membership).is_err());
        assert!(request.authorize(&gid, 11, &membership).is_err(), "expired");
        assert_ne!(request.reference().unwrap(), [0; 32]);

        // A member cannot join again.
        let mut with_bob = tree.clone();
        with_bob
            .add_leaf(
                1,
                LeafNode {
                    device_pk: bob.public_key().to_vec(),
                    since: 1,
                    encryption_key: request.encryption_key.clone(),
                    admission_hash: request.admission.hash(),
                },
            )
            .unwrap();
        let membership = Membership::new(&with_bob, &registry);
        assert_eq!(
            request.authorize(&gid, 2, &membership),
            Err(CoreError::Invalid("joiner is already a member"))
        );

        // The admission must name the requesting device.
        let carol = DeviceIdentity::from_seed(&[5; 32]);
        let secrets = JoinSecrets::generate(&mut rng);
        assert_eq!(
            SignedJoinRequest::create(&carol, &secrets, &request.admission, &mut rng),
            Err(CoreError::Invalid("admission does not match the request"))
        );
        let mut tampered = request.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedJoinRequest::decode(&tampered).is_err());
        let reused = JoinSecrets {
            encryption_key: secrets.init_key.clone(),
            init_key: secrets.init_key.clone(),
        };
        assert_eq!(
            SignedJoinRequest::create(&bob, &reused, &request.admission, &mut rng),
            Err(CoreError::Invalid("join request reuses its leaf key"))
        );
        let restored = JoinSecrets::import(&secrets.export().unwrap()).unwrap();
        assert_eq!(restored.init_key.seed(), secrets.init_key.seed());
        assert!(JoinSecrets::import(&[0x80]).is_err());
        assert_eq!(format!("{secrets:?}"), "JoinSecrets(..)");
    }

    #[test]
    fn welcomes_open_only_with_the_init_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [3; 32];
        let (request, secrets) = request(&gid, &alice, &bob, &mut rng);
        let welcome = Welcome::seal(4, &request, &[9; 32], &mut rng).unwrap();
        let decoded = Welcome::decode(&welcome.encode().unwrap()).unwrap();
        assert_eq!(decoded, welcome);
        assert_eq!(*decoded.open(&secrets.init_key).unwrap(), [9; 32]);
        assert_eq!(
            decoded.open(&secrets.encryption_key).err(),
            Some(CoreError::Decrypt("welcome"))
        );
        // The epoch and the request are bound.
        let moved = Welcome {
            epoch: 5,
            ..welcome.clone()
        };
        assert!(moved.open(&secrets.init_key).is_err());
        let other = Welcome {
            request_ref: [0; 32],
            ..welcome.clone()
        };
        assert!(other.open(&secrets.init_key).is_err());
        let mut truncated = welcome.clone();
        truncated.wrapped_joiner_secret.pop();
        assert_eq!(
            Welcome::decode(&truncated.encode().unwrap()),
            Err(CoreError::Malformed("welcome ciphertext"))
        );
        assert!(Welcome::decode(&[0x80]).is_err());
    }
}
