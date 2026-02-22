#![cfg_attr(not(feature = "std"), no_std)]

pub mod kyber768 {
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::{
        kem::{
            Decapsulate as MlKemDecapsulate, Encapsulate as MlKemEncapsulate, Kem as MlKemKem,
            KeyExport as MlKemKeyExport,
        },
        ml_kem_768,
    };
    use pqcrypto_traits::{
        Error as PqError, Result as PqResult,
        kem::{
            Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
            SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
        },
    };

    const PUBLIC_KEY_BYTES: usize = 1184;
    const SECRET_KEY_BYTES: usize = 2400;
    const CIPHERTEXT_BYTES: usize = 1088;
    const SHARED_SECRET_BYTES: usize = 32;

    type MlKemPublicKey = ml_kem_768::EncapsulationKey;
    type MlKemSecretKey = ml_kem_768::DecapsulationKey;
    type MlKemCiphertext = ml_kem_768::Ciphertext;
    #[allow(deprecated)]
    type MlKemExpandedSecretKey = ml_kem_768::ExpandedDecapsulationKey;

    fn bad_length(name: &'static str, actual: usize, expected: usize) -> PqError {
        PqError::BadLength {
            name,
            actual,
            expected,
        }
    }

    fn decode_public_key(bytes: &[u8]) -> PqResult<(MlKemPublicKey, [u8; PUBLIC_KEY_BYTES])> {
        let raw: [u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| bad_length("kyber768::PublicKey", bytes.len(), PUBLIC_KEY_BYTES))?;
        let key_bytes: ml_kem::kem::Key<MlKemPublicKey> = raw.into();
        let inner = MlKemPublicKey::new(&key_bytes)
            .map_err(|_| bad_length("kyber768::PublicKey", bytes.len(), PUBLIC_KEY_BYTES))?;
        Ok((inner, raw))
    }

    fn decode_secret_key(bytes: &[u8]) -> PqResult<(MlKemSecretKey, [u8; SECRET_KEY_BYTES])> {
        let raw: [u8; SECRET_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| bad_length("kyber768::SecretKey", bytes.len(), SECRET_KEY_BYTES))?;
        #[allow(deprecated)]
        let expanded: MlKemExpandedSecretKey = raw.into();
        #[allow(deprecated)]
        let inner = <MlKemSecretKey as ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
            .map_err(|_| bad_length("kyber768::SecretKey", bytes.len(), SECRET_KEY_BYTES))?;
        Ok((inner, raw))
    }

    #[derive(Clone, Debug)]
    pub struct PublicKey {
        raw: [u8; PUBLIC_KEY_BYTES],
        inner: MlKemPublicKey,
    }

    impl PublicKey {
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        pub fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            <Self as KemPublicKeyTrait>::from_bytes(bytes)
        }
    }

    impl KemPublicKeyTrait for PublicKey {
        fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            let (inner, raw) = decode_public_key(bytes)?;
            Ok(Self { raw, inner })
        }
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    #[derive(Clone, Debug)]
    pub struct SecretKey {
        raw: [u8; SECRET_KEY_BYTES],
        inner: MlKemSecretKey,
    }

    impl SecretKey {
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        pub fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            <Self as KemSecretKeyTrait>::from_bytes(bytes)
        }
    }

    impl KemSecretKeyTrait for SecretKey {
        fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            let (inner, raw) = decode_secret_key(bytes)?;
            Ok(Self { raw, inner })
        }
    }

    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Ciphertext {
        raw: [u8; CIPHERTEXT_BYTES],
    }

    impl Ciphertext {
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        pub fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            <Self as KemCiphertextTrait>::from_bytes(bytes)
        }
    }

    impl KemCiphertextTrait for Ciphertext {
        fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            let raw: [u8; CIPHERTEXT_BYTES] = bytes
                .try_into()
                .map_err(|_| bad_length("kyber768::Ciphertext", bytes.len(), CIPHERTEXT_BYTES))?;
            Ok(Self { raw })
        }
    }

    impl AsRef<[u8]> for Ciphertext {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct SharedSecret {
        raw: [u8; SHARED_SECRET_BYTES],
    }

    impl SharedSecret {
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        pub fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            <Self as KemSharedSecretTrait>::from_bytes(bytes)
        }
    }

    impl KemSharedSecretTrait for SharedSecret {
        fn as_bytes(&self) -> &[u8] {
            self.raw.as_slice()
        }

        fn from_bytes(bytes: &[u8]) -> PqResult<Self> {
            let raw: [u8; SHARED_SECRET_BYTES] = bytes.try_into().map_err(|_| {
                bad_length("kyber768::SharedSecret", bytes.len(), SHARED_SECRET_BYTES)
            })?;
            Ok(Self { raw })
        }
    }

    impl AsRef<[u8]> for SharedSecret {
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    #[must_use]
    pub const fn public_key_bytes() -> usize {
        PUBLIC_KEY_BYTES
    }

    #[must_use]
    pub const fn secret_key_bytes() -> usize {
        SECRET_KEY_BYTES
    }

    #[must_use]
    pub const fn ciphertext_bytes() -> usize {
        CIPHERTEXT_BYTES
    }

    #[must_use]
    pub const fn shared_secret_bytes() -> usize {
        SHARED_SECRET_BYTES
    }

    #[must_use]
    pub fn keypair() -> (PublicKey, SecretKey) {
        let (dk, ek) = ml_kem_768::MlKem768::generate_keypair();

        let ek_bytes = ek.to_bytes();
        let mut pk_raw = [0u8; PUBLIC_KEY_BYTES];
        pk_raw.copy_from_slice(ek_bytes.as_slice());

        #[allow(deprecated)]
        let dk_expanded = <MlKemSecretKey as ExpandedKeyEncoding>::to_expanded_bytes(&dk);
        let mut sk_raw = [0u8; SECRET_KEY_BYTES];
        sk_raw.copy_from_slice(dk_expanded.as_slice());

        (
            PublicKey {
                raw: pk_raw,
                inner: ek,
            },
            SecretKey {
                raw: sk_raw,
                inner: dk,
            },
        )
    }

    #[must_use]
    pub fn encapsulate(public_key: &PublicKey) -> (SharedSecret, Ciphertext) {
        let (ct, ss) = public_key.inner.encapsulate();

        let mut ct_raw = [0u8; CIPHERTEXT_BYTES];
        ct_raw.copy_from_slice(ct.as_slice());
        let mut ss_raw = [0u8; SHARED_SECRET_BYTES];
        ss_raw.copy_from_slice(ss.as_slice());

        (SharedSecret { raw: ss_raw }, Ciphertext { raw: ct_raw })
    }

    #[must_use]
    pub fn decapsulate(ciphertext: &Ciphertext, secret_key: &SecretKey) -> SharedSecret {
        let ct: MlKemCiphertext = ciphertext.raw.into();
        let ss = secret_key.inner.decapsulate(&ct);

        let mut ss_raw = [0u8; SHARED_SECRET_BYTES];
        ss_raw.copy_from_slice(ss.as_slice());
        SharedSecret { raw: ss_raw }
    }
}
