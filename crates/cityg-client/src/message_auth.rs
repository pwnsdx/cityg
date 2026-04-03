use anyhow::{Context as AnyhowContext, Result, anyhow};
use msphf_orchestrator::{CapssWitnessBundle, LeafIdMode, compute_leaf_id};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumDetachedSignatureTrait, PublicKey as DilithiumPublicKeyTrait,
    SecretKey as DilithiumSecretKeyTrait,
};

pub const MESSAGE_PREFIX: &[u8; 4] = b"CGM1";
pub const MESSAGE_SENDER_DEVICE_PK_ALG: &str = "ML-DSA-65";

#[derive(Debug)]
pub struct AuthenticatedMessage<'a> {
    pub timestamp_ms: u64,
    pub plaintext: &'a [u8],
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIdentityBinding {
    pub alias: String,
    pub pop_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn encode_authenticated_message(
    timestamp_ms: u64,
    plaintext: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        MESSAGE_PREFIX.len() + 8 + 4 + plaintext.len() + 4 + public_key.len() + 4 + signature.len(),
    );
    out.extend_from_slice(MESSAGE_PREFIX);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    out.extend_from_slice(signature);
    out
}

pub fn decode_authenticated_message(data: &[u8]) -> Result<AuthenticatedMessage<'_>> {
    if data.len() < MESSAGE_PREFIX.len() + 8 + 4 + 4 + 4 {
        return Err(anyhow!("authenticated message too short"));
    }

    if &data[..MESSAGE_PREFIX.len()] != MESSAGE_PREFIX {
        return Err(anyhow!("invalid message prefix"));
    }

    let mut cursor = MESSAGE_PREFIX.len();

    let timestamp_ms = {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[cursor..cursor + 8]);
        cursor += 8;
        u64::from_le_bytes(buf)
    };

    let plaintext_len = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        u32::from_le_bytes(buf) as usize
    };
    if data.len() < cursor + plaintext_len {
        return Err(anyhow!("authenticated message truncated (plaintext)"));
    }
    let plaintext = &data[cursor..cursor + plaintext_len];
    cursor += plaintext_len;

    let public_key_len = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        u32::from_le_bytes(buf) as usize
    };
    if data.len() < cursor + public_key_len {
        return Err(anyhow!("authenticated message truncated (public key)"));
    }
    let public_key = &data[cursor..cursor + public_key_len];
    cursor += public_key_len;

    let signature_len = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        u32::from_le_bytes(buf) as usize
    };
    if data.len() != cursor + signature_len {
        return Err(anyhow!("authenticated message truncated (signature)"));
    }
    let signature = &data[cursor..];

    Ok(AuthenticatedMessage {
        timestamp_ms,
        plaintext,
        public_key,
        signature,
    })
}

pub fn generate_message_signing_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = dilithium5::keypair();
    (
        public_key.as_bytes().to_vec(),
        secret_key.as_bytes().to_vec(),
    )
}

pub fn message_signing_public_key_bytes() -> usize {
    dilithium5::public_key_bytes()
}

pub fn message_signature_bytes() -> usize {
    dilithium5::signature_bytes()
}

pub fn detached_sign_payload(payload: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 secret key"))?;
    Ok(dilithium5::detached_sign(payload, &sk).as_bytes().to_vec())
}

pub fn sign_message(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 secret key"))?;
    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);
    let signature = dilithium5::detached_sign(&payload, &sk);
    Ok(signature.as_bytes().to_vec())
}

pub fn verify_message_signature(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    let pk = dilithium5::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 public key"))?;
    let signature = dilithium5::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 signature"))?;

    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);

    dilithium5::verify_detached_signature(&signature, &payload, &pk)
        .map_err(|_| anyhow!("signature verification failed"))?;

    Ok(())
}

pub fn verify_sender_leaf_binding(
    gid: &[u8; 32],
    sender_leaf: &[u8; 32],
    public_key_bytes: &[u8],
) -> Result<()> {
    let derived_leaf = compute_leaf_id(
        LeafIdMode::PerGroup,
        gid,
        MESSAGE_SENDER_DEVICE_PK_ALG,
        public_key_bytes,
    )
    .map_err(|err| anyhow!("sender leaf derivation failed: {err}"))?;
    if &derived_leaf != sender_leaf {
        return Err(anyhow!(
            "sender leaf does not match authenticated sender public key"
        ));
    }
    Ok(())
}

pub fn sign_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<Vec<u8>> {
    use ciborium::ser::into_writer;
    use pqcrypto_traits::sign::DetachedSignature as _;
    use serde_bytes::ByteBuf;

    let pop_secret = dilithium5::SecretKey::from_bytes(pop_secret_key)
        .context("invalid persisted room identity secret key")?;
    let message_data = (
        ByteBuf::from(alias.as_bytes().to_vec()),
        ByteBuf::from(pop_public_key.to_vec()),
    );
    let mut message = Vec::new();
    into_writer(&message_data, &mut message)
        .context("failed to encode identity binding message")?;
    let signature = dilithium5::detached_sign(&message, &pop_secret);
    Ok(signature.as_bytes().to_vec())
}

pub fn build_signed_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<SignedIdentityBinding> {
    Ok(SignedIdentityBinding {
        alias: alias.to_string(),
        pop_public_key: pop_public_key.to_vec(),
        signature: sign_identity_binding(alias, pop_public_key, pop_secret_key)?,
    })
}

pub fn encrypt_message(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("encryption failed: {}", e))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_message(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };

    if data.len() < 12 {
        return Err(anyhow!(
            "ciphertext too short (need at least 12-byte nonce)"
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = nonce_bytes.into();
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("decryption failed: {}", e))
}

pub fn encode_capss_witness(witness: &CapssWitnessBundle) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(witness, &mut buf).context("failed to encode CAPSS witness")?;
    Ok(buf)
}

pub fn decode_capss_witness(data: &[u8]) -> Result<CapssWitnessBundle> {
    ciborium::de::from_reader(data).context("failed to decode CAPSS witness")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_message_roundtrips() -> Result<()> {
        let (pk, sk) = dilithium5::keypair();
        let leaf = [0x42; 32];
        let ts = 7u64;
        let payload = b"hello";
        let signature = sign_message(&leaf, ts, payload, sk.as_bytes())?;
        let encoded = encode_authenticated_message(ts, payload, pk.as_bytes(), &signature);
        let decoded = decode_authenticated_message(&encoded)?;
        assert_eq!(decoded.timestamp_ms, ts);
        assert_eq!(decoded.plaintext, payload);
        verify_message_signature(&leaf, ts, payload, decoded.signature, decoded.public_key)?;
        Ok(())
    }

    #[test]
    fn sender_leaf_binding_rejects_spoofed_key() {
        let gid = [0x11; 32];
        let (pk1, _) = dilithium5::keypair();
        let (pk2, _) = dilithium5::keypair();
        let leaf = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid,
            MESSAGE_SENDER_DEVICE_PK_ALG,
            pk1.as_bytes(),
        )
        .expect("leaf must derive");
        assert!(verify_sender_leaf_binding(&gid, &leaf, pk1.as_bytes()).is_ok());
        assert!(verify_sender_leaf_binding(&gid, &leaf, pk2.as_bytes()).is_err());
    }

    #[test]
    fn build_signed_identity_binding_roundtrips_fields() -> Result<()> {
        let (pk, sk) = dilithium5::keypair();
        let binding = build_signed_identity_binding("alice", pk.as_bytes(), sk.as_bytes())?;
        assert_eq!(binding.alias, "alice");
        assert_eq!(binding.pop_public_key, pk.as_bytes());
        assert!(!binding.signature.is_empty());
        Ok(())
    }

    #[test]
    fn generate_message_signing_keypair_uses_ml_dsa_lengths() {
        let (public_key, secret_key) = generate_message_signing_keypair();
        assert_eq!(public_key.len(), dilithium5::public_key_bytes());
        assert_eq!(secret_key.len(), dilithium5::secret_key_bytes());
    }
}
