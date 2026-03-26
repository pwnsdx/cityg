use super::*;

pub(super) const MESSAGE_PREFIX: &[u8; 4] = b"CGM1";
pub(super) const MESSAGE_SENDER_DEVICE_PK_ALG: &str = "ML-DSA-65";

#[derive(Debug)]
pub(super) struct AuthenticatedMessage<'a> {
    pub(super) timestamp_ms: u64,
    pub(super) plaintext: &'a [u8],
    pub(super) public_key: &'a [u8],
    pub(super) signature: &'a [u8],
}

pub(super) fn encode_authenticated_message(
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

pub(super) fn decode_authenticated_message(data: &[u8]) -> Result<AuthenticatedMessage<'_>> {
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

pub(super) fn sign_message(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let sk = dilithium3::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 secret key"))?;

    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);

    let signature = dilithium3::detached_sign(&payload, &sk);
    Ok(signature.as_bytes().to_vec())
}

pub(super) fn verify_message_signature(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 public key"))?;

    let signature = dilithium3::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 signature"))?;

    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);

    dilithium3::verify_detached_signature(&signature, &payload, &pk)
        .map_err(|_| anyhow!("signature verification failed"))?;

    Ok(())
}

pub(super) fn verify_sender_leaf_binding(
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

#[cfg(test)]
pub(super) fn encrypt_message(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
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

#[cfg(test)]
pub(super) fn decrypt_message(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
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

pub(super) fn encode_capss_witness(witness: &CapssWitnessBundle) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(witness, &mut buf).context("failed to encode CAPSS witness")?;
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
pub(super) fn decode_capss_witness(data: &[u8]) -> Result<CapssWitnessBundle> {
    ciborium::de::from_reader(data).context("failed to decode CAPSS witness")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_signing_and_verification() -> Result<(), Box<dyn std::error::Error>> {
        let (msg_sign_pk, msg_sign_sk) = dilithium3::keypair();
        let msg_sign_public_key = msg_sign_pk.as_bytes().to_vec();
        let msg_sign_secret_key = msg_sign_sk.as_bytes().to_vec();

        let leaf_id = [0x42u8; 32];
        let plaintext = b"Hello, authenticated world!";
        let timestamp_ms = 1_234_567_890u64;

        let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;

        let result = verify_message_signature(
            &leaf_id,
            timestamp_ms,
            plaintext,
            &signature,
            &msg_sign_public_key,
        );
        assert!(result.is_ok(), "signature verification should succeed");

        let wrong_plaintext = b"Wrong message";
        let result = verify_message_signature(
            &leaf_id,
            timestamp_ms,
            wrong_plaintext,
            &signature,
            &msg_sign_public_key,
        );
        assert!(
            result.is_err(),
            "verification should fail with wrong plaintext"
        );

        let wrong_timestamp = timestamp_ms + 1;
        let result = verify_message_signature(
            &leaf_id,
            wrong_timestamp,
            plaintext,
            &signature,
            &msg_sign_public_key,
        );
        assert!(
            result.is_err(),
            "verification should fail with wrong timestamp"
        );

        let wrong_leaf_id = [0x99u8; 32];
        let result = verify_message_signature(
            &wrong_leaf_id,
            timestamp_ms,
            plaintext,
            &signature,
            &msg_sign_public_key,
        );
        assert!(
            result.is_err(),
            "verification should fail with wrong leaf_id"
        );

        let mut corrupted_signature = signature.clone();
        corrupted_signature[100] ^= 0xFF;
        let result = verify_message_signature(
            &leaf_id,
            timestamp_ms,
            plaintext,
            &corrupted_signature,
            &msg_sign_public_key,
        );
        assert!(
            result.is_err(),
            "verification should fail with corrupted signature"
        );

        Ok(())
    }

    #[test]
    fn test_authenticated_message_format() -> Result<(), Box<dyn std::error::Error>> {
        let (msg_sign_pk, msg_sign_sk) = dilithium3::keypair();
        let msg_sign_public_key = msg_sign_pk.as_bytes().to_vec();
        let msg_sign_secret_key = msg_sign_sk.as_bytes().to_vec();

        let leaf_id = [0x42u8; 32];
        let plaintext = b"Test message";
        let timestamp_ms = 987_654_321u64;
        let epoch_key = [0x55u8; 32];

        let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;
        let authenticated_msg =
            encode_authenticated_message(timestamp_ms, plaintext, &msg_sign_public_key, &signature);

        let ciphertext = encrypt_message(&authenticated_msg, &epoch_key)?;
        let decrypted = decrypt_message(&ciphertext, &epoch_key)?;
        assert_eq!(decrypted, authenticated_msg);

        let envelope = decode_authenticated_message(&decrypted)?;
        assert_eq!(envelope.timestamp_ms, timestamp_ms);
        assert_eq!(envelope.plaintext, plaintext);
        assert_eq!(envelope.public_key, msg_sign_public_key.as_slice());
        assert_eq!(envelope.signature, signature.as_slice());

        verify_message_signature(
            &leaf_id,
            envelope.timestamp_ms,
            envelope.plaintext,
            envelope.signature,
            envelope.public_key,
        )?;

        Ok(())
    }

    #[test]
    fn test_message_authentication_prevents_spoofing() -> Result<(), Box<dyn std::error::Error>> {
        let (pk_alice, sk_alice) = dilithium3::keypair();
        let (pk_bob, _sk_bob) = dilithium3::keypair();

        let leaf_id_alice = [0x11u8; 32];
        let leaf_id_bob = [0x22u8; 32];
        let plaintext = b"Message from Alice";
        let timestamp_ms = 555_555_555u64;

        let signature = sign_message(&leaf_id_alice, timestamp_ms, plaintext, sk_alice.as_bytes())?;

        let result = verify_message_signature(
            &leaf_id_alice,
            timestamp_ms,
            plaintext,
            &signature,
            pk_alice.as_bytes(),
        );
        assert!(
            result.is_ok(),
            "Alice's signature should verify with Alice's key"
        );

        let result = verify_message_signature(
            &leaf_id_alice,
            timestamp_ms,
            plaintext,
            &signature,
            pk_bob.as_bytes(),
        );
        assert!(
            result.is_err(),
            "Alice's signature should NOT verify with Bob's key"
        );

        let result = verify_message_signature(
            &leaf_id_bob,
            timestamp_ms,
            plaintext,
            &signature,
            pk_alice.as_bytes(),
        );
        assert!(
            result.is_err(),
            "Cannot claim message is from Bob using Alice's signature"
        );

        let result = verify_message_signature(
            &leaf_id_alice,
            timestamp_ms + 1,
            plaintext,
            &signature,
            pk_alice.as_bytes(),
        );
        assert!(
            result.is_err(),
            "Verification should fail with wrong timestamp"
        );

        Ok(())
    }

    #[test]
    fn test_sender_leaf_binding_rejects_mismatched_public_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x44u8; 32];
        let (pk_alice, _sk_alice) = dilithium3::keypair();
        let (pk_bob, _sk_bob) = dilithium3::keypair();
        let alice_leaf = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid,
            MESSAGE_SENDER_DEVICE_PK_ALG,
            pk_alice.as_bytes(),
        )?;

        verify_sender_leaf_binding(&gid, &alice_leaf, pk_alice.as_bytes())?;
        assert!(
            verify_sender_leaf_binding(&gid, &alice_leaf, pk_bob.as_bytes()).is_err(),
            "a different authenticated sender public key must not bind to Alice's leaf"
        );

        Ok(())
    }

    #[test]
    fn test_sender_leaf_id_is_gid_scoped_and_stable_for_same_device()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid_a = [0x51u8; 32];
        let gid_b = [0x52u8; 32];
        let (pk_alice, _sk_alice) = dilithium3::keypair();

        let leaf_a_first = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid_a,
            MESSAGE_SENDER_DEVICE_PK_ALG,
            pk_alice.as_bytes(),
        )?;
        let leaf_a_second = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid_a,
            MESSAGE_SENDER_DEVICE_PK_ALG,
            pk_alice.as_bytes(),
        )?;
        let leaf_b = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid_b,
            MESSAGE_SENDER_DEVICE_PK_ALG,
            pk_alice.as_bytes(),
        )?;

        assert_eq!(
            leaf_a_first, leaf_a_second,
            "same gid + sender device key must re-derive the same sender leaf"
        );
        assert_ne!(
            leaf_a_first, leaf_b,
            "sender leaf derivation must stay gid-scoped"
        );

        Ok(())
    }

    #[test]
    fn test_message_format_size_constraints() -> Result<(), Box<dyn std::error::Error>> {
        const MLDSA65_PUBKEY_SIZE: usize = ml_dsa_public_key_bytes();
        const MLDSA65_SIG_SIZE: usize = ml_dsa_signature_bytes();
        const MIN_MSG_SIZE: usize =
            MESSAGE_PREFIX.len() + 8 + 4 + 4 + MLDSA65_PUBKEY_SIZE + 4 + MLDSA65_SIG_SIZE;

        assert_eq!(
            MIN_MSG_SIZE,
            4 + 8 + 4 + 4 + MLDSA65_PUBKEY_SIZE + 4 + MLDSA65_SIG_SIZE
        );

        let (pk, sk) = dilithium3::keypair();
        assert_eq!(pk.as_bytes().len(), MLDSA65_PUBKEY_SIZE);
        assert_eq!(
            sk.as_bytes().len(),
            4032,
            "ML-DSA-65 secret key is 4032 bytes"
        );

        let leaf_id = [0u8; 32];
        let plaintext = b"test";
        let sig = sign_message(&leaf_id, 42, plaintext, sk.as_bytes())?;
        assert_eq!(sig.len(), MLDSA65_SIG_SIZE);

        Ok(())
    }
}
