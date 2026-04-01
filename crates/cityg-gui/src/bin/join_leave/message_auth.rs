use super::*;

pub(crate) const MESSAGE_PREFIX: &[u8; 4] = b"CGM1";
#[cfg(test)]
pub(crate) const MESSAGE_SENDER_DEVICE_PK_ALG: &str = "ML-DSA-65";

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct AuthenticatedMessage<'a> {
    pub(crate) timestamp_ms: u64,
    pub(crate) plaintext: &'a [u8],
    pub(crate) public_key: &'a [u8],
    pub(crate) signature: &'a [u8],
}

pub(crate) fn encode_authenticated_message(
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

pub(crate) fn sign_message(
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

#[cfg(test)]
pub(crate) fn decode_authenticated_message(data: &[u8]) -> Result<AuthenticatedMessage<'_>> {
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

#[cfg(test)]
pub(crate) fn verify_message_signature(
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

#[cfg(test)]
pub(crate) fn verify_sender_leaf_binding(
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
