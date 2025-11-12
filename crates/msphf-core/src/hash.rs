//! Normative BLAKE3-based hash utilities used across the msphf-we profile.

use blake3::Hasher;
use serde::Serialize;
use std::io::{self, Write};

use crate::{MsphfError, ds};

const CITY_G_PREFIX: &[u8] = b"city-g|";
const CITY_G_XOF_PREFIX: &[u8] = b"city-g|xof|";

struct HasherWriter<'a> {
    hasher: &'a mut Hasher,
}

impl Write for HasherWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hash_serialized<T: Serialize>(
    prefix: &[u8],
    label: &str,
    value: &T,
) -> Result<[u8; 32], MsphfError> {
    let mut hasher = Hasher::new();
    hasher.update(prefix);
    hasher.update(label.as_bytes());
    hasher.update(&[0u8]);
    {
        let mut writer = HasherWriter {
            hasher: &mut hasher,
        };
        ciborium::ser::into_writer(value, &mut writer).map_err(MsphfError::serialization)?;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    Ok(out)
}

/// Compute the normative `H_L(label, args[])` hash.
pub fn h_l<T: Serialize>(label: &str, args: &T) -> Result<[u8; 32], MsphfError> {
    hash_serialized(CITY_G_PREFIX, label, args)
}

#[derive(Serialize)]
struct ByteSlice<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

/// Compute the normative branch-bound hash `H_branch` as defined in the City‑G hash appendix.
pub fn h_branch_bytes(
    label: &str,
    branch: &str,
    crs_id: &str,
    params_id: &str,
    args: &[&[u8]],
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Branch<'a> {
        branch: &'a str,
        crs: &'a str,
        params: &'a str,
        #[serde(rename = "args")]
        args: Vec<ByteSlice<'a>>,
    }

    let args_wrapped = args.iter().map(|a| ByteSlice(a)).collect();
    h_l(
        label,
        &Branch {
            branch,
            crs: crs_id,
            params: params_id,
            args: args_wrapped,
        },
    )
}

/// Compute the normative `XOF(seed, ctx)` function (32-byte output).
pub fn xof32(ctx: &str, seed: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(CITY_G_XOF_PREFIX);
    hasher.update(ctx.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.fill(&mut out);
    out
}

/// Compute the epoch hash `H_epoch(X_k, Y)`.
pub fn h_epoch<X: Serialize, Y: Serialize>(xk: &X, y: &Y) -> Result<[u8; 32], MsphfError> {
    hash_serialized(CITY_G_PREFIX, ds::MSPHF_EPOCH, &(xk, y))
}

/// Compute the epoch identifier `eid := H_L("eid", [E_k])`.
pub fn eid_from_epoch(epoch_key: &[u8]) -> Result<[u8; 32], MsphfError> {
    // Encode as single-element array containing the raw bytes.
    #[derive(Serialize)]
    struct EpochRef<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    h_l(ds::MSPHF_EID, &EpochRef(epoch_key))
}

/// Convenience helper for hashing raw bytes with a DS label.
pub fn hash_bytes_with_label(label: &str, bytes: &[u8]) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Ref<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    h_l(label, &Ref(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Bytes<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    #[derive(Serialize)]
    struct PopMsg<'a> {
        #[serde(with = "serde_bytes")]
        xk: &'a [u8],
        #[serde(with = "serde_bytes")]
        leaf_id: &'a [u8],
        #[serde(with = "serde_bytes")]
        we_epoch_id: &'a [u8],
    }

    #[test]
    fn srx_commit_vector_matches_spec_label() {
        let payload = Bytes(b"srx-payload-v1");
        let digest = h_l(ds::MSPHF_SRX_COMMIT, &payload).expect("hash");
        assert_eq!(
            digest,
            hex_literal::hex!("cd11aac41451ec73113b9a813fbb43d6edfa0e6603092d7c34c2b64ac561b44e")
        );
    }

    #[test]
    fn pop_message_vector_matches_spec_label() {
        let xk = [0x11u8; 32];
        let leaf_id = [0x22u8; 32];
        let weid = [0x33u8; 32];
        let msg = PopMsg {
            xk: &xk,
            leaf_id: &leaf_id,
            we_epoch_id: &weid,
        };
        let digest = h_l(ds::MSPHF_POP_MSG, &msg).expect("hash");
        assert_eq!(
            digest,
            hex_literal::hex!("4f8dc3cd6a21308780ae7a6a3916ff1088b9370c9f4ca397694e451a8577bfaa")
        );
    }
}
