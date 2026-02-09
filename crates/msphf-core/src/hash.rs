//! Normative BLAKE3-based hash utilities used across the msphf-we profile.

use blake3::Hasher;
use serde::Serialize;
use std::io::{self, Write};

use crate::{MsphfError, ds};

const CITY_G_PREFIX: &[u8] = b"city-g|";
const CITY_G_XOF_PREFIX: &[u8] = b"city-g|xof|";
const CITY_G_HL_DERIVE_CTX: &str = "city-g|h_l|v1";
const CITY_G_XOF_DERIVE_CTX: &str = "city-g|xof32|v1";

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

/// Validate that a label does not collide with a sibling namespace.
///
/// Rejected labels:
/// - Labels starting with `"xof|"` (would alias the `city-g|xof|` prefix)
/// - Labels containing embedded NUL bytes (would truncate the label at the
///   separator)
fn validate_label(label: &str) -> Result<(), MsphfError> {
    if label.starts_with("xof|") {
        return Err(MsphfError::invalid_input(
            "label must not start with 'xof|' (reserved for XOF namespace)",
        ));
    }
    if label.as_bytes().contains(&0u8) {
        return Err(MsphfError::invalid_input(
            "label must not contain embedded NUL bytes",
        ));
    }
    Ok(())
}

fn hash_serialized<T: Serialize>(
    prefix: &[u8],
    label: &str,
    value: &T,
) -> Result<[u8; 32], MsphfError> {
    validate_label(label)?;
    let mut hasher = Hasher::new_derive_key(CITY_G_HL_DERIVE_CTX);
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
///
/// # Panics
///
/// Panics if `ctx` contains embedded NUL bytes, which would corrupt the
/// label separator.
pub fn xof32(ctx: &str, seed: &[u8]) -> [u8; 32] {
    assert!(
        !ctx.as_bytes().contains(&0u8),
        "xof32 ctx must not contain embedded NUL bytes"
    );
    let mut hasher = Hasher::new_derive_key(CITY_G_XOF_DERIVE_CTX);
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
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
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
        let digest = match h_l(ds::MSPHF_SRX_COMMIT, &payload) {
            Ok(d) => d,
            Err(_) => unreachable!("hash should not fail"),
        };
        assert_eq!(
            digest,
            hex_literal::hex!("f928a6588b48066df20b459d2d652f12eae569aa26b7562558d5f79b2eef4aa4")
        );
    }

    #[test]
    fn h_l_rejects_xof_prefix_label() {
        let result = h_l("xof|sneaky", &42u64);
        assert!(
            result.is_err(),
            "labels starting with 'xof|' must be rejected"
        );
    }

    #[test]
    fn h_l_rejects_embedded_nul() {
        let result = h_l("label\0extra", &42u64);
        assert!(result.is_err(), "labels with embedded NUL must be rejected");
    }

    #[test]
    #[should_panic(expected = "NUL")]
    fn xof32_rejects_nul_ctx() {
        xof32("ctx\0bad", &[1, 2, 3]);
    }

    #[test]
    fn h_l_and_xof32_produce_different_digests() {
        // Even for the same label suffix and payload, the two functions
        // must produce distinct outputs because they live in different
        // prefix namespaces.
        let label = "test-label";
        let seed = &[0xAB; 32];
        let h_l_digest = h_l(label, &Bytes(seed)).expect("h_l should succeed");
        let xof_digest = xof32(label, seed);
        assert_ne!(
            h_l_digest, xof_digest,
            "h_l and xof32 must be in separate domains"
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
        let digest = match h_l(ds::MSPHF_POP_MSG, &msg) {
            Ok(d) => d,
            Err(_) => unreachable!("hash should not fail"),
        };
        assert_eq!(
            digest,
            hex_literal::hex!("4c113375085ed2fe93883a4d4fb753aeb2fe16f5d5985713fa5963bf8f1348b4")
        );
    }

    #[test]
    fn h_l_uses_derive_key_mode() {
        let payload = Bytes(b"derive-key-check");
        let derived = h_l(ds::MSPHF_SRX_COMMIT, &payload).expect("h_l should succeed");

        let mut plain = Hasher::new();
        plain.update(CITY_G_PREFIX);
        plain.update(ds::MSPHF_SRX_COMMIT.as_bytes());
        plain.update(&[0u8]);
        {
            let mut writer = HasherWriter { hasher: &mut plain };
            ciborium::ser::into_writer(&payload, &mut writer).expect("serialize payload");
        }
        let mut plain_out = [0u8; 32];
        plain_out.copy_from_slice(plain.finalize().as_bytes());

        assert_ne!(
            derived, plain_out,
            "h_l must use derive_key mode and not plain BLAKE3 mode"
        );
    }

    #[test]
    fn xof32_uses_derive_key_mode() {
        let ctx = "derive-key-check";
        let seed = [0xABu8; 32];
        let derived = xof32(ctx, &seed);

        let mut plain = Hasher::new();
        plain.update(CITY_G_XOF_PREFIX);
        plain.update(ctx.as_bytes());
        plain.update(&[0u8]);
        plain.update(&seed);
        let mut reader = plain.finalize_xof();
        let mut plain_out = [0u8; 32];
        reader.fill(&mut plain_out);

        assert_ne!(
            derived, plain_out,
            "xof32 must use derive_key mode and not plain BLAKE3 mode"
        );
    }
}
