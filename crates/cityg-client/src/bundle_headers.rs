use anyhow::{Context as AnyhowContext, Result, anyhow};
use ciborium::value::Value;
use msphf_core::{ds, hash::h_l};
use msphf_orchestrator::{compute_proofs_commit_bytes, hdr};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct FsFingerprintInputs<'a> {
    fs_policy_version: &'a str,
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    fs_epoch_commit: &'a [u8],
    fs_epoch_base_ts: u64,
}

pub fn derive_fs_fingerprint_from_fields(
    fs_policy_version: &str,
    fs_ec: u64,
    fs_epoch_commit: &[u8; 32],
    fs_epoch_base_ts: u64,
) -> Option<[u8; 32]> {
    let inputs = FsFingerprintInputs {
        fs_policy_version,
        fs_ec,
        fs_epoch_commit,
        fs_epoch_base_ts,
    };
    h_l("fs/fingerprint", &inputs).ok()
}

pub fn compute_fs_fingerprint_from_header(header: &BTreeMap<u64, Value>) -> Option<[u8; 32]> {
    let policy = match header.get(&hdr::HDR_FS_POLICY_VERSION)? {
        Value::Text(text) => text.clone(),
        Value::Integer(value) => u64::try_from(*value).ok()?.to_string(),
        _ => return None,
    };
    let fs_ec = match header.get(&hdr::HDR_FS_EC)? {
        Value::Integer(int) => (*int).try_into().ok()?,
        _ => return None,
    };
    let fs_epoch_commit = match header.get(&hdr::HDR_FS_EPOCH_COMMIT)? {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok()?,
        _ => return None,
    };
    let fs_epoch_base_ts = match header.get(&hdr::HDR_FS_EPOCH_BASE_TS)? {
        Value::Integer(int) => (*int).try_into().ok()?,
        _ => return None,
    };
    derive_fs_fingerprint_from_fields(policy.as_str(), fs_ec, &fs_epoch_commit, fs_epoch_base_ts)
}

pub fn recompute_proofs_commit(header: &BTreeMap<u64, Value>) -> Result<[u8; 32]> {
    let vrf = header_bytes(header, hdr::HDR_VRF_PROOF, "vrf_proof")?;
    let fs = header_bytes(header, hdr::HDR_FS_CAPSS, "fs_capss")?;
    let srx_root = header_bytes32_opt(header, hdr::HDR_SRX_ROOT_SW)?;
    let srx_smallwood = header_bytes_opt(header, hdr::HDR_SRX_SMALLWOOD)?;
    compute_proofs_commit_bytes(
        &vrf,
        &fs,
        srx_root.as_ref().map(|arr| arr.as_slice()),
        srx_smallwood.as_deref(),
    )
    .map_err(|err| anyhow!("compute proofs commit: {err}"))
}

pub fn recompute_srx_commit(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    let payload = match header.get(&hdr::HDR_SRX_PAYLOAD) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(Value::Null) | None => return Ok(None),
        Some(_) => return Err(anyhow!("srx_payload must be bytes")),
    };

    #[derive(Serialize)]
    struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    let commit = h_l(ds::MSPHF_SRX_COMMIT, &SrxCommit(payload)).context("compute srx commit")?;
    Ok(Some(commit))
}

fn header_bytes(header: &BTreeMap<u64, Value>, key: u64, label: &'static str) -> Result<Vec<u8>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(anyhow!("{label} must be bytes")),
        None => Err(anyhow!("{label} missing")),
    }
}

fn header_bytes_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<Vec<u8>>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

fn header_bytes32_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<[u8; 32]>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(Some(arr))
        }
        Some(Value::Bytes(_)) => Err(anyhow!("header {key} must be 32 bytes")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use ciborium::value::Integer;

    #[test]
    fn fs_fingerprint_roundtrips_header_fields() {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_FS_POLICY_VERSION, Value::Text("7".to_string()));
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(21u64)));
        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes(vec![0xAB; 32]));
        header.insert(
            hdr::HDR_FS_EPOCH_BASE_TS,
            Value::Integer(Integer::from(777u64)),
        );

        let direct = derive_fs_fingerprint_from_fields("7", 21, &[0xAB; 32], 777);
        let from_header = compute_fs_fingerprint_from_header(&header);
        assert_eq!(direct, from_header);
    }

    #[test]
    fn recompute_srx_commit_none_when_missing() -> Result<()> {
        let header = BTreeMap::new();
        assert!(recompute_srx_commit(&header)?.is_none());
        Ok(())
    }
}
