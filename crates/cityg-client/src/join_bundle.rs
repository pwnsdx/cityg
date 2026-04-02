use std::{collections::BTreeMap, convert::TryInto};

use anyhow::{Result, anyhow};
use ciborium::value::Value;
use msphf_orchestrator::{AnchorInstanceParts, ForwardSecrecyState, OrchestrationParams, hdr};

use crate::{
    CityGClient, ClientEpochBundle,
    bundle_headers::{compute_fs_fingerprint_from_header, derive_fs_fingerprint_from_fields},
};

pub struct JoinEpochBundleInputs<'a> {
    pub header: BTreeMap<u64, Value>,
    pub parts: AnchorInstanceParts<'a>,
    pub params: OrchestrationParams<'a>,
    pub fs_state: &'a mut ForwardSecrecyState,
    pub witness_bytes: Option<&'a [u8]>,
    pub disable_autonomic_evolve: bool,
}

pub struct AcceptedBundleRuntimeState {
    pub fs_ec: u64,
    pub fs_epoch_commit: [u8; 32],
    pub fs_dev_prev_commit: Option<[u8; 32]>,
    pub fs_policy_version: String,
    pub fs_epoch_base_ts: u64,
    pub anchor_hdr_ctx: Vec<u8>,
    pub seed_ctx_hash: [u8; 32],
    pub seed_commit: [u8; 32],
    pub seed_bundle_commit: [u8; 32],
    pub fs_fingerprint: Option<[u8; 32]>,
}

fn header_required_u64(header: &BTreeMap<u64, Value>, key: u64, label: &str) -> Result<u64> {
    header
        .get(&key)
        .and_then(Value::as_integer)
        .ok_or_else(|| anyhow!("accepted bundle missing {label}"))?
        .try_into()
        .map_err(|_| anyhow!("{label} out of range"))
}

fn header_required_bytes32(
    header: &BTreeMap<u64, Value>,
    key: u64,
    label: &str,
) -> Result<[u8; 32]> {
    header
        .get(&key)
        .and_then(Value::as_bytes)
        .map(|bytes| bytes.as_slice())
        .ok_or_else(|| anyhow!("accepted bundle missing {label}"))?
        .try_into()
        .map_err(|_| anyhow!("{label} length"))
}

fn header_optional_u64(header: &BTreeMap<u64, Value>, key: u64) -> Option<u64> {
    header
        .get(&key)
        .and_then(Value::as_integer)
        .and_then(|value| value.try_into().ok())
}

fn header_optional_policy_version(header: &BTreeMap<u64, Value>, key: u64) -> Option<String> {
    match header.get(&key) {
        Some(Value::Text(text)) => Some(text.clone()),
        Some(Value::Integer(value)) => u64::try_from(*value).ok().map(|value| value.to_string()),
        _ => None,
    }
}

pub fn parse_accepted_bundle_runtime_state(
    bundle: &ClientEpochBundle,
    fs_policy_version: &str,
    fs_epoch_base_ts: u64,
) -> Result<AcceptedBundleRuntimeState> {
    let fs_ec = header_required_u64(&bundle.header_map, hdr::HDR_FS_EC, "fs_ec")?;
    let fs_epoch_commit = header_required_bytes32(
        &bundle.header_map,
        hdr::HDR_FS_EPOCH_COMMIT,
        "fs_epoch_commit",
    )?;
    let fs_dev_prev_commit = bundle
        .header_map
        .get(&hdr::HDR_FS_DEV_COMMIT)
        .or_else(|| bundle.header_map.get(&hdr::HDR_FS_DEV_PREV_COMMIT))
        .and_then(Value::as_bytes)
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("fs_dev commit length"))
        })
        .transpose()?;
    let fs_policy_version =
        header_optional_policy_version(&bundle.header_map, hdr::HDR_FS_POLICY_VERSION)
            .unwrap_or_else(|| fs_policy_version.to_string());
    let fs_epoch_base_ts = header_optional_u64(&bundle.header_map, hdr::HDR_FS_EPOCH_BASE_TS)
        .unwrap_or(fs_epoch_base_ts);

    Ok(AcceptedBundleRuntimeState {
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        fs_policy_version: fs_policy_version.clone(),
        fs_epoch_base_ts,
        anchor_hdr_ctx: bundle.anchor.anchor_hdr_ctx.clone(),
        seed_ctx_hash: bundle.hp_binding.seed_ctx_hash,
        seed_commit: bundle.hp_binding.seed_commit,
        seed_bundle_commit: bundle.hp_binding.seed_bundle_commit,
        fs_fingerprint: compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
            derive_fs_fingerprint_from_fields(
                fs_policy_version.as_str(),
                fs_ec,
                &fs_epoch_commit,
                fs_epoch_base_ts,
            )
        }),
    })
}

pub fn build_join_epoch_bundle(inputs: JoinEpochBundleInputs<'_>) -> Result<ClientEpochBundle> {
    let JoinEpochBundleInputs {
        header,
        parts,
        params,
        fs_state,
        witness_bytes,
        disable_autonomic_evolve,
    } = inputs;

    if disable_autonomic_evolve {
        Ok(CityGClient::generate_epoch_without_evolve(
            header,
            parts,
            params,
            fs_state,
            witness_bytes,
        )?)
    } else {
        Ok(CityGClient::generate_epoch(
            header,
            parts,
            params,
            fs_state,
            witness_bytes,
        )?)
    }
}
