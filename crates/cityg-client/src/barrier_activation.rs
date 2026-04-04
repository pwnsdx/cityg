use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use ciborium::Value;
use msphf_orchestrator::{LeafIdMode, compute_fs_dev_commit_v2, compute_leaf_id, hdr};

use crate::barrier::{
    BarrierHistoryCommitment, header_history_commitment, require_same_history_commitment,
    verify_full_verification_receipt,
};
use crate::barrier_update::{
    compute_barrier_update_digest, normalize_max_barrier_update_bytes,
    parse_barrier_update_for_recover,
};

#[derive(Clone, Copy, Debug)]
pub struct ClientVisibleBarrierActivationInput<'a> {
    pub gid: &'a [u8; 32],
    pub local_pop_public_key: &'a [u8],
    pub local_current_history_commitment: Option<&'a BarrierHistoryCommitment>,
    pub local_current_history_view_id: [u8; 32],
    pub local_current_history_authority_extension_present: bool,
    pub local_current_global_history_attestation_bytes: &'a [u8],
    pub local_n_max: u64,
    pub local_max_barrier_update_bytes: u64,
    pub local_fs_policy_version: &'a str,
    pub local_fs_epoch_base_ts: u64,
    pub local_last_accepted_ec: u64,
    pub local_fs_ec: u64,
    pub local_fs_dev_prev_commit: [u8; 32],
    pub fs_forward_leap_h: u64,
    pub fs_forward_leap_checkpoint_interval: u64,
    pub fs_forward_leap_slack_anchor: u64,
    pub fs_forward_leap_slack_first_device: u64,
    pub fs_forward_leap_slack_device: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BarrierForwardLeapCaps {
    anchor_max: u64,
    first_device_max: u64,
    device_max: u64,
}

fn barrier_forward_leap_caps(
    input: &ClientVisibleBarrierActivationInput<'_>,
) -> Result<BarrierForwardLeapCaps> {
    if input.fs_forward_leap_h == 0
        || input.fs_forward_leap_checkpoint_interval == 0
        || input.fs_forward_leap_checkpoint_interval < input.fs_forward_leap_h
    {
        return Err(anyhow!(
            "client-side activation guard failed (948.0): invalid local fs policy window"
        ));
    }
    let window_periods = input
        .fs_forward_leap_checkpoint_interval
        .div_ceil(input.fs_forward_leap_h);
    Ok(BarrierForwardLeapCaps {
        anchor_max: window_periods.saturating_add(input.fs_forward_leap_slack_anchor),
        first_device_max: window_periods.saturating_add(input.fs_forward_leap_slack_first_device),
        device_max: window_periods.saturating_add(input.fs_forward_leap_slack_device),
    })
}

fn header_policy_version(header: &BTreeMap<u64, Value>, key: u64) -> Option<String> {
    match header.get(&key)? {
        Value::Text(text) => Some(text.clone()),
        Value::Integer(value) => u64::try_from(*value).ok().map(|v| v.to_string()),
        _ => None,
    }
}

fn header_u64(header: &BTreeMap<u64, Value>, key: u64) -> Option<u64> {
    match header.get(&key)? {
        Value::Integer(int) => (*int).try_into().ok(),
        _ => None,
    }
}

fn header_bytes32(header: &BTreeMap<u64, Value>, key: u64) -> Option<[u8; 32]> {
    match header.get(&key)? {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    }
}

pub fn extract_barrier_update_digest(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    match header.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(raw)) => Ok(Some(compute_barrier_update_digest(raw)?)),
        Some(_) => Err(anyhow!("header barrier_update must be bytes")),
        None => Ok(None),
    }
}

pub fn bundle_authored_by_local_device(
    local_pop_public_key: &[u8],
    header: &BTreeMap<u64, Value>,
) -> bool {
    matches!(
        header.get(&hdr::HDR_POP_PK),
        Some(Value::Bytes(pop_pk)) if pop_pk.as_slice() == local_pop_public_key
    )
}

pub fn validate_client_visible_activation_guards(
    input: ClientVisibleBarrierActivationInput<'_>,
    header_map: &BTreeMap<u64, Value>,
) -> Result<()> {
    let has_barrier_update = matches!(
        header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );
    let global_history_attestation = match header_map
        .get(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
    {
        Some(Value::Bytes(raw)) => Some(raw),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): header[182] global_history_attestation must be bytes"
            ));
        }
        None => None,
    };
    if !input
        .local_current_global_history_attestation_bytes
        .is_empty()
    {
        if !input.local_current_history_authority_extension_present {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): unsupported or missing history authority extension for local attested current state"
            ));
        }
        let supplied = global_history_attestation.ok_or_else(|| {
            anyhow!(
                "client-side activation guard failed (960.7): missing header[182] global_history_attestation for authority-bound barrier state"
            )
        })?;
        if supplied.as_slice() != input.local_current_global_history_attestation_bytes {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): header[182] global_history_attestation mismatch with local authenticated current state"
            ));
        }
    } else if global_history_attestation.is_some() && !has_barrier_update {
        return Err(anyhow!(
            "client-side activation guard failed (960.7): unexpected header[182] global_history_attestation without pinned local authority state"
        ));
    }
    if global_history_attestation.is_some()
        && !header_map.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
    {
        return Err(anyhow!(
            "client-side activation guard failed (960.7): missing header[181] full_verification_receipt for authority-bound barrier state"
        ));
    }
    if header_map.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        && global_history_attestation.is_none()
    {
        return Err(anyhow!(
            "client-side activation guard failed (960.7): header[181] full_verification_receipt requires header[182] global_history_attestation"
        ));
    }
    if let Some(global_history_attestation) = global_history_attestation {
        verify_client_visible_full_verification_receipt(
            &input,
            header_map,
            global_history_attestation.as_slice(),
        )?;
    }

    let fs_policy_version = header_policy_version(header_map, hdr::HDR_FS_POLICY_VERSION)
        .ok_or_else(|| {
            anyhow!("client-side activation guard failed (944.6): missing fs_policy_version")
        })?;
    if !input.local_fs_policy_version.is_empty()
        && fs_policy_version != input.local_fs_policy_version
    {
        return Err(anyhow!(
            "client-side activation guard failed (944.6): fs_policy_version mismatch"
        ));
    }
    let fs_epoch_base_ts = header_u64(header_map, hdr::HDR_FS_EPOCH_BASE_TS).ok_or_else(|| {
        anyhow!("client-side activation guard failed (945.0): missing fs_epoch_base_ts")
    })?;
    if input.local_fs_epoch_base_ts != 0 && fs_epoch_base_ts != input.local_fs_epoch_base_ts {
        return Err(anyhow!(
            "client-side activation guard failed (945.0): fs_epoch_base_ts mismatch"
        ));
    }

    let author_device_pk = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            anyhow!("client-side activation guard failed (947.2): missing author_device_pk")
        })?;
    let fs_ec = header_u64(header_map, hdr::HDR_FS_EC)
        .ok_or_else(|| anyhow!("client-side activation guard failed (947.2): missing fs_ec"))?;
    let fs_dev_prev_commit =
        header_bytes32(header_map, hdr::HDR_FS_DEV_PREV_COMMIT).ok_or_else(|| {
            anyhow!("client-side activation guard failed (947.2): missing fs_dev_prev_commit")
        })?;
    let fs_dev_commit = header_bytes32(header_map, hdr::HDR_FS_DEV_COMMIT).ok_or_else(|| {
        anyhow!("client-side activation guard failed (947.2): missing fs_dev_commit")
    })?;
    let barrier_version = header_u64(header_map, hdr::HDR_BARRIER_VERSION).ok_or_else(|| {
        anyhow!("client-side activation guard failed (947.2): missing barrier_version")
    })?;
    let barrier_update_digest = extract_barrier_update_digest(header_map)?.unwrap_or([0u8; 32]);
    let fs_caps = barrier_forward_leap_caps(&input)?;
    if fs_ec
        > input
            .local_last_accepted_ec
            .saturating_add(fs_caps.anchor_max)
    {
        return Err(anyhow!(
            "client-side activation guard failed (947.6): fs_ec exceeds local group forward-jump window"
        ));
    }
    if fs_dev_prev_commit == [0u8; 32] {
        if fs_ec
            > input
                .local_last_accepted_ec
                .saturating_add(fs_caps.first_device_max)
        {
            return Err(anyhow!(
                "client-side activation guard failed (947.5): new-device fs_ec exceeds local first-device forward-jump window"
            ));
        }
    } else if author_device_pk == input.local_pop_public_key
        && fs_ec > input.local_fs_ec.saturating_add(fs_caps.device_max)
    {
        return Err(anyhow!(
            "client-side activation guard failed (947.4): local device fs_ec exceeds local device forward-jump window"
        ));
    }
    let expected_fs_dev_commit = compute_fs_dev_commit_v2(
        author_device_pk,
        fs_ec,
        &fs_dev_prev_commit,
        barrier_version,
        &barrier_update_digest,
    )
    .map_err(|err| anyhow!("client-side activation guard failed (947.2): {err}"))?;
    if fs_dev_commit != expected_fs_dev_commit {
        return Err(anyhow!(
            "client-side activation guard failed (947.2): fs_dev_chain_bind mismatch"
        ));
    }

    if author_device_pk == input.local_pop_public_key
        && (fs_dev_prev_commit != input.local_fs_dev_prev_commit || fs_ec < input.local_fs_ec)
    {
        return Err(anyhow!(
            "client-side activation guard failed (947.0): local device chain continuity mismatch"
        ));
    }

    let Some(bundle_history_commitment) = header_history_commitment(header_map)? else {
        return Err(anyhow!(
            "client-side activation guard failed (960.9): missing barrier history commitment header"
        ));
    };
    let authored_by_local_device =
        bundle_authored_by_local_device(input.local_pop_public_key, header_map);
    if !authored_by_local_device {
        if let Some(current_history_commitment) = input.local_current_history_commitment {
            require_same_history_commitment(current_history_commitment, &bundle_history_commitment)
                .map_err(|_| {
                    anyhow!(
                        "client-side activation guard failed (960.9): bundle barrier history commitment mismatch with local authenticated current state"
                    )
                })?;
        } else if input.local_current_history_view_id != [0u8; 32]
            && bundle_history_commitment.history_view_id != input.local_current_history_view_id
        {
            return Err(anyhow!(
                "client-side activation guard failed (960.9): bundle barrier history commitment view mismatch"
            ));
        }
    }

    Ok(())
}

fn verify_client_visible_full_verification_receipt(
    input: &ClientVisibleBarrierActivationInput<'_>,
    header_map: &BTreeMap<u64, Value>,
    global_history_attestation: &[u8],
) -> Result<()> {
    let raw_receipt = match header_map.get(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): header[181] full_verification_receipt must be bytes"
            ));
        }
        None => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): missing header[181] full_verification_receipt for authority-bound barrier state"
            ));
        }
    };
    let raw_history_commitment = match header_map.get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): barrier history commitment header must be bytes"
            ));
        }
        None => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): missing barrier history commitment header for authority-bound barrier state"
            ));
        }
    };
    let raw_barrier_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): barrier_update must be bytes for authority-bound barrier state"
            ));
        }
        None => {
            return Err(anyhow!(
                "client-side activation guard failed (960.7): missing barrier_update for authority-bound barrier state"
            ));
        }
    };
    let barrier_update_reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| {
            anyhow!(
                "client-side activation guard failed (960.7): missing barrier_update_reason for authority-bound barrier state"
            )
        })?;
    let max_barrier_update_bytes = normalize_max_barrier_update_bytes(
        input
            .local_max_barrier_update_bytes
            .max(u64::try_from(raw_barrier_update.len()).unwrap_or(u64::MAX)),
    )
    .map_err(|err| anyhow!("client-side activation guard failed (960.7): {err}"))?;
    let parsed = parse_barrier_update_for_recover(
        raw_barrier_update,
        input.local_n_max,
        max_barrier_update_bytes,
    )
    .map_err(|err| {
        anyhow!(
            "client-side activation guard failed (960.7): invalid barrier_update for receipt verification: {err}"
        )
    })?;
    let author_device_pk = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            anyhow!("client-side activation guard failed (960.7): missing author_device_pk")
        })?;
    let author_leaf_id = compute_leaf_id(
        LeafIdMode::PerGroup,
        input.gid,
        "ML-DSA-65",
        author_device_pk,
    )
    .map_err(|err| {
        anyhow!("client-side activation guard failed (960.7): author leaf derivation failed: {err}")
    })?;
    verify_full_verification_receipt(
        raw_receipt,
        input.gid,
        &author_leaf_id,
        barrier_update_reason,
        parsed.updater_slot_index,
        None,
        raw_history_commitment,
        global_history_attestation,
        raw_barrier_update,
        author_device_pk,
    )
    .map_err(|err| {
        anyhow!(
            "client-side activation guard failed (960.7): invalid header[181] full_verification_receipt: {err}"
        )
    })
}
