#[cfg(test)]
use std::fs;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::barrier_shared::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    DEFAULT_BARRIER_N_MAX, TICKET_RETRY_MAX_ATTEMPTS, apply_join_set_to_snapshot,
    apply_revoked_set_to_snapshot, barrier_path_nodes, blank_leaf_and_path,
    collect_resolution_targets, compute_barrier_pkhash, compute_barrier_tree_hash,
    compute_revocation_roots_hash, expected_barrier_tree_nodes, should_retry_ticket_http_error,
    sibling_node, ticket_retry_delay,
};
#[cfg(test)]
use crate::message_crypto::{MSG_INDEX_REPLAY_WINDOW, decrypt_message_v2};
use crate::message_crypto::{MsgReplayState, PersistedMsgReplayState};
use ahash::AHashMap;
use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use anyhow::{Context as AnyhowContext, Result, anyhow};
use ciborium::value::{Integer, Value};
use cityg_api_client::{
    BarrierJoinRecord, BarrierPublicTree, CitygApiClient, Error as ApiClientError, MergeTicket,
    RoomAdminOperation, build_room_admin_listing_proof, build_room_admin_proof,
    build_room_admin_target_proof,
};
use cityg_client::witness::SrxInputsOwned;
use cityg_client::{CityGClient, ClientEpochBundle};
use cityg_config::CityGConfig;
use gpui::prelude::*;
#[cfg(not(test))]
use gpui::{
    App, Application, Bounds, TitlebarOptions, WindowBounds, WindowDecorations, WindowOptions, size,
};
use gpui::{
    ClipboardItem, Context as ViewContext, CursorStyle, Div, FontWeight, Keystroke, MouseButton,
    MouseDownEvent, Render, ScrollHandle, Task, Window, div, point, px, rgb,
};
use hex::{decode as hex_decode, encode as hex_encode};
use humantime::format_rfc3339_seconds;
use ml_kem::{
    ExpandedDecapsulationKey as MlKemExpandedDecapsulationKey, Seed as MlKemSeed,
    kem::{Decapsulate as MlKemDecapsulate, KeyExport as MlKemKeyExport},
    ml_kem_768,
    ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey,
};
use msphf_core::{
    ds, hash::h_l, hkdf::hkdf_blake3, merkle::canonical_set_root, serde_utils::to_cbor_vec,
};
use msphf_orchestrator::CapssWitnessBundle;
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode,
    OrchestrationParams, PivotParity, PopKeypair, SrxMode, compute_proofs_commit_bytes,
    derive_we_epoch_id, hdr,
};
use pqcrypto_dilithium::{
    dilithium3::{self},
    dilithium5,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::sleep;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use cityg_client::demo;

#[path = "native/barrier_core.rs"]
mod barrier_core;
#[path = "native/barrier_ops.rs"]
mod barrier_ops;
#[path = "native/chat_ui.rs"]
mod chat_ui;
#[path = "native/epoch_sync.rs"]
mod epoch_sync;
#[path = "native/errors.rs"]
mod errors;
#[path = "native/fault_injection.rs"]
mod fault_injection;
#[path = "native/helpers.rs"]
mod helpers;
#[path = "native/interactions.rs"]
mod interactions;
#[path = "native/join_form.rs"]
mod join_form;
#[path = "native/join_ops.rs"]
mod join_ops;
#[path = "native/lifecycle.rs"]
mod lifecycle;
#[path = "native/member_validation.rs"]
mod member_validation;
#[path = "native/members.rs"]
mod members;
#[path = "native/message_auth.rs"]
mod message_auth;
#[path = "native/network_ops.rs"]
mod network_ops;
#[path = "native/params.rs"]
mod params;
#[path = "native/persisted.rs"]
mod persisted;
#[path = "native/pivot_helpers.rs"]
mod pivot_helpers;
#[path = "native/render_panels.rs"]
mod render_panels;
#[path = "native/render_session.rs"]
mod render_session;
#[path = "native/room_admin.rs"]
mod room_admin;
#[path = "native/session_runtime.rs"]
mod session_runtime;
#[path = "native/session_state.rs"]
mod session_state;
#[path = "native/storage.rs"]
mod storage;
#[path = "native/tokio_bridge.rs"]
mod tokio_bridge;
#[path = "native/websocket.rs"]
mod websocket;

use barrier_core::*;
use barrier_ops::*;
use errors::*;
#[cfg(test)]
use fault_injection::*;
use helpers::*;
use join_form::*;
use join_ops::*;
use member_validation::*;
use message_auth::*;
use network_ops::*;
use params::*;
use persisted::*;
use pivot_helpers::*;
use storage::*;
use tokio_bridge::Tokio;

fn generate_vrf_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut rng = rng();
    rng.fill(&mut params_seed);
    rng.fill(&mut key_seed);
    let params = msphf_orchestrator::lb::generate_parameters(params_seed)
        .map_err(|err| anyhow!("generate VRF params: {err}"))?;
    msphf_orchestrator::lb::generate_keypair(&params, key_seed)
        .map_err(|err| anyhow!("generate VRF keypair: {err}"))
}

#[cfg(test)]
const DEFAULT_MAX_BARRIER_UPDATE_BYTES: u64 = 1_048_576;
const JOIN_INVITE_PREFIX: &str = "cityg-invite:";

fn is_refresh_pivot_conflict(status_code: u16, message: &str) -> bool {
    matches!(status_code, 409 | 500)
        && (message.contains("pivot head missing")
            || message.contains("refresh payload diverges from stored parity"))
}

fn try_recover_barrier_from_header_with_expected_before(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        expected_before_hash,
        false,
    )
}

/// Best-effort barrier recovery that skips local version progression and
/// hash-chain checks.  Used when the client is behind by multiple barrier
/// versions and cannot validate the chain, but can still attempt to decrypt
/// the barrier update using its leaf KEM key.
fn try_recover_barrier_best_effort(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
        true,
    )
}

fn apply_recovered_barrier_state(
    session: &mut AppSession,
    recovered: BarrierRecoverResult,
) -> Result<()> {
    let BarrierRecoverResult {
        k_barrier_new,
        k_fs_after_pcs,
        derived_node_key_material,
        ..
    } = recovered;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.k_barrier = k_barrier_new;
    for (node, material) in derived_node_key_material {
        session.barrier_state.dk_nodes.insert(node, material);
    }
    if let Some(k_fs_after_pcs) = k_fs_after_pcs {
        apply_forward_state_k_fs(session, *k_fs_after_pcs);
    }
    session.barrier_state.barrier_recovery_pending = false;
    Ok(())
}

fn enter_barrier_recovery_pending(session: &mut AppSession) -> Result<()> {
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.barrier_recovery_pending = true;
    Ok(())
}

fn try_recover_barrier_inner(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
    skip_local_checks: bool,
) -> Result<Option<BarrierRecoverResult>> {
    if max_barrier_update_bytes == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }

    let raw_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
        None => return Ok(None),
    };

    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)?;

    let valid_progression = (parsed.prev_barrier_version == 0 && parsed.barrier_version == 0)
        || parsed.prev_barrier_version.saturating_add(1) == parsed.barrier_version;
    if !valid_progression {
        return Err(anyhow!("barrier version progression is invalid"));
    }

    if !skip_local_checks {
        let local_barrier_version = session.barrier_state.barrier_version;
        let genesis_local_case = !session.barrier_state.barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        let valid_local_progression = genesis_local_case
            || (session.barrier_state.barrier_initialized
                && parsed.prev_barrier_version == local_barrier_version
                && parsed.barrier_version == local_barrier_version.saturating_add(1));
        if !valid_local_progression {
            return Err(anyhow!(
                "barrier version progression does not match local barrier state"
            ));
        }
    }

    if parsed.tree_size != n_max {
        return Err(anyhow!("barrier tree_size mismatch for local state"));
    }
    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| anyhow!("barrier_update_reason is missing or malformed"))?;

    if !skip_local_checks {
        let required_before_hash =
            expected_before_hash.unwrap_or(session.barrier_state.kem_tree_hash_after);
        if reason != 2 && parsed.kem_tree_hash_before != required_before_hash {
            return Err(anyhow!("barrier hash-chain before-hash mismatch"));
        }
    }

    let revoked_since_root = header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT)
        .ok_or_else(|| anyhow!("header revoked_since_prev_root is missing or malformed"))?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT)
        .ok_or_else(|| anyhow!("header revoked_root is missing or malformed"))?;
    let expected_rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != expected_rrh {
        return Err(anyhow!("barrier revocation_roots_hash mismatch"));
    }

    if !skip_local_checks {
        let genesis_local_case = !session.barrier_state.barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        if !genesis_local_case {
            if session.barrier_state.barrier_roots_hash == parsed.revocation_roots_hash {
                if !matches!(reason, 1 | 2) {
                    return Err(anyhow!(
                        "barrier_update_reason must be pcs_refresh (1) or join_finalize (2) when local barrier_roots_hash is unchanged"
                    ));
                }
            } else if reason != 0 {
                return Err(anyhow!(
                    "barrier_update_reason must be revocation_or_bootstrap (0) when local barrier_roots_hash changed"
                ));
            }
        }
    }

    let author_matches = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .map(|pk| pk == session.pop_public_key.as_slice())
        .unwrap_or(false);
    if author_matches && parsed.updater_leaf == session.barrier_state.cover_leaf_index {
        return Ok(None);
    }

    let self_path = self_path_nodes(n_max, session.barrier_state.cover_leaf_index);
    let self_path_set: HashSet<u64> = self_path.iter().copied().collect();
    let leaf_node = self_path
        .first()
        .copied()
        .ok_or_else(|| anyhow!("local self path is empty"))?;

    let mut matches: Vec<(u64, u64, [u8; 32])> = Vec::new();
    let mut candidate_decrypt_failure = false;
    for node in &parsed.node_ciphertexts {
        if !self_path_set.contains(&node.target_node) {
            continue;
        }

        let (dk_bytes, pkhash_t) = if node.target_node == leaf_node {
            (
                session.barrier_state.dk_leaf.as_slice(),
                session.barrier_state.pkhash_leaf,
            )
        } else if let Some(material) = session
            .barrier_state
            .dk_nodes
            .get(&(node.target_node as u32))
        {
            (material.dk.as_slice(), material.pkhash)
        } else {
            continue;
        };

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&pkhash_t[..16]);
        if target_prefix != node.target_pk_hash {
            continue;
        }

        let mut ss = if node.target_node == leaf_node {
            if dk_bytes.len() != kyber768::secret_key_bytes() {
                continue;
            }
            let ct = match kyber768::Ciphertext::from_bytes(node.kem_ct.as_slice()) {
                Ok(ct) => ct,
                Err(_) => continue,
            };
            let dk = match kyber768::SecretKey::from_bytes(dk_bytes) {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let shared = kyber768::decapsulate(&ct, &dk);
            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared.as_bytes());
            ss
        } else if dk_bytes.len() == ML_KEM_EXPANDED_DK_BYTES {
            match decapsulate_internal_node_shared_secret(dk_bytes, node.kem_ct.as_slice()) {
                Ok(ss) => ss,
                Err(_) => {
                    candidate_decrypt_failure = true;
                    continue;
                }
            }
        } else {
            candidate_decrypt_failure = true;
            continue;
        };

        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.updater_leaf,
            node.source_node,
            node.target_node,
            &pkhash_t,
        ))
        .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(node.source_node, node.target_node),
        )
        .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };
        let cipher = ChaCha20Poly1305::new((&ss).into());
        let mut plaintext = match cipher.decrypt(
            (&nonce).into(),
            Payload {
                msg: node.wrapped_ps.as_slice(),
                aad: aad.as_slice(),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                ss.zeroize();
                candidate_decrypt_failure = true;
                continue;
            }
        };
        ss.zeroize();
        if plaintext.len() != 32 {
            plaintext.zeroize();
            candidate_decrypt_failure = true;
            continue;
        }
        let mut path_secret = [0u8; 32];
        path_secret.copy_from_slice(plaintext.as_slice());
        plaintext.zeroize();
        matches.push((node.source_node, node.target_node, path_secret));
    }

    if matches.is_empty() {
        if candidate_decrypt_failure {
            return Err(anyhow!(
                "barrier recover rejected: candidate unwrap/decrypt failure (960.7)"
            ));
        }
        warn!(
            code = BARRIER_CODE_RECOVER_NO_MATCH,
            "barrier recover produced no matching ciphertext"
        );
        return Ok(None);
    }
    if matches.len() > 1 {
        for (_, _, secret) in &mut matches {
            secret.zeroize();
        }
        return Err(anyhow!("barrier recover rejected: multi-match (960.2)"));
    }

    let (source_node, target_node, source_secret) = matches.remove(0);
    if !self_path_set.contains(&source_node) || !self_path_set.contains(&target_node) {
        return Err(anyhow!(
            "barrier recover rejected: off-path source/target (960.7)"
        ));
    }
    let source_index = parsed
        .path_nodes
        .iter()
        .position(|node| *node == source_node)
        .ok_or_else(|| {
            anyhow!("barrier recover rejected: source missing from path_nodes (960.7)")
        })?;

    let mut path_secrets = BTreeMap::new();
    path_secrets.insert(source_node, source_secret);
    for k in (source_index + 1)..parsed.path_nodes.len() {
        let parent_node = parsed.path_nodes[k];
        let child_node = parsed.path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier recover missing child path secret"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier recover failed to derive root path secret"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(parsed.barrier_version, &parsed.revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier key salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let expected_node_set: HashSet<u64> = parsed.path_nodes.iter().copied().skip(1).collect();
    let mut derived_node_key_material = BTreeMap::new();
    for node in parsed.path_nodes.iter().copied().skip(source_index) {
        if node == leaf_node || !self_path_set.contains(&node) {
            continue;
        }
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("barrier recover missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            path_secret,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.tree_size,
            node,
        )?;
        if expected_node_set.contains(&node) {
            let announced_ek = parsed.new_public_keys.get(&node).ok_or_else(|| {
                anyhow!("barrier recover rejected: missing new_public_keys for node {node} (960.7)")
            })?;
            if announced_ek.as_slice() != ek_bytes.as_slice() {
                return Err(anyhow!(
                    "barrier recover rejected: new_public_keys mismatch for node {node} (960.7)"
                ));
            }
        }
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        derived_node_key_material.insert(
            node_index,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
    }

    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    let k_fs_after_pcs = if reason == Some(1) {
        let k_fs_before = session.forward_state.snapshot().k_fs;
        Some(derive_k_fs_after_pcs(
            &k_fs_before,
            weid,
            fs_ec,
            parsed.barrier_version,
            &k_barrier_new,
        )?)
    } else {
        None
    };

    zeroize_path_secret_map(&mut path_secrets);

    Ok(Some(BarrierRecoverResult {
        k_barrier_new: Zeroizing::new(k_barrier_new),
        kem_tree_hash_after: parsed.kem_tree_hash_after,
        k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
        derived_node_key_material,
    }))
}

#[cfg(test)]
fn try_recover_barrier_from_header(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_from_header_with_expected_before(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
    )
}

fn extract_barrier_update_digest(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    match header.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(raw)) => Ok(Some(compute_barrier_update_digest(raw)?)),
        Some(_) => Err(anyhow!("header barrier_update must be bytes")),
        None => Ok(None),
    }
}

fn apply_forward_state_k_fs(session: &mut AppSession, k_fs: [u8; 32]) {
    let snapshot = session.forward_state.snapshot();
    let mut updated_state = ForwardSecrecyState::with_state(
        k_fs,
        snapshot.fs_ec,
        session.fs_dev_prev_commit,
        session.we_epoch_id,
    );
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

fn apply_forward_state_snapshot(
    session: &mut AppSession,
    k_fs: [u8; 32],
    fs_ec: u64,
    fs_dev_commit: [u8; 32],
    last_weid: [u8; 32],
) {
    let mut updated_state = ForwardSecrecyState::with_state(k_fs, fs_ec, fs_dev_commit, last_weid);
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

fn bundle_authored_by_local_device(session: &AppSession, header: &BTreeMap<u64, Value>) -> bool {
    matches!(
        header.get(&hdr::HDR_POP_PK),
        Some(Value::Bytes(pop_pk)) if pop_pk.as_slice() == session.pop_public_key.as_slice()
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingBarrierHistoryOutcome {
    Unchanged,
    Activated([u8; 32]),
    Discarded,
}

fn apply_pending_barrier_activation(
    session: &mut AppSession,
    observed_barrier_version: u64,
    observed_fs_ec: Option<u64>,
    observed_barrier_update_reason: Option<u64>,
    accepted_digest: Option<[u8; 32]>,
) -> Result<bool> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(false);
    };

    if observed_barrier_version < pending.barrier_version {
        return Ok(false);
    }

    if let Some(digest) = accepted_digest
        && digest == pending.barrier_update_digest
        && observed_barrier_version == pending.barrier_version
        && observed_fs_ec == Some(pending.fs_ec)
        && observed_barrier_update_reason == pending.barrier_update_reason
    {
        let BarrierPendingState {
            barrier_version,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            next_forward_fs_ec,
            next_forward_fs_dev_commit,
            next_forward_last_weid,
            revocation_roots_hash,
            on_path_key_material,
            ..
        } = pending;
        session.barrier_state.barrier_initialized = true;
        session.barrier_state.barrier_version = barrier_version;
        session.barrier_state.barrier_roots_hash = revocation_roots_hash;
        session.barrier_state.k_barrier = k_barrier_new;
        session.barrier_state.kem_tree_hash_after = kem_tree_hash_after;
        for (node, material) in on_path_key_material {
            session.barrier_state.dk_nodes.insert(node, material);
        }
        let reseeded_k_fs = k_fs_after_pcs.as_deref().copied();
        if next_forward_fs_ec != 0 {
            let k_fs = reseeded_k_fs.unwrap_or_else(|| session.forward_state.snapshot().k_fs);
            apply_forward_state_snapshot(
                session,
                k_fs,
                next_forward_fs_ec,
                next_forward_fs_dev_commit,
                next_forward_last_weid,
            );
        } else if let Some(k_fs_after_pcs) = reseeded_k_fs {
            apply_forward_state_k_fs(session, k_fs_after_pcs);
        }
        #[cfg(test)]
        fault_injection::trigger_fault(
            FaultInjectionCutPoint::AfterAuthenticatedAcceptBeforePersist,
            None,
        )?;
        session.barrier_state.pending = None;
        session.barrier_state.barrier_recovery_pending = false;
        return Ok(true);
    }

    Ok(false)
}

async fn apply_pending_barrier_activation_from_history(
    client: &CitygApiClient,
    session: &mut AppSession,
    current_barrier_version: u64,
) -> Result<PendingBarrierHistoryOutcome> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    };

    if pending.we_epoch_id == [0u8; 32] {
        if current_barrier_version > pending.barrier_version {
            warn!(
                code = BARRIER_CODE_SNAPSHOT_AUTH_FAILURE,
                pending_barrier_version = pending.barrier_version,
                current_barrier_version,
                "pending barrier state predates pending we_epoch_id persistence; discarding after newer barrier version observed"
            );
            session.barrier_state.pending = None;
            return Ok(PendingBarrierHistoryOutcome::Discarded);
        }
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    }

    match client.get_bundle(&pending.we_epoch_id).await {
        Ok(bundle_response) => {
            let bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor).context(
                "decode accepted pending bundle for barrier activation correlation (960.9)",
            )?;
            let accepted_digest = extract_barrier_update_digest(&bundle.header_map)?.ok_or_else(|| {
                anyhow!(
                    "pending barrier activation history returned bundle without barrier_update (960.9)"
                )
            })?;
            let observed_barrier_version = header_u64(&bundle.header_map, hdr::HDR_BARRIER_VERSION)
                .ok_or_else(|| {
                    anyhow!("pending barrier activation history missing barrier_version (960.9)")
                })?;
            let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
            let observed_barrier_update_reason =
                header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
            if apply_pending_barrier_activation(
                session,
                observed_barrier_version,
                observed_fs_ec,
                observed_barrier_update_reason,
                Some(accepted_digest),
            )? {
                return Ok(PendingBarrierHistoryOutcome::Activated(bundle.we_epoch_id));
            }
            Err(anyhow!(
                "pending barrier activation history mismatch (960.9): accepted bundle did not match persisted pending state"
            ))
        }
        Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
            if current_barrier_version > pending.barrier_version {
                session.barrier_state.pending = None;
                return Ok(PendingBarrierHistoryOutcome::Discarded);
            }
            Ok(PendingBarrierHistoryOutcome::Unchanged)
        }
        Err(err) => Err(anyhow!(
            "pending barrier activation history lookup failed (960.9): {err}"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_barrier_update_bytes(
    gid: &[u8; 32],
    n_max: u64,
    updater_leaf: u64,
    barrier_version: u64,
    prev_barrier_version: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    snapshot_pre: &[Vec<u8>],
) -> Result<BarrierUpdateBuildResult> {
    if n_max == 0 || !n_max.is_power_of_two() || updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let expected_nodes = expected_barrier_tree_nodes(n_max)?;
    if snapshot_pre.len() != expected_nodes {
        return Err(anyhow!(
            "barrier snapshot size mismatch: expected {expected_nodes}, got {}",
            snapshot_pre.len()
        ));
    }

    let leaf_base = n_max.saturating_sub(1);
    let path_nodes = barrier_path_nodes(n_max, updater_leaf)?;

    let mut path_secrets = BTreeMap::new();
    let mut ps_leaf = [0u8; 32];
    rng().fill(&mut ps_leaf);
    path_secrets.insert(path_nodes[0], ps_leaf);
    ps_leaf.zeroize();
    for k in 1..path_nodes.len() {
        let parent_node = path_nodes[k];
        let child_node = path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier path secret derivation missing child"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree/path salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier path secret derivation missing root"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(barrier_version, &revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier/derive/salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let mut expected_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
    expected_nodes.sort_unstable();
    let mut on_path_key_material = BTreeMap::new();
    let mut new_public_keys = Vec::with_capacity(expected_nodes.len());
    for node in expected_nodes {
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            path_secret,
            barrier_version,
            &revocation_roots_hash,
            n_max,
            node,
        )?;
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        on_path_key_material.insert(
            node_index,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
        new_public_keys.push(NewPublicKeyWire(node, ek_bytes));
    }

    let mut snapshot_post = snapshot_pre.to_vec();
    for NewPublicKeyWire(node, ek) in &new_public_keys {
        let idx = usize::try_from(*node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot_post
            .get_mut(idx)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = ek.clone();
    }
    let kem_tree_hash_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

    let mut node_ciphertexts = Vec::new();
    for step in 0..path_nodes.len().saturating_sub(1) {
        let child_node = path_nodes[step];
        let source_node = path_nodes[step + 1];
        let sibling =
            sibling_node(child_node).ok_or_else(|| anyhow!("barrier sibling missing for root"))?;
        let mut targets = Vec::new();
        collect_resolution_targets(snapshot_pre, sibling, leaf_base, &mut targets)?;
        targets.sort_unstable();
        for target_node in targets {
            let target_index = usize::try_from(target_node)
                .map_err(|_| anyhow!("barrier node index out of range"))?;
            let target_pk = snapshot_pre
                .get(target_index)
                .ok_or_else(|| anyhow!("barrier node index out of range"))?;
            if target_pk.is_empty() {
                return Err(anyhow!("barrier resolution produced blank target node"));
            }
            let target_pkhash = compute_barrier_pkhash(target_pk.as_slice())?;
            let target_ek = kyber768::PublicKey::from_bytes(target_pk.as_slice())
                .map_err(|_| anyhow!("invalid ML-KEM target public key in snapshot_pre"))?;
            let (ss, kem_ct) = kyber768::encapsulate(&target_ek);
            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            let aad = to_cbor_vec(&BarrierWrapAadPreimage(
                gid,
                barrier_version,
                &revocation_roots_hash,
                updater_leaf,
                source_node,
                target_node,
                &target_pkhash,
            ))
            .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
            let nonce_full = h_l(
                "barrier/wrap/nonce",
                &BarrierWrapNoncePreimage(source_node, target_node),
            )
            .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_full[..12]);

            let source_secret = path_secrets
                .get(&source_node)
                .ok_or_else(|| anyhow!("missing path secret for source node {source_node}"))?;
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit, Payload},
            };
            let cipher = ChaCha20Poly1305::new((&ss_bytes).into());
            let wrapped_ps = match cipher.encrypt(
                (&nonce).into(),
                Payload {
                    msg: source_secret.as_slice(),
                    aad: aad.as_slice(),
                },
            ) {
                Ok(wrapped_ps) => wrapped_ps,
                Err(_) => {
                    ss_bytes.zeroize();
                    return Err(anyhow!("barrier wrap encrypt failed"));
                }
            };
            ss_bytes.zeroize();
            node_ciphertexts.push(NodeCiphertextWire(
                source_node,
                target_node,
                target_pkhash[..16].to_vec(),
                KemCiphertext::as_bytes(&kem_ct).to_vec(),
                wrapped_ps,
            ));
        }
    }
    node_ciphertexts.sort_by_key(|entry| (entry.0, entry.1));

    let cover_payload = KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover_payload).context("encode barrier cover payload")?;

    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        barrier_version,
        prev_barrier_version,
        n_max,
        revocation_roots_hash.to_vec(),
        kem_tree_hash_before.to_vec(),
        kem_tree_hash_after.to_vec(),
        cover_bytes,
    );
    let raw_update = to_cbor_vec(&update).context("encode barrier update")?;
    let barrier_update_digest = compute_barrier_update_digest(raw_update.as_slice())?;
    zeroize_path_secret_map(&mut path_secrets);
    Ok(BarrierUpdateBuildResult {
        raw_update,
        barrier_update_digest,
        kem_tree_hash_after,
        k_barrier_new: Zeroizing::new(k_barrier_new),
        on_path_key_material,
    })
}

#[cfg(not(test))]
pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    // Load configuration
    let config = match CityGConfig::load() {
        Ok(config) => {
            if let Err(e) = config.validate() {
                eprintln!("Configuration validation failed: {}", e);
                eprintln!("Please check your configuration and try again.");
                std::process::exit(1);
            }
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            warn!("Failed to load configuration: {}, using defaults", e);
            CityGConfig::default()
        }
    };

    Application::new().run(move |app: &mut App| {
        info!("Starting City-G GUI");
        tokio_bridge::init(app);

        let window_options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: None,
                appears_transparent: true,
                traffic_light_position: Some(point(px(12.0), px(12.0))),
            }),
            window_decorations: Some(WindowDecorations::Client),
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(
                    px(config.gui.default_window_width),
                    px(config.gui.default_window_height),
                ),
                app,
            ))),
            ..Default::default()
        };

        let config_clone = config.clone();
        let window_result = app.open_window(window_options, |_, cx| {
            let entity = cx.new(|_| AppModel::new(config_clone));
            let weak = entity.downgrade();

            cx.observe_keystrokes(move |event, _, cx| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |model, cx| {
                        model.on_keystroke(&event.keystroke, cx);
                    });
                }
            })
            .detach();

            entity
        });

        if let Err(e) = window_result {
            eprintln!("Failed to open application window: {}", e);
            eprintln!("Please check your display settings and try again.");
            std::process::exit(1);
        }

        app.activate(true);
    });
}

struct AppModel {
    config: CityGConfig,
    join_form: JoinFormState,
    join_status: JoinStatus,
    leave_status: LeaveStatus,
    session: Option<AppSession>,
    last_error: Option<String>,
    categorized_error: Option<CategorizedError>,
    info_message: Option<String>,
    toasts: Vec<Toast>,
    messages: Vec<ChatMessageEntry>,
    message_keys: HashSet<MessageKey>,
    next_pending_message_id: u64,
    fetch_status: FetchStatus,
    send_status: SendStatus,
    composer: MessageComposer,
    fetch_task: Option<Task<()>>,
    fetch_in_flight: bool,
    fetch_after_epoch_sync: bool,
    show_ciphertext: bool,
    members: Vec<MemberEntry>,
    members_status: MembersStatus,
    members_total: u64,
    members_next_offset: Option<u64>,
    members_loading_append: bool,
    members_auto_page: bool,
    members_alias_dirty: bool,
    members_mode: MembersMode,
    members_search: MembersSearchState,
    members_refresh_task: Option<Task<()>>,
    alias_bindings: AHashMap<String, AliasBindingRecord>,
    leaf_alias_index: AHashMap<[u8; 32], String>,
    room_admins: Vec<Vec<u8>>,
    room_admins_loaded: bool,
    room_admin_status: RoomAdminStatus,
    room_admin_target: RoomAdminTargetState,
    room_admin_revoke_confirmation: Option<Vec<u8>>,
    epoch_sync_task: Option<Task<()>>, // Background task for membership-driven epoch sync
    ws_task: Option<Task<()>>,         // WebSocket connection task
    ws_connected: bool,                // WebSocket connection status
    ws_autostart_attempted: bool,
    restore_epoch_sync_pending: bool,
    last_retry_action: Option<RetryAction>, // Track what action to retry
    security_events: Vec<SecurityEvent>,
    security_unread: u32,
    security_panel_expanded: bool,
    activity_events: Vec<ActivityEvent>,
    chat_scroll_handle: ScrollHandle,
    right_sidebar_scroll_handle: ScrollHandle,
}

enum JoinStatus {
    Idle,
    Joining,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaveStatus {
    Idle,
    Leaving,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FetchStatus {
    Idle,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendStatus {
    Idle,
    Sending,
}

#[derive(Clone, PartialEq, Eq)]
enum RoomAdminStatus {
    Idle,
    Loading(String),
    Error(String),
}

#[derive(Clone, PartialEq, Eq)]
enum MembersStatus {
    Idle,
    Loading(String),
    Error(String),
}

// Error categorization for user-friendly error handling
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorCategory {
    Network,
    Crypto,
    Policy,
    Server,
    Validation,
}

#[derive(Debug, Clone)]
struct CategorizedError {
    category: ErrorCategory,
    user_message: String,
    technical_details: String,
    recovery_suggestion: String,
    can_retry: bool,
}

impl CategorizedError {
    fn new(
        category: ErrorCategory,
        user_message: impl Into<String>,
        technical_details: impl Into<String>,
        recovery_suggestion: impl Into<String>,
        can_retry: bool,
    ) -> Self {
        Self {
            category,
            user_message: user_message.into(),
            technical_details: technical_details.into(),
            recovery_suggestion: recovery_suggestion.into(),
            can_retry,
        }
    }
}

// Toast notification system
#[derive(Debug, Clone, PartialEq)]
enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Debug, Clone)]
struct Toast {
    kind: ToastKind,
    message: String,
    created_at: SystemTime,
    duration_secs: u64,
}

impl Toast {
    fn success(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 4,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Error,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 6,
        }
    }

    fn info(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Info,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 3,
        }
    }

    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.created_at)
            .map(|d| d.as_secs() >= self.duration_secs)
            .unwrap_or(true)
    }
}

// Track which action can be retried
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryAction {
    Join,
    Send,
    Leave,
    Refresh,
}

#[derive(Clone, Default)]
struct MessageComposer {
    text: String,
    active: bool,
}

// Configuration constants have been moved to cityg_config
// These are kept as fallback if needed but should use config from AppModel

impl MessageComposer {
    fn clear(&mut self) {
        self.text.clear();
    }

    fn is_ready(&self) -> bool {
        !self.text.trim().is_empty()
    }

    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn set_text(&mut self, text: String) {
        self.text = text;
    }

    fn text(&self) -> &str {
        self.text.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            if self.is_ready() {
                return KeyOutcome::Submit;
            }
            return KeyOutcome::None;
        }

        if ks.key == "backspace" {
            if !self.text.is_empty() {
                self.text.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.text.is_empty() {
                self.text.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.text.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }
            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }
            self.text.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
struct MembersSearchState {
    query: String,
    active: bool,
}

impl MembersSearchState {
    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn clear(&mut self) {
        self.query.clear();
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
    }

    fn query(&self) -> &str {
        self.query.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if ks.key == "backspace" {
            if !self.query.is_empty() {
                self.query.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.query.is_empty() {
                self.query.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.query.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.query.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
struct RoomAdminTargetState {
    value: String,
    active: bool,
}

impl RoomAdminTargetState {
    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn clear(&mut self) {
        self.value.clear();
    }

    fn set_value(&mut self, value: String) {
        self.value = value;
    }

    fn value(&self) -> &str {
        self.value.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if ks.key == "backspace" {
            if !self.value.is_empty() {
                self.value.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.value.is_empty() {
                self.value.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.value.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.value.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
enum MembersMode {
    #[default]
    Full,
    Search {
        query: String,
    },
}

#[derive(Clone)]
struct SecurityEvent {
    alias: String,
    description: String,
    timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivityKind {
    Connection,
    Roster,
    Message,
    Sync,
    System,
}

#[derive(Clone, Debug)]
struct ActivityEvent {
    kind: ActivityKind,
    summary: String,
    detail: Option<String>,
    timestamp_ms: u64,
}

#[derive(Clone)]
struct ChatMessageEntry {
    sender_leaf: Option<[u8; 32]>,
    fallback_label: String,
    plaintext: String,
    ciphertext_hex: String,
    timestamp_ms: u64,
    delivery: MessageDelivery,
    pending_id: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MessageDelivery {
    Pending,
    Sent,
    Failed,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct MessageKey {
    ciphertext_hex: String,
    sender_leaf: Option<[u8; 32]>,
}

#[derive(Clone)]
struct MemberEntry {
    leaf_id: [u8; 32],
    alias: Option<String>,
    pop_public_key: Option<Vec<u8>>,
    join_timestamp_ms: Option<u64>,
    last_seen_timestamp_ms: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
struct AliasBindingRecord {
    pop_public_key: Vec<u8>,
    leaf_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoomIdentity {
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
}

#[derive(Clone)]
struct AppSession {
    server_url: String,
    room_id: String,
    alias: String,
    gid: [u8; 32],
    cat: [u8; 32],
    leaf_id: [u8; 32],
    parent_root: [u8; 32],
    join_delta_root: [u8; 32],
    revoked_since_root: [u8; 32],
    revoked_root: [u8; 32],
    regular_fingerprint: Option<[u8; 32]>,
    fs_fingerprint: Option<[u8; 32]>,
    tswe_salt_hash: [u8; 32],
    pox_r_commit: [u8; 32],
    we_epoch_id: [u8; 32],
    xk_hash: [u8; 32],
    epoch_key: [u8; 32],
    forward_state: ForwardSecrecyState,
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_prev_commit: [u8; 32],
    fs_epoch_created_at: SystemTime, // Timestamp when current epoch was created
    fs_epoch_rotation_interval_secs: u64, // Epoch rotation interval (default: 300 = 5 min)
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
    msg_sign_public_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    msg_sign_secret_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    kbroad_public: Vec<u8>,
    bootstrap_public: Vec<u8>,
    proof_mode: String,
    vrf_id: String,
    policy_version: String,
    msphf_crs_id: String,
    msphf_params_id: String,
    fs_policy_version: String,
    fs_epoch_base_ts: u64,
    last_fetch_timestamp_ms: Option<u64>,
    msg_replay_state: MsgReplayState,
    capss_witness: Vec<u8>,
    barrier_state: BarrierSecretState,
}

#[derive(Clone)]
struct BarrierSecretState {
    barrier_initialized: bool,
    barrier_version: u64,
    barrier_roots_hash: [u8; 32],
    k_barrier: Zeroizing<[u8; 32]>,
    kem_tree_hash_after: [u8; 32],
    max_barrier_update_bytes: u64,
    n_max: u64,
    cover_leaf_index: u64,
    dk_leaf: Zeroizing<Vec<u8>>,
    pkhash_leaf: [u8; 32],
    dk_nodes: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pending: Option<BarrierPendingState>,
    barrier_recovery_pending: bool,
}

impl Default for BarrierSecretState {
    fn default() -> Self {
        Self {
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            k_barrier: Zeroizing::new([0u8; 32]),
            kem_tree_hash_after: [0u8; 32],
            max_barrier_update_bytes: 0,
            n_max: DEFAULT_BARRIER_N_MAX,
            cover_leaf_index: 0,
            dk_leaf: Zeroizing::new(Vec::new()),
            pkhash_leaf: [0u8; 32],
            dk_nodes: BTreeMap::new(),
            pending: None,
            barrier_recovery_pending: false,
        }
    }
}

#[derive(Clone, Default, Debug)]
struct BarrierNodeKeyMaterial {
    dk: Zeroizing<Vec<u8>>,
    pkhash: [u8; 32],
}

impl Drop for BarrierNodeKeyMaterial {
    fn drop(&mut self) {
        self.dk.zeroize();
        self.pkhash.zeroize();
    }
}

#[derive(Clone, Default)]
struct BarrierPendingState {
    barrier_version: u64,
    we_epoch_id: [u8; 32],
    fs_ec: u64,
    next_forward_fs_ec: u64,
    next_forward_fs_dev_commit: [u8; 32],
    next_forward_last_weid: [u8; 32],
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    k_barrier_new: Zeroizing<[u8; 32]>,
    k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    barrier_update_reason: Option<u64>,
    barrier_update_digest: [u8; 32],
    on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone)]
struct PublishedBarrierMerge {
    bundle: ClientEpochBundle,
    pending_barrier_state: BarrierPendingState,
    forward_state_after: ForwardSecrecyState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BarrierMergeMode {
    PcsRefresh,
    JoinFinalize,
}

impl BarrierMergeMode {
    fn reason(self) -> u64 {
        match self {
            Self::PcsRefresh => 1,
            Self::JoinFinalize => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PcsRefresh => "refresh",
            Self::JoinFinalize => "join_finalize",
        }
    }

    fn publish_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "publish PCS refresh",
            Self::JoinFinalize => "publish join finalization barrier update",
        }
    }

    fn persist_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "persist refreshed room session",
            Self::JoinFinalize => "persist join-finalized room session",
        }
    }

    fn fallback_sync_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "recover initial barrier state after setup merge",
            Self::JoinFinalize => "recover barrier state after join finalization merge",
        }
    }

    fn still_pending_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "initial room setup completed but barrier recovery is still pending"
            }
            Self::JoinFinalize => {
                "join finalization completed but barrier recovery is still pending"
            }
        }
    }

    fn build_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "failed to build refresh merge bundle",
            Self::JoinFinalize => "failed to build join finalize merge bundle",
        }
    }

    fn accept_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "server rejected refresh merge bundle",
            Self::JoinFinalize => "server rejected join finalize merge bundle",
        }
    }

    fn pending_guard_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "cannot originate PCS refresh while barrier recovery is pending; complete FULL barrier recovery first"
            }
            Self::JoinFinalize => {
                "cannot originate join finalization while barrier recovery is pending without join-finalize eligibility"
            }
        }
    }

    fn reseeds_k_fs(self) -> bool {
        matches!(self, Self::PcsRefresh)
    }
}

impl AppModel {
    fn barrier_recovery_pending(&self) -> bool {
        self.session
            .as_ref()
            .map(|session| session.barrier_state.barrier_recovery_pending)
            .unwrap_or(false)
    }

    fn barrier_recovery_wait_message() -> &'static str {
        "Joined room. Waiting for barrier recovery before messaging."
    }

    fn new(config: CityGConfig) -> Self {
        let mut model = Self {
            config: config.clone(),
            join_form: JoinFormState {
                server: config.client.default_server_url.clone(),
                room_id: AppModel::random_room_id(),
                alias: String::new(),
                active: Some(ActiveField::Alias),
            },
            join_status: JoinStatus::Idle,
            leave_status: LeaveStatus::Idle,
            session: None,
            last_error: None,
            categorized_error: None,
            info_message: None,
            toasts: Vec::new(),
            messages: Vec::new(),
            message_keys: HashSet::new(),
            next_pending_message_id: 1,
            fetch_status: FetchStatus::Idle,
            send_status: SendStatus::Idle,
            composer: MessageComposer::default(),
            fetch_task: None,
            fetch_in_flight: false,
            fetch_after_epoch_sync: false,
            show_ciphertext: false,
            members: Vec::new(),
            members_status: MembersStatus::Idle,
            members_total: 0,
            members_next_offset: None,
            members_loading_append: false,
            members_auto_page: false,
            members_alias_dirty: false,
            members_mode: MembersMode::default(),
            members_search: MembersSearchState::default(),
            members_refresh_task: None,
            alias_bindings: AHashMap::new(),
            leaf_alias_index: AHashMap::new(),
            room_admins: Vec::new(),
            room_admins_loaded: false,
            room_admin_status: RoomAdminStatus::Idle,
            room_admin_target: RoomAdminTargetState::default(),
            room_admin_revoke_confirmation: None,
            epoch_sync_task: None,
            ws_task: None,
            ws_connected: false,
            ws_autostart_attempted: false,
            restore_epoch_sync_pending: false,
            last_retry_action: None,
            security_events: Vec::new(),
            security_unread: 0,
            security_panel_expanded: false,
            activity_events: Vec::new(),
            chat_scroll_handle: ScrollHandle::new(),
            right_sidebar_scroll_handle: ScrollHandle::new(),
        };

        match load_last_session() {
            Ok(Some(saved)) => {
                model.join_form.server = saved.server_url.clone();
                model.join_form.room_id = saved.room_id.clone();
                model.join_form.alias = saved.alias.clone();
                model.join_form.active = None;
                model.session = Some(saved);
                model.hydrate_alias_bindings_from_disk();
                model.load_security_events_from_disk();
                model.info_message = Some("Restored saved session.".to_string());
                model.fetch_status = FetchStatus::Idle;
                model.send_status = SendStatus::Idle;
                model.messages.clear();
                model.message_keys.clear();
                model.composer.clear();
                model.composer.blur();
                model.fetch_task = None;
                model.fetch_in_flight = false;
                model.fetch_after_epoch_sync = false;
                model.show_ciphertext = false;
                model.restore_epoch_sync_pending = true;
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to load saved session: {err:?}");
            }
        }

        model
    }
}

impl Render for AppModel {
    fn render(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) -> impl IntoElement {
        self.ensure_fetch_loop(cx);
        self.ensure_websocket_task(cx);
        self.ensure_epoch_sync_task(cx);
        self.ensure_members_refresh_task(cx);
        self.ensure_room_admins_loaded(cx);
        self.cleanup_expired_toasts();

        let background = rgb(0x0f1118);
        let has_session = self.session.is_some();
        let body: Div = if let Some(session) = &self.session {
            self.render_session(window, session, cx)
        } else {
            self.render_join(cx)
        };

        let mut root = div()
            .key_context("cityg-root")
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(background);

        if has_session {
            root = root.child(body);
        } else {
            root = root.items_center().justify_center().child(body);
        }

        // Add toast notifications overlay
        if let Some(toasts) = self.render_toasts() {
            root = root.child(toasts);
        }

        root
    }
}

impl AppModel {
    fn random_room_id() -> String {
        let mut bytes = [0u8; 32];
        rng().fill(&mut bytes);
        hex_encode(bytes)
    }

    fn toast_cleanup_delay() -> Duration {
        #[cfg(test)]
        {
            Duration::from_millis(1)
        }
        #[cfg(not(test))]
        {
            Duration::from_secs(8)
        }
    }

    // Toast notification helpers
    fn show_toast(&mut self, toast: Toast, cx: &mut ViewContext<Self>) {
        self.toasts.push(toast);
        cx.notify();

        let cleanup_delay = Self::toast_cleanup_delay();
        let delay = Tokio::spawn_result(cx, async move {
            sleep(cleanup_delay).await;
            Ok(())
        });

        // Schedule cleanup of expired toasts
        cx.spawn(async move |this, cx| {
            if let Err(err) = delay.await {
                warn!("toast cleanup delay task failed: {err}");
                return;
            }
            let _ = this.update(cx, |model, cx| {
                model.cleanup_expired_toasts();
                cx.notify();
            });
        })
        .detach();
    }

    fn show_success(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::success(message), cx);
    }

    fn show_error_toast(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::error(message), cx);
    }

    fn show_info(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::info(message), cx);
    }

    fn cleanup_expired_toasts(&mut self) {
        self.toasts.retain(|t| !t.is_expired());
    }

    // Set categorized error with automatic retry action tracking
    fn set_error(&mut self, err: &anyhow::Error, context: &str, retry_action: Option<RetryAction>) {
        let categorized = categorize_error(err, context);
        self.last_error = Some(categorized.user_message.clone());
        self.categorized_error = Some(categorized);
        self.last_retry_action = retry_action;
    }

    fn clear_error(&mut self) {
        self.last_error = None;
        self.categorized_error = None;
        self.last_retry_action = None;
    }

    // Render loading spinner with animated appearance
    fn render_spinner(&self) -> Div {
        div()
            .flex()
            .items_center()
            .gap(px(2.0))
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x72f88e))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x5fd87f))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x4cb86f))
                    .child("●"),
            )
    }

    // Render categorized error box with actions
    fn render_error_box(&self, cx: &mut ViewContext<Self>) -> Option<Div> {
        let error = self.categorized_error.as_ref()?;

        let (icon, color) = match error.category {
            ErrorCategory::Network => ("⚠", rgb(0xffa500)),
            ErrorCategory::Crypto => ("⚠", rgb(0xff6b6b)),
            ErrorCategory::Policy => ("⛔", rgb(0xff9f68)),
            ErrorCategory::Server => ("⚠", rgb(0xff6b6b)),
            ErrorCategory::Validation => ("ℹ", rgb(0x72a5f8)),
        };

        let mut error_box = div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(16.0))
            .py(px(14.0))
            .rounded(px(12.0))
            .bg(rgb(0x1f1f2e))
            .border_1()
            .border_color(color)
            .max_w(px(640.0))
            .child(
                div()
                    .flex()
                    .gap(px(8.0))
                    .items_center()
                    .child(div().text_size(px(18.0)).child(icon))
                    .child(
                        div()
                            .text_size(px(15.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(0xf2f4ff))
                            .child(error.user_message.clone()),
                    ),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(0x9aa5d3))
                    .child(error.recovery_suggestion.clone()),
            );

        // Add action buttons row
        let mut action_row = div().flex().flex_wrap().gap(px(8.0)).mt(px(4.0));

        // Primary action: Try Again (if retryable)
        if error.can_retry {
            action_row = action_row.child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x72f88e))
                    .text_color(rgb(0x0f1118))
                    .text_size(px(13.0))
                    .font_weight(FontWeight::MEDIUM)
                    .cursor(CursorStyle::PointingHand)
                    .child("Try Again")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_retry_clicked)),
            );
        }

        // Secondary actions
        action_row = action_row
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x2a3148))
                    .text_color(rgb(0xc8d0e8))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Copy Details")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_error_details)),
            )
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x2a3148))
                    .text_color(rgb(0xc8d0e8))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Report Issue")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_report_issue)),
            )
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x1f1f2e))
                    .text_color(rgb(0x9aa5d3))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Dismiss")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_dismiss_error)),
            );

        error_box = error_box.child(action_row);
        Some(error_box)
    }

    // Render toast notifications
    fn render_toasts(&self) -> Option<Div> {
        if self.toasts.is_empty() {
            return None;
        }

        let mut container = div()
            .absolute()
            .top(px(20.0))
            .right(px(20.0))
            .flex()
            .flex_col()
            .gap(px(8.0));

        for toast in &self.toasts {
            if !toast.is_expired() {
                let (icon, bg_color) = match toast.kind {
                    ToastKind::Success => ("✓", rgb(0x2d5f2d)),
                    ToastKind::Error => ("✗", rgb(0x5f2d2d)),
                    ToastKind::Info => ("ℹ", rgb(0x2d3d5f)),
                };

                container = container.child(
                    div()
                        .flex()
                        .gap(px(10.0))
                        .items_center()
                        .px(px(16.0))
                        .py(px(12.0))
                        .rounded(px(10.0))
                        .bg(bg_color)
                        .border_1()
                        .border_color(rgb(0x3a3a4f))
                        .child(
                            div()
                                .text_size(px(16.0))
                                .text_color(rgb(0xf2f4ff))
                                .child(icon),
                        )
                        .child(
                            div()
                                .text_size(px(14.0))
                                .text_color(rgb(0xf2f4ff))
                                .child(toast.message.clone()),
                        ),
                );
            }
        }

        Some(container)
    }

    fn render_join(&self, cx: &mut ViewContext<Self>) -> Div {
        let heading_color = rgb(0xf2f4ff);
        let subtext_color = rgb(0x9aa5d3);
        let error_color = rgb(0xff6b6b);
        let info_color = rgb(0x72f88e);
        let join_disabled =
            !self.join_form.is_ready() || matches!(self.join_status, JoinStatus::Joining);

        let form = div()
            .flex()
            .flex_col()
            .px(px(40.0))
            .py(px(36.0))
            .gap(px(16.0))
            .rounded(px(18.0))
            .bg(rgb(0x151929))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(28.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(heading_color)
                            .child("Join a City-G Room"),
                    )
                    .child(div().text_size(px(14.0)).text_color(subtext_color).child(
                        "Connect to a City-G server, pick your alias, and request a join ticket.",
                    )),
            )
            .child(self.render_field(
                "Server URL",
                &self.join_form.server,
                "https://server.example",
                ActiveField::Server,
                cx,
            ))
            .child(self.render_field(
                "Room ID",
                &self.join_form.room_id,
                "64 hex characters",
                ActiveField::Room,
                cx,
            ))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .text_size(px(12.0))
                    .text_color(subtext_color)
                    .child("Paste a City-G invite or enter a 64-character room ID.")
                    .child(
                        div()
                            .px(px(12.0))
                            .py(px(6.0))
                            .rounded(px(10.0))
                            .bg(rgb(0x2a3148))
                            .text_color(rgb(0xf2f4ff))
                            .cursor(CursorStyle::PointingHand)
                            .text_size(px(12.0))
                            .child("Generate new ID")
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(Self::on_generate_room_id),
                            ),
                    ),
            )
            .child(self.render_field(
                "Alias",
                &self.join_form.alias,
                "your name",
                ActiveField::Alias,
                cx,
            ))
            .child({
                let status_text = match self.join_status {
                    JoinStatus::Joining => Some("Requesting join ticket...".to_string()),
                    JoinStatus::Idle => None,
                };
                let mut status_div = div()
                    .flex()
                    .gap(px(6.0))
                    .items_center()
                    .text_size(px(13.0))
                    .text_color(subtext_color);
                if let Some(text) = status_text {
                    status_div = status_div.child(self.render_spinner()).child(text);
                }
                status_div
            })
            .child({
                let mut button = div()
                    .px(px(18.0))
                    .py(px(10.0))
                    .rounded(px(12.0))
                    .text_size(px(16.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(0x0f1118))
                    .bg(if join_disabled {
                        rgb(0x3a3f57)
                    } else {
                        rgb(0x72f88e)
                    })
                    .cursor(if join_disabled {
                        CursorStyle::Arrow
                    } else {
                        CursorStyle::PointingHand
                    })
                    .child(if matches!(self.join_status, JoinStatus::Joining) {
                        "Joining..."
                    } else {
                        "Join room"
                    });

                if !join_disabled {
                    button =
                        button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_join_clicked));
                }
                button
            });

        let mut root = div()
            .flex()
            .flex_col()
            .items_center()
            .gap(px(20.0))
            .child(form);

        // Show categorized error box if available
        if let Some(error_box) = self.render_error_box(cx) {
            root = root.child(error_box);
        } else if let Some(err) = &self.last_error {
            // Fallback to simple error message if no categorized error
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(error_color)
                    .child(format!("Join failed: {err}")),
            );
        }

        if let Some(info) = &self.info_message {
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(info_color)
                    .child(info.clone()),
            );
        }

        root
    }

    fn render_field(
        &self,
        label: &str,
        value: &str,
        placeholder: &str,
        field: ActiveField,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let is_active = self.join_form.active == Some(field);
        let border = if is_active {
            rgb(0x72f88e)
        } else {
            rgb(0x2a3148)
        };
        let background = if is_active {
            rgb(0x1b2135)
        } else {
            rgb(0x161b2a)
        };
        let text_color = if value.is_empty() {
            rgb(0x5b6584)
        } else {
            rgb(0xf5f7ff)
        };
        let display = if value.is_empty() {
            placeholder.to_string()
        } else {
            value.to_string()
        };

        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(0x9aa5d3))
                    .child(label.to_string()),
            )
            .child({
                let handler_field = field;
                div()
                    .px(px(14.0))
                    .py(px(10.0))
                    .rounded(px(12.0))
                    .border(px(1.0))
                    .border_color(border)
                    .bg(background)
                    .cursor(CursorStyle::IBeam)
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.focus_field(handler_field, cx);
                        }),
                    )
                    .child(
                        div()
                            .text_size(px(16.0))
                            .text_color(text_color)
                            .child(display),
                    )
            })
    }
}

const UI_CANVAS_BG: u32 = 0x111522;
const UI_SIDEBAR_BG: u32 = 0x151c2f;
const UI_PANEL_BG: u32 = 0x171f33;
const UI_ROW_BG: u32 = 0x1e2940;
const UI_PANEL_BORDER: u32 = 0x2e3d5b;
const UI_BUTTON_BG: u32 = 0x2c3956;
const UI_PANEL_TEXT: u32 = 0xf2f5ff;
const UI_SUBTLE_TEXT: u32 = 0x9eabd2;
const UI_MUTED_TEXT: u32 = 0x7180a5;
const UI_ACCENT_TEXT: u32 = 0x67f3b8;
const UI_ACCENT_BUTTON_TEXT: u32 = 0x122015;
const UI_WARN_TEXT: u32 = 0xffb384;
const BARRIER_HP_MODE: &str = "barrier-sealed-v1";
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::await_holding_lock,
    clippy::useless_conversion
)]
#[path = "native/tests/mod.rs"]
mod tests;
