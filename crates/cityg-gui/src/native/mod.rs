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

mod activity_state;
mod app_shell;
mod barrier_core;
mod barrier_ops;
mod barrier_runtime;
mod chat_ui;
mod epoch_sync;
mod errors;
mod fault_injection;
mod helpers;
mod input_state;
mod interactions;
mod join_form;
mod join_ops;
mod lifecycle;
mod member_validation;
mod members;
mod message_auth;
mod network_ops;
mod params;
mod persisted;
mod pivot_helpers;
mod render_panels;
mod render_session;
mod room_admin;
mod session_runtime;
mod session_state;
mod session_types;
mod shell_ui;
mod state;
mod storage;
mod tokio_bridge;
mod websocket;

use activity_state::*;
use barrier_core::*;
use barrier_ops::*;
use barrier_runtime::*;
use errors::*;
#[cfg(test)]
use fault_injection::*;
use helpers::*;
use input_state::*;
use join_form::*;
use join_ops::*;
use member_validation::*;
use message_auth::*;
use network_ops::*;
use params::*;
use persisted::*;
use pivot_helpers::*;
use session_types::*;
use shell_ui::*;
use state::*;
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

#[cfg(not(test))]
pub fn main() {
    app_shell::run_native_app();
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::await_holding_lock,
    clippy::useless_conversion
)]
mod tests;
