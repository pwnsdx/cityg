#![forbid(unsafe_code)]

//! Worker-oriented runtime boundary for City-G.
//!
//! This crate intentionally starts small. Its current role is to define a
//! Worker-facing bootstrap surface around `cityg-server` without inheriting the
//! native runtime assumptions from `cityg-api`.

#[cfg(feature = "cloudflare")]
mod cloudflare;
mod do_store;
mod rehydrate;

use std::time::Duration;

use msphf_orchestrator::AcceptanceOptions;
#[cfg(feature = "cloudflare")]
use worker::wasm_bindgen;
#[cfg(feature = "cloudflare")]
use worker::{
    DurableObject, Env, Request, Response, Result as WorkerResult, State, WebSocket,
    WebSocketIncomingMessage, durable_object, event,
};

pub use cityg_runtime::{
    AcceptedBundleRecord, EpochLeafBindingRecord, EpochScopeRecord, MemberMetadataRecord,
    MemoryRoomStateStore, RoomSnapshot, RoomStateCheckpoint, RoomStateStore, RoomVolatileSnapshot,
    RuntimeRoom, StoredBundleRecord, aligned_fs_epoch_base_ts, lane_state_path,
    server_config_from_cityg_config, server_from_cityg_config, server_from_cityg_config_for_lane,
};
use cityg_server::{CityGServer, HistoryAuthorityMode, ServerConfig};
#[cfg(feature = "cloudflare")]
pub use cloudflare::{
    CLOUDFLARE_ALIAS_NAMESPACE_BINDING, CLOUDFLARE_ALIAS_ROUTE_PREFIX, CLOUDFLARE_POLICY_ROUTE,
    CLOUDFLARE_ROOM_NAMESPACE_BINDING, CLOUDFLARE_ROOM_REGISTRY_NAMESPACE_BINDING,
    CLOUDFLARE_ROOM_REGISTRY_ROUTE_PREFIX, CLOUDFLARE_ROOM_ROUTE_PREFIX,
    CLOUDFLARE_ROUTING_NAMESPACE_BINDING, CLOUDFLARE_ROUTING_ROUTE_PREFIX,
    CloudflareAliasDurableObject, CloudflareRoomDurableObject, CloudflareRoomRegistryDurableObject,
    CloudflareRoutingDurableObject, CloudflareSqlDurableObjectStorage,
    CloudflareWeEpochRoutingIndex, cloudflare_fetch,
};
pub use do_store::{
    DurableObjectRoomStateStore, DurableObjectRoomStateStoreError, DurableObjectStorage,
    MemoryDurableObjectStorage,
};
pub use rehydrate::{WorkerRoomRehydrationError, rehydrate_runtime_room_from_checkpoint};

/// Preferred room coordination model for Cloudflare-native deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomCoordinationModel {
    /// One authoritative Durable Object per room/gid.
    DurableObjectPerRoom,
    /// A fallback deployment shape backed by an external transactional store.
    ExternalTransactionalStore,
}

/// The recommended coordination model for the Worker migration.
pub const RECOMMENDED_COORDINATION_MODEL: RoomCoordinationModel =
    RoomCoordinationModel::DurableObjectPerRoom;

/// Optional Worker binding carrying a serialized `CityGConfig`.
pub const WORKER_CONFIG_JSON_ENV: &str = "CITYG_WORKER_CONFIG_JSON";
/// Optional Worker binding carrying a JSON array of legacy room gids to seed the room registry.
pub const WORKER_KNOWN_GIDS_JSON_ENV: &str = "CITYG_WORKER_KNOWN_GIDS_JSON";

/// Worker-facing selection for history authority behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WorkerHistoryAuthority {
    Disabled,
    Local,
    #[default]
    Global,
}

/// Minimal room bootstrap surface for a Worker-hosted room engine.
///
/// This intentionally excludes native-only concerns such as bind addresses or
/// filesystem journal paths. Cloudflare-specific storage will be introduced via
/// explicit adapters in a later step.
#[derive(Clone)]
pub struct WorkerRoomBootstrap {
    pub h_max: Option<usize>,
    pub window_ttl: Option<Duration>,
    pub history_authority: WorkerHistoryAuthority,
    pub fs_epoch_period_seconds: u64,
    pub acceptance_options: Option<AcceptanceOptions>,
}

impl Default for WorkerRoomBootstrap {
    fn default() -> Self {
        Self {
            h_max: None,
            window_ttl: None,
            history_authority: WorkerHistoryAuthority::Global,
            fs_epoch_period_seconds: 1,
            acceptance_options: None,
        }
    }
}

impl WorkerRoomBootstrap {
    /// Build a Worker bootstrap from the shared repository config shape.
    #[must_use]
    pub fn from_cityg_config(cfg: &cityg_config::CityGConfig) -> Self {
        let mut bootstrap = Self::from_server_config(&server_config_from_cityg_config(cfg));
        bootstrap.fs_epoch_period_seconds = cfg.protocol.fs_policy.h_seconds.max(1);
        bootstrap
    }

    /// Build a Worker bootstrap from an already-synthesized server config.
    #[must_use]
    pub fn from_server_config(config: &ServerConfig) -> Self {
        let history_authority = match config.history_authority.as_ref().map(|value| value.mode) {
            Some(HistoryAuthorityMode::Disabled) => WorkerHistoryAuthority::Disabled,
            Some(HistoryAuthorityMode::Local) => WorkerHistoryAuthority::Local,
            Some(HistoryAuthorityMode::Global) | None => WorkerHistoryAuthority::Global,
        };
        Self {
            h_max: config.h_max,
            window_ttl: config.window_ttl,
            history_authority,
            fs_epoch_period_seconds: 1,
            acceptance_options: config.acceptance_options.clone(),
        }
    }

    /// Parse a Worker bootstrap from serialized `CityGConfig` JSON.
    pub fn from_config_json(json: &str) -> serde_json::Result<Self> {
        let config = serde_json::from_str::<cityg_config::CityGConfig>(json)?;
        Ok(Self::from_cityg_config(&config))
    }

    /// Build the corresponding `cityg-server` configuration.
    #[must_use]
    pub fn to_server_config(&self) -> ServerConfig {
        let mut config = ServerConfig::new();
        config.h_max = self.h_max;
        config.window_ttl = self.window_ttl;
        config.acceptance_options = self.acceptance_options.clone();
        match self.history_authority {
            WorkerHistoryAuthority::Disabled => {
                config.history_authority = Some(cityg_server::HistoryAuthorityConfig {
                    mode: HistoryAuthorityMode::Disabled,
                    require_full_verification_receipt: false,
                });
            }
            WorkerHistoryAuthority::Local => config.enable_local_history_authority(),
            WorkerHistoryAuthority::Global => config.enable_global_history_authority(),
        }
        config
    }
}

/// Room-scoped engine that will eventually sit behind a Worker runtime adapter.
///
/// For now this wraps the shared `RuntimeRoom` core. That keeps the Worker path
/// aligned with the same room abstraction the native API is gradually moving
/// toward.
pub struct WorkerRoomEngine {
    room: RuntimeRoom,
}

impl WorkerRoomEngine {
    #[must_use]
    pub fn new(bootstrap: WorkerRoomBootstrap) -> Self {
        Self {
            room: RuntimeRoom::new(CityGServer::new(bootstrap.to_server_config())),
        }
    }

    #[must_use]
    pub fn server(&self) -> &CityGServer {
        self.room.server()
    }

    pub fn server_mut(&mut self) -> &mut CityGServer {
        self.room.server_mut()
    }

    #[must_use]
    pub fn room(&self) -> &RuntimeRoom {
        &self.room
    }

    pub fn room_mut(&mut self) -> &mut RuntimeRoom {
        &mut self.room
    }
}

#[cfg(feature = "cloudflare")]
#[event(fetch, respond_with_errors)]
pub async fn worker_fetch(req: Request, env: Env, _ctx: worker::Context) -> WorkerResult<Response> {
    cloudflare_fetch(req, env).await
}

#[cfg(feature = "cloudflare")]
#[durable_object]
pub struct CityGRoomDurableObject {
    inner: CloudflareRoomDurableObject,
}

#[cfg(feature = "cloudflare")]
impl DurableObject for CityGRoomDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            inner: CloudflareRoomDurableObject::new(state, env),
        }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        self.inner.fetch(req).await
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> WorkerResult<()> {
        self.inner.websocket_message(ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> WorkerResult<()> {
        self.inner
            .websocket_close(ws, code, reason, was_clean)
            .await
    }

    async fn websocket_error(&self, ws: WebSocket, error: worker::Error) -> WorkerResult<()> {
        self.inner.websocket_error(ws, error).await
    }
}

#[cfg(feature = "cloudflare")]
#[durable_object]
pub struct CityGRoutingDurableObject {
    inner: CloudflareRoutingDurableObject,
}

#[cfg(feature = "cloudflare")]
impl DurableObject for CityGRoutingDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            inner: CloudflareRoutingDurableObject::new(state, env),
        }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        self.inner.fetch(req).await
    }
}

#[cfg(feature = "cloudflare")]
#[durable_object]
pub struct CityGRoomRegistryDurableObject {
    inner: CloudflareRoomRegistryDurableObject,
}

#[cfg(feature = "cloudflare")]
impl DurableObject for CityGRoomRegistryDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            inner: CloudflareRoomRegistryDurableObject::new(state, env),
        }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        self.inner.fetch(req).await
    }
}

#[cfg(feature = "cloudflare")]
#[durable_object]
pub struct CityGAliasDurableObject {
    inner: CloudflareAliasDurableObject,
}

#[cfg(feature = "cloudflare")]
impl DurableObject for CityGAliasDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            inner: CloudflareAliasDurableObject::new(state, env),
        }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        self.inner.fetch(req).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn recommended_coordination_model_is_durable_object_per_room() {
        assert_eq!(
            RECOMMENDED_COORDINATION_MODEL,
            RoomCoordinationModel::DurableObjectPerRoom
        );
    }

    #[test]
    fn bootstrap_defaults_to_global_history_authority() {
        let config = WorkerRoomBootstrap::default().to_server_config();
        let authority = config.history_authority.expect("history authority");
        assert_eq!(authority.mode, HistoryAuthorityMode::Global);
        assert!(authority.require_full_verification_receipt);
    }

    #[test]
    fn bootstrap_can_disable_history_authority() {
        let config = WorkerRoomBootstrap {
            history_authority: WorkerHistoryAuthority::Disabled,
            ..WorkerRoomBootstrap::default()
        }
        .to_server_config();
        let authority = config.history_authority.expect("history authority");
        assert_eq!(authority.mode, HistoryAuthorityMode::Disabled);
        assert!(!authority.require_full_verification_receipt);
    }

    #[test]
    fn worker_room_engine_constructs_from_bootstrap() {
        let _engine = WorkerRoomEngine::new(WorkerRoomBootstrap {
            h_max: Some(8),
            window_ttl: Some(Duration::from_secs(45)),
            history_authority: WorkerHistoryAuthority::Local,
            fs_epoch_period_seconds: 60,
            acceptance_options: None,
        });
    }

    #[test]
    fn bootstrap_from_cityg_config_preserves_demo_acceptance_options() {
        let mut config = cityg_config::CityGConfig::default();
        config.server.seed_demo_room = true;
        let bootstrap = WorkerRoomBootstrap::from_cityg_config(&config);
        let acceptance = bootstrap
            .acceptance_options
            .expect("acceptance options should be set");

        match acceptance.bootstrap_policy {
            msphf_orchestrator::BootstrapPolicy::CaMlDsa { public_key } => {
                assert_eq!(public_key, cityg_client::demo::bootstrap_public());
            }
            _ => panic!("expected seeded demo bootstrap policy"),
        }
        let registry = acceptance.kbroad_registry.expect("kbroad registry");
        assert_eq!(
            registry.get(cityg_client::demo::DEMO_GID.as_slice()),
            Some(&cityg_client::demo::kbroad_public().to_vec())
        );
    }

    #[test]
    fn bootstrap_from_config_json_parses_serialized_cityg_config() {
        let mut config = cityg_config::CityGConfig::default();
        config.server.seed_demo_room = true;
        let json = serde_json::to_string(&config).expect("serialize config");

        let bootstrap = WorkerRoomBootstrap::from_config_json(&json).expect("parse config json");
        assert_eq!(bootstrap.h_max, Some(config.protocol.max_concurrent_heads));
        assert_eq!(
            bootstrap.window_ttl,
            Some(Duration::from_secs(config.server.window_ttl_secs))
        );
        assert!(bootstrap.acceptance_options.is_some());
    }
}
