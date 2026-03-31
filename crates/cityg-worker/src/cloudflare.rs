use std::{
    cell::RefCell,
    collections::VecDeque,
    convert::TryInto,
    time::{Duration, SystemTime},
};

use cityg_api_schema::{
    API_PROFILE_VERSION, BundleCborRequestDecodeError, ExpelMemberTicketRequestValidationError,
    FetchMessagesRequestValidationError, FetchPublicTreeRequestDecodeError,
    GetBundleRequestValidationError, JoinTicketRequestPreparationError,
    LookupMergeAcceptanceRequestDecodeError, MAX_BARRIER_HELPER_PAGE_ENTRIES,
    MembersRequestValidationError, MergeTicketRequestValidationError,
    ResolveRevokedLeavesRequestDecodeError, RoomAdminProofValidationError,
    RoomAdminRequestValidationError, RoomScopedApiRoute, RoomScopedRequestTarget,
    RoomScopedRoutingKey, SearchMembersRequestValidationError, SendMessageRequestValidationError,
    decode_barrier_fetch_public_tree_request, decode_barrier_lookup_merge_acceptance_request,
    decode_barrier_resolve_revoked_leaves_request,
    decode_bundle_cbor_request as schema_decode_bundle_cbor_request,
    decode_full_verification_witness_request, encode_bootstrap_room_response,
    encode_full_verification_witness_response, encode_list_room_admins_response,
    encode_members_response, encode_prepared_barrier_public_tree_response,
    encode_prepared_join_ticket_response, encode_prepared_merge_acceptance_lookup_response,
    encode_prepared_merge_ticket_response, encode_prepared_resolved_joins_response,
    encode_prepared_resolved_revoked_leaves_response, encode_room_admin_leaf_pair_payload,
    encode_room_admin_mutation_response, encode_rotate_room_kbroad_response,
    encode_search_members_response, extract_room_scoped_request_target, pb,
    pb_member as schema_pb_member, prepare_join_ticket_request_for_gid,
    room_admin_proof_replay_key, validate_bootstrap_room_request,
    validate_expel_member_ticket_request, validate_fetch_messages_request,
    validate_list_room_admins_request, validate_members_request, validate_merge_ticket_request,
    validate_room_admin_mutation_request, validate_rotate_room_kbroad_request,
    validate_search_members_request, validate_send_message_request, verify_room_admin_proof,
    verify_room_admin_proof_payload,
};
use cityg_client::CityGError as ClientError;
use cityg_runtime::{
    AcceptedRoomEpoch, AliasLeafLookup, AliasRegistrationError, AliasRegistry,
    BarrierPaginationError, RoomAcceptEpochError, RoomAuthorizationError, RoomBarrierEnvelopeError,
    RoomBarrierHelperPreparationError, RoomFullVerificationWitnessPreparationError,
    RoomMemberListingError, RoomMessageStoreError, RoomRoutingEntry, RoomServiceError,
    RoomSnapshot, RoomStateCheckpoint, RoomTicketPreparationError, RoomVolatileState, RuntimeRoom,
    accept_room_epoch, alias_entry_for_member, classify_refresh_pivot_conflict,
    derive_room_routing_entries, fetch_room_bundle, fetch_room_members, fetch_room_messages,
    filter_room_members_by_query, paginate_room_members, prepare_barrier_public_tree,
    prepare_full_verification_witness, prepare_merge_acceptance_lookup, prepare_resolved_joins,
    prepare_resolved_revoked_leaves, refresh_room_pivot, store_room_message,
};
use cityg_server::MergeTicketIntent as ServerMergeTicketIntent;
use msphf_core::MsphfError;
use msphf_orchestrator::AcceptanceError;
use prost::Message;
use serde::{Deserialize, Serialize};
use worker::{
    Env, Method, Request, RequestInit, Response, Result, SqlStorage, SqlStorageValue, State,
    WebSocket, WebSocketIncomingMessage, WebSocketPair, WebSocketRequestResponsePair,
    wasm_bindgen::JsValue,
};

use crate::{
    DurableObjectRoomStateStore, DurableObjectStorage, RoomStateStore, WORKER_CONFIG_JSON_ENV,
    WORKER_KNOWN_GIDS_JSON_ENV, WorkerHistoryAuthority, WorkerRoomBootstrap,
    rehydrate_runtime_room_from_checkpoint,
};

pub const CLOUDFLARE_ROOM_NAMESPACE_BINDING: &str = "CITYG_ROOM";
pub const CLOUDFLARE_ROOM_ROUTE_PREFIX: &str = "/__cloudflare/rooms";
pub const CLOUDFLARE_ROUTING_NAMESPACE_BINDING: &str = "CITYG_ROUTING_INDEX";
pub const CLOUDFLARE_ROUTING_ROUTE_PREFIX: &str = "/__cloudflare/routing";
pub const CLOUDFLARE_ROOM_REGISTRY_NAMESPACE_BINDING: &str = "CITYG_ROOM_REGISTRY";
pub const CLOUDFLARE_ROOM_REGISTRY_ROUTE_PREFIX: &str = "/__cloudflare/room-registry";
pub const CLOUDFLARE_ALIAS_NAMESPACE_BINDING: &str = "CITYG_ALIAS_INDEX";
pub const CLOUDFLARE_ALIAS_ROUTE_PREFIX: &str = "/__cloudflare/aliases";
const ROOM_STATE_TABLE: &str = "cityg_room_state";
const ROUTING_INDEX_TABLE: &str = "cityg_epoch_scope_index";
const ROOM_REGISTRY_TABLE: &str = "cityg_room_registry";
const GLOBAL_ROUTING_OBJECT_NAME: &str = "global";
const GLOBAL_ROOM_REGISTRY_OBJECT_NAME: &str = "global";
const GLOBAL_ALIAS_OBJECT_NAME: &str = "global";
const ROOM_STORAGE_PREFIX: &str = "rooms/";
const ALIAS_REGISTRY_STORAGE_KEY: &str = "aliases/registry.cbor";
const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";
const MESSAGE_AUTH_TOKEN_ENV: &str = "CITYG_SERVER_MESSAGE_AUTH_TOKEN";
const MESSAGE_PRUNE_INTERVAL_MS: u64 = 1_000;
const DEFAULT_FS_MESSAGE_RETENTION_SECS: u64 = 600;
const ROOM_SNAPSHOT_FORMAT_VERSION: u32 = 1;
const NATIVE_WEBSOCKET_PATH: &str = "/v1/ws";
const WS_MAX_LAG_ENV: &str = "CITYG_SERVER_WS_MAX_LAG";
const WS_MAX_LAG_DEFAULT: u64 = 256;
const WEBSOCKET_ACK_TYPE: &str = "ack";
const WEBSOCKET_PING_REQUEST: &str = "ping";
const WEBSOCKET_PING_RESPONSE: &str = "pong";
const WEBSOCKET_RESUME_TYPE: &str = "resume";

pub async fn cloudflare_fetch(req: Request, env: Env) -> Result<Response> {
    if req.path() == "/healthz" {
        return Response::ok("ok");
    }

    let path = req.path();
    let namespace = env.durable_object(CLOUDFLARE_ROOM_NAMESPACE_BINDING)?;
    if path == NATIVE_WEBSOCKET_PATH {
        let subscription = match parse_websocket_subscription(&req) {
            Ok(subscription) => subscription,
            Err(message) => return Response::error(message, 400),
        };
        let gid_hex = hex::encode(subscription.gid);
        let stub = namespace.id_from_name(&gid_hex)?.get_stub()?;
        return stub.fetch_with_request(req).await;
    }
    if let Some(route) = parse_room_route(&path) {
        let stub = namespace.id_from_name(route.gid_hex)?.get_stub()?;
        return stub.fetch_with_request(req).await;
    }
    if let Some(target) = extract_native_room_target(&req).await? {
        return match target.key {
            RoomScopedRoutingKey::Gid(gid) => {
                let gid_hex = hex::encode(gid);
                let stub = namespace.id_from_name(&gid_hex)?.get_stub()?;
                stub.fetch_with_request(req).await
            }
            RoomScopedRoutingKey::WeEpochId(we_epoch_id) => {
                let gid_hex = match resolve_gid_for_we_epoch_id(&env, &we_epoch_id).await? {
                    Some(gid_hex) => gid_hex,
                    None => match resync_and_resolve_gid_for_we_epoch_id(&env, &we_epoch_id).await?
                    {
                        Some(gid_hex) => gid_hex,
                        None => {
                            return Response::error(
                                format!(
                                    "no room routing entry found for we_epoch_id {}",
                                    hex::encode(we_epoch_id)
                                ),
                                404,
                            );
                        }
                    },
                };
                let stub = namespace.id_from_name(&gid_hex)?.get_stub()?;
                stub.fetch_with_request(req).await
            }
        };
    }
    Response::error("unsupported Cloudflare route", 404)
}

pub struct CloudflareRoomDurableObject {
    object_id: String,
    state: State,
    env: Env,
    store: Option<RefCell<DurableObjectRoomStateStore<CloudflareSqlDurableObjectStorage>>>,
    realtime: RefCell<RoomRealtimeState>,
    init_error: Option<String>,
}

impl CloudflareRoomDurableObject {
    #[must_use]
    pub fn new(state: State, env: Env) -> Self {
        let object_id = state.id().to_string();
        match CloudflareSqlDurableObjectStorage::new(state.storage().sql()) {
            Ok(storage) => Self {
                object_id,
                state,
                env,
                store: Some(RefCell::new(DurableObjectRoomStateStore::new(storage))),
                realtime: RefCell::new(RoomRealtimeState::default()),
                init_error: None,
            },
            Err(error) => Self {
                object_id,
                state,
                env,
                store: None,
                realtime: RefCell::new(RoomRealtimeState::default()),
                init_error: Some(error.to_string()),
            },
        }
    }

    pub async fn fetch(&self, req: Request) -> Result<Response> {
        if let Some(init_error) = &self.init_error {
            return Response::error(
                format!("failed to initialize Cloudflare room storage: {init_error}"),
                500,
            );
        }

        self.ensure_websocket_auto_response();

        let path = req.path();
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;

        if path == NATIVE_WEBSOCKET_PATH {
            return self.handle_websocket_connect(&req).await;
        }

        if let Some(route) = parse_room_route(&path) {
            let gid = parse_gid(route.gid_hex)?;
            register_room_gid(&self.env, gid).await?;
            return match (req.method(), route.action) {
                (Method::Get, RoomRouteAction::Status) => {
                    let checkpoint = store
                        .borrow()
                        .load_checkpoint(&gid)
                        .map_err(|error| worker::Error::from(error.to_string()))?;
                    let routing_entry_count = checkpoint
                        .as_ref()
                        .map(|checkpoint| derive_room_routing_entries(checkpoint).len())
                        .unwrap_or(0);
                    let rehydration = checkpoint.as_ref().map(|checkpoint| {
                        let bootstrap = configured_room_bootstrap(&self.env)
                            .unwrap_or_else(|_| rehydration_bootstrap());
                        match rehydrate_runtime_room_from_checkpoint(checkpoint, &bootstrap) {
                            Ok(_) => RoomRehydrationSummary {
                                replay_ready: true,
                                accepted_bundle_replay_count: checkpoint.accepted_bundles.len(),
                                error: None,
                            },
                            Err(error) => RoomRehydrationSummary {
                                replay_ready: false,
                                accepted_bundle_replay_count: checkpoint.accepted_bundles.len(),
                                error: Some(error.to_string()),
                            },
                        }
                    });
                    Response::from_json(&RoomStatusResponse {
                        gid: route.gid_hex.to_owned(),
                        durable_object_id: self.object_id.clone(),
                        storage_backend: "cloudflare-do-sqlite",
                        sqlite_database_size_bytes: store.borrow().storage().database_size_bytes(),
                        routing_entry_count,
                        rehydration,
                        checkpoint: checkpoint.as_ref().map(RoomCheckpointSummary::from),
                    })
                }
                (Method::Get, RoomRouteAction::Checkpoint) => {
                    let Some(checkpoint) = store
                        .borrow()
                        .load_checkpoint(&gid)
                        .map_err(|error| worker::Error::from(error.to_string()))?
                    else {
                        return Response::error("room checkpoint not found", 404);
                    };
                    Response::from_json(&checkpoint)
                }
                (Method::Post, RoomRouteAction::SyncRouting) => {
                    let synced_entries = self.sync_routing_index_from_checkpoint(gid).await?;
                    Response::from_json(&RoomRoutingSyncResponse {
                        gid: route.gid_hex.to_owned(),
                        synced_entries,
                    })
                }
                _ => Response::error("method not allowed", 405),
            };
        }

        if let Some((target, body)) = extract_native_room_request(&req).await? {
            return self.execute_native_room_request(&req, target, body).await;
        }

        Response::error("unsupported Cloudflare room route", 404)
    }

    async fn execute_native_room_request(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if let RoomScopedRoutingKey::Gid(gid) = target.key {
            register_room_gid(&self.env, gid).await?;
        }
        match target.route {
            RoomScopedApiRoute::AcceptEpoch => self.handle_accept_epoch(req, target, body).await,
            RoomScopedApiRoute::Members => self.handle_members(req, target, body).await,
            RoomScopedApiRoute::SearchMembers => {
                self.handle_search_members(req, target, body).await
            }
            RoomScopedApiRoute::BootstrapRoom => {
                self.handle_bootstrap_room(req, target, body).await
            }
            RoomScopedApiRoute::RotateRoomKbroad => {
                self.handle_rotate_room_kbroad(req, target, body).await
            }
            RoomScopedApiRoute::GrantRoomAdmin => {
                self.handle_grant_room_admin(req, target, body).await
            }
            RoomScopedApiRoute::RevokeRoomAdmin => {
                self.handle_revoke_room_admin(req, target, body).await
            }
            RoomScopedApiRoute::ListRoomAdmins => {
                self.handle_list_room_admins(req, target, body).await
            }
            RoomScopedApiRoute::SendMessage => self.handle_send_message(req, target, body).await,
            RoomScopedApiRoute::FetchMessages => {
                self.handle_fetch_messages(req, target, body).await
            }
            RoomScopedApiRoute::GetBundle => self.handle_get_bundle(req, target, body).await,
            RoomScopedApiRoute::BarrierResolveRevokedLeaves => {
                self.handle_barrier_resolve_revoked_leaves(req, target, body)
                    .await
            }
            RoomScopedApiRoute::BarrierResolveJoinsSince => {
                self.handle_barrier_resolve_joins_since(req, target, body)
                    .await
            }
            RoomScopedApiRoute::BarrierFetchPublicTree => {
                self.handle_barrier_fetch_public_tree(req, target, body)
                    .await
            }
            RoomScopedApiRoute::BarrierIssueFullVerificationWitness => {
                self.handle_barrier_issue_full_verification_witness(req, target, body)
                    .await
            }
            RoomScopedApiRoute::BarrierLookupMergeAcceptance => {
                self.handle_barrier_lookup_merge_acceptance(req, target, body)
                    .await
            }
            RoomScopedApiRoute::ExpelMemberTicket => {
                self.handle_expel_member_ticket(req, target, body).await
            }
            RoomScopedApiRoute::JoinTicket => self.handle_join_ticket(req, target, body).await,
            RoomScopedApiRoute::MergeTicket => self.handle_merge_ticket(req, target, body).await,
            RoomScopedApiRoute::RefreshPivot => self.handle_refresh_pivot(req, target, body).await,
        }
    }

    async fn handle_websocket_connect(&self, req: &Request) -> Result<Response> {
        if req.method() != Method::Get {
            return Response::error("method not allowed", 405);
        }
        if !websocket_upgrade_requested(req) {
            return Response::error("expected websocket upgrade", 426);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let subscription = match parse_websocket_subscription(req) {
            Ok(subscription) => subscription,
            Err(message) => return Response::error(message, 400),
        };
        let Some(checkpoint) = self.load_checkpoint_for_gid(subscription.gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (server, _) = room.into_parts();
        match cityg_runtime::ensure_leaf_member_for_room(
            &server,
            &subscription.gid,
            subscription.leaf_id,
        ) {
            Ok(()) => {}
            Err(RoomAuthorizationError::NotFound) => {
                return Response::error("resource not found", 404);
            }
            Err(RoomAuthorizationError::Unauthorized) => {
                return Response::error("leaf is not a member for room", 401);
            }
        }

        let pair = WebSocketPair::new()?;
        pair.server
            .serialize_attachment(WebSocketSessionAttachment {
                gid: subscription.gid,
                leaf_id: subscription.leaf_id,
                last_client_activity_ms: current_timestamp_ms(),
                last_acknowledged_sequence: 0,
                last_sent_sequence: 0,
                last_lag_notice_acknowledged_sequence: 0,
            })?;
        let leaf_tag = format!("leaf:{}", hex::encode(subscription.leaf_id));
        self.state
            .accept_websocket_with_tags(&pair.server, &[leaf_tag.as_str()]);
        Response::from_websocket(pair.client)
    }

    pub async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if let WebSocketIncomingMessage::String(text) = message {
            if let Some(signal) = parse_websocket_client_signal(text.as_str()) {
                self.record_websocket_signal(&ws, signal)?;
            }
        }
        Ok(())
    }

    pub async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let _ = ws.close(u16::try_from(code).ok(), Some(reason.as_str()));
        Ok(())
    }

    pub async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        let _ = ws.close(Some(1011), Some("websocket error"));
        Ok(())
    }

    async fn handle_accept_epoch(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::AcceptEpochRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let bundle = match schema_decode_bundle_cbor_request(&request.bundle_cbor, false) {
            Ok(bundle) => bundle,
            Err(error) => return bundle_cbor_request_decode_error_response(error),
        };
        let gid = route_gid(&target)?;
        let checkpoint = self.load_checkpoint_for_gid(gid)?;
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match checkpoint.as_ref() {
            Some(checkpoint) => {
                match rehydrate_runtime_room_from_checkpoint(checkpoint, &bootstrap) {
                    Ok(room) => room,
                    Err(error) => {
                        return Response::error(
                            format!("failed to rehydrate room checkpoint: {error}"),
                            500,
                        );
                    }
                }
            }
            None => RuntimeRoom::new(cityg_server::CityGServer::new(bootstrap.to_server_config())),
        };
        let (mut server, mut room_state) = room.into_parts();

        let timestamp_ms = current_timestamp_ms();
        let accepted = match accept_room_epoch(
            &mut server,
            &mut room_state,
            &bundle,
            timestamp_ms,
            message_retention(),
            MESSAGE_PRUNE_INTERVAL_MS,
        ) {
            Ok(accepted) => accepted,
            Err(error) => return accept_epoch_error_response(error),
        };
        if let Err(error) =
            remove_alias_bindings_for_revoked_leaves(&self.env, accepted.applied.revoked.as_slice())
                .await
        {
            return Response::error(
                format!("failed to unbind revoked aliases after accept_epoch: {error}"),
                500,
            );
        }
        let server_state_bytes = export_server_runtime_metadata_bytes(&server)?;

        self.persist_room_accept(
            gid,
            checkpoint.as_ref(),
            server_state_bytes,
            &accepted,
            room_state.snapshot(),
            timestamp_ms,
        )?;
        let _ = upsert_routing_entries(
            &self.env,
            &[RoomRoutingEntry {
                gid,
                we_epoch_id: accepted.outcome.we_epoch_id,
            }],
        )
        .await;
        self.broadcast_accept_epoch_notifications(&accepted);

        let response = pb::AcceptEpochResponse {
            we_epoch_id: accepted.outcome.we_epoch_id.to_vec(),
            wid: accepted.outcome.wid.to_vec(),
            parent_root: accepted.outcome.parent_root.to_vec(),
            new_root: accepted.outcome.new_root.to_vec(),
        };
        protobuf_response(&response)
    }

    async fn handle_bootstrap_room(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::BootstrapRoomRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_bootstrap_room_request(request) {
            Ok(request) => request,
            Err(error) => return room_admin_request_validation_error_response(error),
        };

        let gid = route_gid(&target)?;
        let initial_room_admin_pop_key = match verify_room_admin_proof(
            &request.admin_proof,
            "bootstrap_room_v1",
            &request.room_id,
            &request.kbroad_public,
        ) {
            Ok(pop_key) => pop_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };

        let checkpoint = self.load_checkpoint_for_gid(gid)?;
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match checkpoint.as_ref() {
            Some(checkpoint) => {
                match rehydrate_runtime_room_from_checkpoint(checkpoint, &bootstrap) {
                    Ok(room) => room,
                    Err(error) => {
                        return Response::error(
                            format!("failed to rehydrate room checkpoint: {error}"),
                            500,
                        );
                    }
                }
            }
            None => RuntimeRoom::new(cityg_server::CityGServer::new(bootstrap.to_server_config())),
        };
        let (mut server, room_state) = room.into_parts();
        match server.register_group_with_admin(
            &gid,
            request.kbroad_public,
            initial_room_admin_pop_key,
        ) {
            Ok(()) => {}
            Err(error) => return client_error_response(error),
        }

        let persisted_at_ms = current_timestamp_ms();
        self.persist_room_runtime_state(
            gid,
            checkpoint.as_ref(),
            &server,
            room_state.snapshot(),
            persisted_at_ms,
        )?;

        protobuf_response_bytes(encode_bootstrap_room_response("registered"))
    }

    async fn handle_rotate_room_kbroad(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::RotateRoomKbroadRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_rotate_room_kbroad_request(request) {
            Ok(request) => request,
            Err(error) => return room_admin_request_validation_error_response(error),
        };

        let replay_key = match room_admin_proof_replay_key(&request.admin_proof) {
            Ok(replay_key) => replay_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };
        let actor_pop_key = match verify_room_admin_proof(
            &request.admin_proof,
            "rotate_room_kbroad_v1",
            &request.room_id,
            &request.kbroad_public,
        ) {
            Ok(pop_key) => pop_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };

        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, room_state) = room.into_parts();
        let kbroad_generation = match server.rotate_group_kbroad_with_actor(
            &gid,
            request.kbroad_public,
            &actor_pop_key,
            replay_key,
        ) {
            Ok(generation) => generation,
            Err(error) => return client_error_response(error),
        };

        self.persist_room_runtime_state(
            gid,
            Some(&checkpoint),
            &server,
            room_state.snapshot(),
            current_timestamp_ms(),
        )?;

        protobuf_response_bytes(encode_rotate_room_kbroad_response(
            "rotated",
            kbroad_generation,
        ))
    }

    async fn handle_grant_room_admin(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        self.handle_room_admin_mutation(req, target, body, RoomAdminMutationKind::Grant)
            .await
    }

    async fn handle_revoke_room_admin(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        self.handle_room_admin_mutation(req, target, body, RoomAdminMutationKind::Revoke)
            .await
    }

    async fn handle_room_admin_mutation(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
        kind: RoomAdminMutationKind,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::RoomAdminMutationRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_room_admin_mutation_request(request) {
            Ok(request) => request,
            Err(error) => return room_admin_request_validation_error_response(error),
        };

        let replay_key = match room_admin_proof_replay_key(&request.admin_proof) {
            Ok(replay_key) => replay_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };
        let actor_pop_key = match verify_room_admin_proof_payload(
            &request.admin_proof,
            kind.operation(),
            &request.room_id,
            &request.target_pop_public_key,
        ) {
            Ok(pop_key) => pop_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };

        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, room_state) = room.into_parts();
        let (applied, admin_count) = match kind {
            RoomAdminMutationKind::Grant => match server.grant_room_admin(
                &gid,
                &actor_pop_key,
                request.target_pop_public_key,
                replay_key,
            ) {
                Ok(result) => result,
                Err(error) => return client_error_response(error),
            },
            RoomAdminMutationKind::Revoke => match server.revoke_room_admin(
                &gid,
                &actor_pop_key,
                &request.target_pop_public_key,
                replay_key,
            ) {
                Ok(result) => result,
                Err(error) => return client_error_response(error),
            },
        };

        self.persist_room_runtime_state(
            gid,
            Some(&checkpoint),
            &server,
            room_state.snapshot(),
            current_timestamp_ms(),
        )?;

        protobuf_response_bytes(encode_room_admin_mutation_response(
            kind.status(applied),
            admin_count,
        ))
    }

    async fn handle_list_room_admins(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::ListRoomAdminsRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_list_room_admins_request(request) {
            Ok(request) => request,
            Err(error) => return room_admin_request_validation_error_response(error),
        };
        let actor_pop_key = match verify_room_admin_proof_payload(
            &request.admin_proof,
            "list_room_admins_v1",
            &request.room_id,
            &[],
        ) {
            Ok(pop_key) => pop_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };

        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (server, _) = room.into_parts();
        let admin_pop_public_keys = match server.list_room_admins(&gid, &actor_pop_key) {
            Ok(admin_pop_public_keys) => admin_pop_public_keys,
            Err(error) => return client_error_response(error),
        };

        protobuf_response_bytes(encode_list_room_admins_response(admin_pop_public_keys))
    }

    async fn handle_members(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::MembersRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_members_request(request) {
            Ok(request) => request,
            Err(error) => return members_request_validation_error_response(error),
        };
        let gid = route_gid(&target)?;
        let checkpoint = self.load_checkpoint_for_gid(gid)?;
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match checkpoint.as_ref() {
            Some(checkpoint) => {
                match rehydrate_runtime_room_from_checkpoint(checkpoint, &bootstrap) {
                    Ok(room) => room,
                    Err(error) => {
                        return Response::error(
                            format!("failed to rehydrate room checkpoint: {error}"),
                            500,
                        );
                    }
                }
            }
            None => RuntimeRoom::new(cityg_server::CityGServer::new(bootstrap.to_server_config())),
        };
        let (server, room_state) = room.into_parts();
        let (members, root) = match fetch_room_members(&server, &gid, request.parent_root) {
            Ok(result) => result,
            Err(RoomMemberListingError::NotFound) => {
                return Response::error("resource not found", 404);
            }
        };

        let page = paginate_room_members(members.as_slice(), request.offset, request.limit);
        let alias_lookup =
            match lookup_alias_bindings_by_leaf(&self.env, page.members.as_slice()).await {
                Ok(lookup) => lookup,
                Err(error) => {
                    return Response::error(format!("alias lookup failed: {error}"), 500);
                }
            };

        protobuf_response_bytes(encode_members_response(
            page.members
                .iter()
                .map(|leaf| room_member_response(leaf, &alias_lookup, room_state.member_metadata()))
                .collect(),
            root,
            page.total_count,
            page.next_offset,
        ))
    }

    async fn handle_search_members(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::SearchMembersRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_search_members_request(request) {
            Ok(request) => request,
            Err(error) => return search_members_request_validation_error_response(error),
        };
        let gid = route_gid(&target)?;
        let checkpoint = self.load_checkpoint_for_gid(gid)?;
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match checkpoint.as_ref() {
            Some(checkpoint) => {
                match rehydrate_runtime_room_from_checkpoint(checkpoint, &bootstrap) {
                    Ok(room) => room,
                    Err(error) => {
                        return Response::error(
                            format!("failed to rehydrate room checkpoint: {error}"),
                            500,
                        );
                    }
                }
            }
            None => RuntimeRoom::new(cityg_server::CityGServer::new(bootstrap.to_server_config())),
        };
        let (server, room_state) = room.into_parts();
        let (members, root) = match fetch_room_members(&server, &gid, request.parent_root) {
            Ok(result) => result,
            Err(RoomMemberListingError::NotFound) => {
                return Response::error("resource not found", 404);
            }
        };
        let alias_lookup = match lookup_alias_bindings_by_leaf(&self.env, members.as_slice()).await
        {
            Ok(lookup) => lookup,
            Err(error) => {
                return Response::error(format!("alias lookup failed: {error}"), 500);
            }
        };

        let filtered_members =
            filter_room_members_by_query(members.as_slice(), &alias_lookup, request.query.as_str());
        let page =
            paginate_room_members(filtered_members.as_slice(), request.offset, request.limit);

        protobuf_response_bytes(encode_search_members_response(
            page.members
                .iter()
                .map(|leaf| room_member_response(leaf, &alias_lookup, room_state.member_metadata()))
                .collect(),
            root,
            page.total_count,
            page.next_offset,
        ))
    }

    async fn handle_fetch_messages(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::FetchMessagesRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_fetch_messages_request(request) {
            Ok(request) => request,
            Err(error) => return fetch_messages_request_validation_error_response(error),
        };

        let Some(checkpoint) = self.load_checkpoint_for_target(&target)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let we_epoch_id = route_we_epoch_id(&target)?;
        let (server, mut room_state) = room.into_parts();
        let now_ms = current_timestamp_ms();
        let messages = match fetch_room_messages(
            &server,
            &mut room_state,
            &we_epoch_id,
            request.leaf_id,
            now_ms,
            message_retention(),
            MESSAGE_PRUNE_INTERVAL_MS,
        ) {
            Ok(messages) => messages,
            Err(RoomAuthorizationError::NotFound) => {
                return Response::error("resource not found", 404);
            }
            Err(RoomAuthorizationError::Unauthorized) => {
                return Response::error("leaf is not a member for epoch", 401);
            }
        };

        let response = pb::FetchMessagesResponse {
            messages: messages
                .into_iter()
                .map(|msg| pb::ChatMessage {
                    ciphertext: msg.ciphertext,
                    we_epoch_id: msg.we_epoch_id.to_vec(),
                    sender: msg.sender,
                    timestamp_ms: msg.timestamp_ms,
                })
                .collect(),
        };
        protobuf_response(&response)
    }

    async fn handle_send_message(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::SendMessageRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_send_message_request(request) {
            Ok(request) => request,
            Err(error) => return send_message_request_validation_error_response(error),
        };
        let we_epoch_id = route_we_epoch_id(&target)?;

        let Some(checkpoint) = self.load_checkpoint_for_target(&target)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let gid = checkpoint.snapshot.gid;
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };

        let (server, mut room_state) = room.into_parts();
        let timestamp_ms = current_timestamp_ms();
        match store_room_message(
            &server,
            &mut room_state,
            we_epoch_id,
            request.sender_leaf,
            request.ciphertext,
            request.sender,
            timestamp_ms,
            message_retention(),
            MESSAGE_PRUNE_INTERVAL_MS,
        ) {
            Ok(scope) => scope,
            Err(RoomMessageStoreError::NotFound) => {
                return Response::error("resource not found", 404);
            }
            Err(RoomMessageStoreError::EpochUnauthorized) => {
                return Response::error("leaf is not a member for epoch", 401);
            }
            Err(RoomMessageStoreError::RoomUnauthorized) => {
                return Response::error("leaf is not a member for room", 401);
            }
        };
        self.persist_room_volatile_snapshot(gid, room_state.snapshot())?;
        self.broadcast_message_notification(gid, we_epoch_id, timestamp_ms);
        let response = pb::SendMessageResponse {
            status: "stored".to_string(),
        };
        protobuf_response(&response)
    }

    async fn handle_get_bundle(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::GetBundleRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match cityg_api_schema::validate_get_bundle_request(request) {
            Ok(request) => request,
            Err(error) => return get_bundle_request_validation_error_response(error),
        };
        let Some(checkpoint) = self.load_checkpoint_for_target(&target)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let mut room_state = RoomVolatileState::from_snapshot(checkpoint.volatile);
        let now_ms = current_timestamp_ms();
        let Some(bundle) = fetch_room_bundle(
            &mut room_state,
            &request.we_epoch_id,
            now_ms,
            message_retention(),
            MESSAGE_PRUNE_INTERVAL_MS,
        ) else {
            return Response::error("resource not found", 404);
        };

        let response = pb::GetBundleResponse {
            bundle_cbor: bundle.bytes,
        };
        protobuf_response(&response)
    }

    async fn handle_barrier_resolve_revoked_leaves(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::BarrierResolveRevokedLeavesRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match decode_barrier_resolve_revoked_leaves_request(request) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    ResolveRevokedLeavesRequestDecodeError::api_message(&error),
                    400,
                );
            }
        };
        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();

        let prepared = match prepare_resolved_revoked_leaves(
            &mut server,
            &gid,
            &request.revocation_roots_hash,
            request.page_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return barrier_helper_error_response(error),
        };
        protobuf_response_bytes(encode_prepared_resolved_revoked_leaves_response(prepared))
    }

    async fn handle_barrier_resolve_joins_since(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::BarrierResolveJoinsSinceRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();

        let prepared = match prepare_resolved_joins(
            &mut server,
            &gid,
            request.prev_barrier_version,
            request.page_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return barrier_helper_error_response(error),
        };
        protobuf_response_bytes(encode_prepared_resolved_joins_response(prepared))
    }

    async fn handle_barrier_fetch_public_tree(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::BarrierFetchPublicTreeRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match decode_barrier_fetch_public_tree_request(request) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    FetchPublicTreeRequestDecodeError::api_message(&error),
                    400,
                );
            }
        };
        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();

        let prepared = match prepare_barrier_public_tree(
            &mut server,
            &gid,
            &request.kem_tree_hash_after,
            request.entry_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return barrier_helper_error_response(error),
        };
        protobuf_response_bytes(encode_prepared_barrier_public_tree_response(prepared))
    }

    async fn handle_barrier_lookup_merge_acceptance(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::BarrierLookupMergeAcceptanceRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match decode_barrier_lookup_merge_acceptance_request(request) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    LookupMergeAcceptanceRequestDecodeError::api_message(&error),
                    400,
                );
            }
        };
        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();

        let prepared = match prepare_merge_acceptance_lookup(
            &mut server,
            &gid,
            request.pending_barrier_version,
            &request.pending_barrier_update_digest,
            &request.pending_we_epoch_id,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return barrier_helper_error_response(error),
        };
        protobuf_response_bytes(encode_prepared_merge_acceptance_lookup_response(prepared))
    }

    async fn handle_barrier_issue_full_verification_witness(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::BarrierIssueFullVerificationWitnessRequest::decode(body.as_slice())
        {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };

        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();

        let witness_request = match decode_full_verification_witness_request(request) {
            Ok(request) => request,
            Err(error) => return Response::error(error.api_message(), 400),
        };

        let witness = match prepare_full_verification_witness(
            &mut server,
            &gid,
            witness_request,
            API_PROFILE_VERSION,
        ) {
            Ok(witness) => witness,
            Err(error) => return full_verification_witness_error_response(error),
        };

        protobuf_response_bytes(encode_full_verification_witness_response(witness))
    }

    async fn handle_join_ticket(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::JoinTicketRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let gid = route_gid(&target)?;
        let request = match prepare_join_ticket_request_for_gid(gid, request) {
            Ok(request) => request,
            Err(error) => return join_ticket_request_preparation_error_response(error),
        };

        let checkpoint = self.load_checkpoint_for_gid(gid)?;
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match checkpoint.as_ref() {
            Some(checkpoint) => {
                match rehydrate_runtime_room_from_checkpoint(checkpoint, &bootstrap) {
                    Ok(room) => room,
                    Err(error) => {
                        return Response::error(
                            format!("failed to rehydrate room checkpoint: {error}"),
                            500,
                        );
                    }
                }
            }
            None => RuntimeRoom::new(cityg_server::CityGServer::new(bootstrap.to_server_config())),
        };
        let (mut server, room_state) = room.into_parts();
        let prepared = match cityg_runtime::prepare_join_ticket(
            &mut server,
            &gid,
            request.requested_leaf_id,
            SystemTime::now(),
            bootstrap.fs_epoch_period_seconds,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return ticket_preparation_error_response(error),
        };

        self.persist_room_runtime_state(
            gid,
            checkpoint.as_ref(),
            &server,
            room_state.snapshot(),
            current_timestamp_ms(),
        )?;

        if let Some(binding) = request.confirmed_binding.as_ref() {
            match register_alias_binding(
                &self.env,
                binding.alias.as_str(),
                prepared.bundle.leaf_id,
                binding.pop_public_key.as_slice(),
            )
            .await
            {
                Ok(()) => {}
                Err(AliasRemoteError::Conflict) => {
                    return Response::error("alias already bound to a different identity", 400);
                }
                Err(AliasRemoteError::Backend(message)) => {
                    return Response::error(
                        format!("failed to register alias binding: {message}"),
                        500,
                    );
                }
            }
        }

        protobuf_response_bytes(encode_prepared_join_ticket_response(
            prepared,
            request.confirmed_binding,
        ))
    }

    async fn handle_merge_ticket(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::MergeTicketRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_merge_ticket_request(request) {
            Ok(request) => request,
            Err(error) => return merge_ticket_request_validation_error_response(error),
        };
        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();
        let intent = match request.intent {
            pb::MergeTicketIntent::Leave => ServerMergeTicketIntent::Leave,
            pb::MergeTicketIntent::Refresh => ServerMergeTicketIntent::Refresh,
        };

        let prepared = match cityg_runtime::prepare_merge_ticket(
            &mut server,
            &gid,
            &request.leaf_id,
            intent,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return ticket_preparation_error_response(error),
        };

        protobuf_response_bytes(encode_prepared_merge_ticket_response(prepared))
    }

    async fn handle_refresh_pivot(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        if let Err(message) =
            enforce_message_auth_header(req, configured_message_auth_token(&self.env).as_deref())
        {
            return Response::error(message, 401);
        }

        let request = match pb::RefreshPivotRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let bundle = match schema_decode_bundle_cbor_request(&request.bundle_cbor, true) {
            Ok(bundle) => bundle,
            Err(error) => return bundle_cbor_request_decode_error_response(error),
        };
        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, room_state) = room.into_parts();

        match refresh_room_pivot(&mut server, &bundle) {
            Ok(()) => {}
            Err(error) => return refresh_pivot_error_response(error),
        }

        self.persist_room_runtime_state(
            gid,
            Some(&checkpoint),
            &server,
            room_state.snapshot(),
            current_timestamp_ms(),
        )?;

        protobuf_response(&pb::RefreshPivotResponse {})
    }

    async fn handle_expel_member_ticket(
        &self,
        req: &Request,
        target: RoomScopedRequestTarget,
        body: Vec<u8>,
    ) -> Result<Response> {
        if req.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }

        let request = match pb::ExpelMemberTicketRequest::decode(body.as_slice()) {
            Ok(request) => request,
            Err(error) => {
                return Response::error(
                    format!("failed to decode {} request: {error}", target.route.path()),
                    400,
                );
            }
        };
        let request = match validate_expel_member_ticket_request(request) {
            Ok(request) => request,
            Err(error) => return expel_member_ticket_request_validation_error_response(error),
        };
        let payload = match encode_room_admin_leaf_pair_payload(
            &request.author_leaf_id,
            &request.target_leaf_id,
        ) {
            Ok(payload) => payload,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };
        let replay_key = match room_admin_proof_replay_key(&request.admin_proof) {
            Ok(replay_key) => replay_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };
        let actor_pop_key = match verify_room_admin_proof_payload(
            &request.admin_proof,
            "expel_room_member_v1",
            &request.room_id,
            &payload,
        ) {
            Ok(pop_key) => pop_key,
            Err(error) => return room_admin_proof_validation_error_response(error),
        };

        let gid = route_gid(&target)?;
        let Some(checkpoint) = self.load_checkpoint_for_gid(gid)? else {
            return Response::error("room checkpoint not found", 404);
        };
        let bootstrap = configured_room_bootstrap(&self.env)?;
        let room = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &bootstrap) {
            Ok(room) => room,
            Err(error) => {
                return Response::error(
                    format!("failed to rehydrate room checkpoint: {error}"),
                    500,
                );
            }
        };
        let (mut server, _) = room.into_parts();
        let bundle = match server.build_admin_expel_ticket(
            &gid,
            &actor_pop_key,
            &request.author_leaf_id,
            &request.target_leaf_id,
            replay_key,
        ) {
            Ok(bundle) => bundle,
            Err(ClientError::InvalidInput(message)) => return Response::error(message, 400),
            Err(error) => return Response::error(error.to_string(), 500),
        };
        let prepared = match cityg_runtime::prepare_merge_ticket_from_bundle(
            &server,
            &gid,
            bundle,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return ticket_preparation_error_response(error),
        };

        protobuf_response_bytes(encode_prepared_merge_ticket_response(prepared))
    }

    fn persist_room_accept(
        &self,
        gid: [u8; 32],
        previous_checkpoint: Option<&RoomStateCheckpoint>,
        server_state_bytes: Vec<u8>,
        accepted: &AcceptedRoomEpoch,
        volatile_snapshot: cityg_runtime::RoomVolatileSnapshot,
        persisted_at_ms: u64,
    ) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;
        let mut borrowed = store.borrow_mut();
        borrowed
            .persist_snapshot(room_snapshot_after_accept(
                gid,
                previous_checkpoint,
                server_state_bytes,
                accepted,
                persisted_at_ms,
            ))
            .map_err(|error| worker::Error::from(error.to_string()))?;
        borrowed
            .append_accepted_bundle(
                gid,
                cityg_runtime::AcceptedBundleRecord {
                    we_epoch_id: accepted.outcome.we_epoch_id,
                    parent_root: accepted.outcome.parent_root,
                    new_root: accepted.outcome.new_root,
                    bytes: accepted.stored_bundle_bytes.clone(),
                    accepted_at_ms: persisted_at_ms,
                },
            )
            .map_err(|error| worker::Error::from(error.to_string()))?;
        borrowed
            .persist_volatile_snapshot(gid, volatile_snapshot)
            .map_err(|error| worker::Error::from(error.to_string()))
    }

    fn broadcast_message_notification(
        &self,
        gid: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        let payload = serde_json::json!({
            "type": "message",
            "gid": hex::encode(gid),
            "we_epoch_id": hex::encode(we_epoch_id),
            "timestamp_ms": timestamp_ms,
            "connection_healthy": true,
        });
        self.broadcast_websocket_payload(payload);
    }

    fn broadcast_membership_notification(
        &self,
        gid: [u8; 32],
        leaf_id: [u8; 32],
        event: &'static str,
        timestamp_ms: u64,
    ) {
        let payload = serde_json::json!({
            "type": "membership",
            "gid": hex::encode(gid),
            "leaf_id": hex::encode(leaf_id),
            "event": event,
            "timestamp_ms": timestamp_ms,
        });
        self.broadcast_websocket_payload(payload);
    }

    fn broadcast_accept_epoch_notifications(&self, accepted: &AcceptedRoomEpoch) {
        for leaf_id in &accepted.applied.joined {
            self.broadcast_membership_notification(
                accepted.applied.gid,
                *leaf_id,
                "join",
                accepted.applied.timestamp_ms,
            );
        }
        for leaf_id in &accepted.applied.revoked {
            self.broadcast_membership_notification(
                accepted.applied.gid,
                *leaf_id,
                "revoke",
                accepted.applied.timestamp_ms,
            );
        }
    }

    fn broadcast_websocket_payload(&self, payload: serde_json::Value) {
        let sequence = self.next_websocket_sequence();
        let timestamp_ms = current_timestamp_ms();
        let max_lag = configured_ws_max_lag(&self.env);
        let replay_capacity = websocket_replay_buffer_capacity(max_lag);
        self.record_websocket_replay_event(
            payload.clone(),
            sequence,
            timestamp_ms,
            replay_capacity,
        );
        let oldest_retained_sequence = self.oldest_buffered_websocket_sequence();
        for websocket in self.state.get_websockets() {
            let mut attachment = websocket
                .deserialize_attachment::<WebSocketSessionAttachment>()
                .ok()
                .flatten()
                .unwrap_or_else(|| WebSocketSessionAttachment {
                    gid: [0; 32],
                    leaf_id: [0; 32],
                    last_client_activity_ms: timestamp_ms,
                    last_acknowledged_sequence: 0,
                    last_sent_sequence: 0,
                    last_lag_notice_acknowledged_sequence: 0,
                });
            if websocket_gap_is_irrecoverable(&attachment, oldest_retained_sequence) {
                let lagged_messages =
                    websocket_lagged_messages(&attachment, attachment.last_sent_sequence);
                if let Ok(text) = serde_json::to_string(&websocket_lag_disconnect_payload(
                    lagged_messages,
                    max_lag,
                    sequence,
                    timestamp_ms,
                )) {
                    let _ = websocket.send_with_str(text.as_str());
                }
                let _ = websocket.close(Some(1013), Some("websocket replay window exceeded"));
                continue;
            }
            let lagged_messages = websocket_lagged_messages(&attachment, sequence);

            if should_emit_websocket_lag_notice(&attachment, lagged_messages, max_lag) {
                if let Ok(text) = serde_json::to_string(&websocket_lag_payload(
                    lagged_messages,
                    max_lag,
                    sequence,
                    timestamp_ms,
                )) {
                    let _ = websocket.send_with_str(text.as_str());
                }
                attachment.last_lag_notice_acknowledged_sequence =
                    attachment.last_acknowledged_sequence;
            }

            attachment.last_sent_sequence = sequence;
            let _ = websocket.serialize_attachment(&attachment);
            let socket_payload =
                decorate_websocket_payload(payload.clone(), sequence, timestamp_ms, &attachment);
            let Ok(text) = serde_json::to_string(&socket_payload) else {
                continue;
            };
            let _ = websocket.send_with_str(text.as_str());
        }
    }

    fn next_websocket_sequence(&self) -> u64 {
        let mut realtime = self.realtime.borrow_mut();
        realtime.next_sequence = realtime.next_sequence.saturating_add(1);
        realtime.next_sequence
    }

    fn record_websocket_replay_event(
        &self,
        payload: serde_json::Value,
        sequence: u64,
        timestamp_ms: u64,
        capacity: usize,
    ) {
        let mut realtime = self.realtime.borrow_mut();
        push_websocket_replay_event(
            &mut realtime.replay_buffer,
            BufferedWebSocketEvent {
                sequence,
                payload,
                timestamp_ms,
            },
            capacity,
        );
    }

    fn oldest_buffered_websocket_sequence(&self) -> Option<u64> {
        let realtime = self.realtime.borrow();
        websocket_oldest_buffered_sequence(&realtime.replay_buffer)
    }

    fn replay_websocket_gap(
        &self,
        ws: &WebSocket,
        attachment: &mut WebSocketSessionAttachment,
    ) -> Result<()> {
        if attachment.last_acknowledged_sequence == 0
            || attachment.last_acknowledged_sequence >= attachment.last_sent_sequence
        {
            return Ok(());
        }

        let events = {
            let realtime = self.realtime.borrow();
            buffered_websocket_events_after(
                &realtime.replay_buffer,
                attachment.last_acknowledged_sequence,
                attachment.last_sent_sequence,
            )
        };
        for event in events {
            let payload = decorate_websocket_payload(
                event.payload.clone(),
                event.sequence,
                event.timestamp_ms,
                attachment,
            );
            let payload = mark_replayed_websocket_payload(payload);
            if let Ok(text) = serde_json::to_string(&payload) {
                ws.send_with_str(text.as_str())?;
            }
        }
        Ok(())
    }

    fn ensure_websocket_auto_response(&self) {
        if self.state.get_websocket_auto_response().is_some() {
            return;
        }
        if let Ok(pair) =
            WebSocketRequestResponsePair::new(WEBSOCKET_PING_REQUEST, WEBSOCKET_PING_RESPONSE)
        {
            self.state.set_websocket_auto_response(&pair);
        }
    }

    fn record_websocket_signal(&self, ws: &WebSocket, signal: WebSocketClientSignal) -> Result<()> {
        let now_ms = current_timestamp_ms();
        let Some(mut attachment) = ws.deserialize_attachment::<WebSocketSessionAttachment>()?
        else {
            return Ok(());
        };
        let max_lag = configured_ws_max_lag(&self.env);
        attachment.last_client_activity_ms = now_ms;
        attachment.last_acknowledged_sequence = attachment
            .last_acknowledged_sequence
            .max(signal.acknowledged_sequence());
        if websocket_gap_is_irrecoverable(&attachment, self.oldest_buffered_websocket_sequence()) {
            let lagged_messages =
                websocket_lagged_messages(&attachment, attachment.last_sent_sequence);
            let payload = websocket_lag_disconnect_payload(
                lagged_messages,
                max_lag,
                attachment.last_sent_sequence,
                now_ms,
            );
            ws.send_with_str(serde_json::to_string(&payload)?.as_str())?;
            ws.close(Some(1013), Some("websocket replay window exceeded"))?;
            return Ok(());
        }
        self.replay_websocket_gap(ws, &mut attachment)?;
        ws.serialize_attachment(&attachment)?;
        if signal.should_reply_with_pong() {
            if signal.prefers_json_reply() || attachment.last_sent_sequence > 0 {
                let payload = serde_json::json!({
                    "type": WEBSOCKET_PING_RESPONSE,
                    "last_sequence": attachment.last_sent_sequence,
                    "server_time_ms": now_ms,
                });
                ws.send_with_str(payload.to_string().as_str())?;
            } else {
                ws.send_with_str(WEBSOCKET_PING_RESPONSE)?;
            }
        }
        Ok(())
    }

    fn persist_room_runtime_state(
        &self,
        gid: [u8; 32],
        previous_checkpoint: Option<&RoomStateCheckpoint>,
        server: &cityg_server::CityGServer,
        volatile_snapshot: cityg_runtime::RoomVolatileSnapshot,
        persisted_at_ms: u64,
    ) -> Result<()> {
        let checkpoint = RoomStateCheckpoint {
            snapshot: room_snapshot_with_server_state(
                gid,
                previous_checkpoint,
                export_server_runtime_metadata_bytes(server)?,
                persisted_at_ms,
            ),
            accepted_bundles: previous_checkpoint
                .map(|checkpoint| checkpoint.accepted_bundles.clone())
                .unwrap_or_default(),
            volatile: volatile_snapshot,
        };
        self.persist_room_checkpoint(checkpoint)
    }

    fn persist_room_checkpoint(&self, checkpoint: RoomStateCheckpoint) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;
        store
            .borrow_mut()
            .persist_checkpoint(checkpoint)
            .map_err(|error| worker::Error::from(error.to_string()))
    }

    async fn sync_routing_index_from_checkpoint(&self, gid: [u8; 32]) -> Result<usize> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;
        let Some(checkpoint) = store
            .borrow()
            .load_checkpoint(&gid)
            .map_err(|error| worker::Error::from(error.to_string()))?
        else {
            return Ok(0);
        };
        let entries = derive_room_routing_entries(&checkpoint);
        upsert_routing_entries(&self.env, &entries).await?;
        Ok(entries.len())
    }

    fn load_checkpoint_for_gid(&self, gid: [u8; 32]) -> Result<Option<RoomStateCheckpoint>> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;
        let borrowed = store.borrow();
        if let Some(existing_gid) = infer_room_gid_from_store(&borrowed)? {
            if existing_gid != gid {
                return Err(worker::Error::from(
                    "room durable object storage is bound to a different gid",
                ));
            }
        }
        borrowed
            .load_checkpoint(&gid)
            .map_err(|error| worker::Error::from(error.to_string()))
    }

    fn load_checkpoint_for_target(
        &self,
        target: &RoomScopedRequestTarget,
    ) -> Result<Option<cityg_runtime::RoomStateCheckpoint>> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;
        let borrowed = store.borrow();
        let gid = match target.key {
            RoomScopedRoutingKey::Gid(gid) => {
                if let Some(existing_gid) = infer_room_gid_from_store(&borrowed)? {
                    if existing_gid != gid {
                        return Err(worker::Error::from(
                            "room durable object storage is bound to a different gid",
                        ));
                    }
                }
                Some(gid)
            }
            RoomScopedRoutingKey::WeEpochId(_) => infer_room_gid_from_store(&borrowed)?,
        };
        let Some(gid) = gid else {
            return Ok(None);
        };
        borrowed
            .load_checkpoint(&gid)
            .map_err(|error| worker::Error::from(error.to_string()))
    }

    fn persist_room_volatile_snapshot(
        &self,
        gid: [u8; 32],
        snapshot: cityg_runtime::RoomVolatileSnapshot,
    ) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| worker::Error::from("room storage was not initialized"))?;
        store
            .borrow_mut()
            .persist_volatile_snapshot(gid, snapshot)
            .map_err(|error| worker::Error::from(error.to_string()))
    }
}

async fn extract_native_room_request(
    req: &Request,
) -> Result<Option<(RoomScopedRequestTarget, Vec<u8>)>> {
    let mut clone = req.clone()?;
    let body = clone.bytes().await?;
    let target = extract_room_scoped_request_target(req.path().as_str(), &body)
        .map_err(|error| worker::Error::from(error.to_string()))?;
    Ok(target.map(|target| (target, body)))
}

async fn extract_native_room_target(req: &Request) -> Result<Option<RoomScopedRequestTarget>> {
    Ok(extract_native_room_request(req)
        .await?
        .map(|(target, _)| target))
}

async fn resolve_gid_for_we_epoch_id(env: &Env, we_epoch_id: &[u8; 32]) -> Result<Option<String>> {
    let namespace = env.durable_object(CLOUDFLARE_ROUTING_NAMESPACE_BINDING)?;
    let stub = namespace
        .id_from_name(GLOBAL_ROUTING_OBJECT_NAME)?
        .get_stub()?;
    let route = format!(
        "https://cityg.internal{CLOUDFLARE_ROUTING_ROUTE_PREFIX}/epochs/{}",
        hex::encode(we_epoch_id)
    );
    let request = Request::new(&route, Method::Get)?;
    let mut response = stub.fetch_with_request(request).await?;
    match response.status_code() {
        200 => response.text().await.map(Some),
        404 => Ok(None),
        status => {
            let message = response.text().await.unwrap_or_default();
            Err(worker::Error::from(format!(
                "routing index lookup failed with status {status}: {message}"
            )))
        }
    }
}

async fn resync_and_resolve_gid_for_we_epoch_id(
    env: &Env,
    we_epoch_id: &[u8; 32],
) -> Result<Option<String>> {
    for gid in configured_known_room_gids(env)? {
        register_room_gid(env, gid).await?;
    }
    let namespace = env.durable_object(CLOUDFLARE_ROOM_REGISTRY_NAMESPACE_BINDING)?;
    let stub = namespace
        .id_from_name(GLOBAL_ROOM_REGISTRY_OBJECT_NAME)?
        .get_stub()?;
    let route = format!(
        "https://cityg.internal{CLOUDFLARE_ROOM_REGISTRY_ROUTE_PREFIX}/epochs/{}/resolve",
        hex::encode(we_epoch_id)
    );
    let request = Request::new(&route, Method::Post)?;
    let mut response = stub.fetch_with_request(request).await?;
    match response.status_code() {
        200 => response.text().await.map(Some),
        404 => Ok(None),
        status => {
            let message = response.text().await.unwrap_or_default();
            Err(worker::Error::from(format!(
                "room registry routing convergence failed with status {status}: {message}"
            )))
        }
    }
}

async fn upsert_routing_entries(env: &Env, entries: &[RoomRoutingEntry]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let namespace = env.durable_object(CLOUDFLARE_ROUTING_NAMESPACE_BINDING)?;
    let stub = namespace
        .id_from_name(GLOBAL_ROUTING_OBJECT_NAME)?
        .get_stub()?;
    for entry in entries {
        let route = format!(
            "https://cityg.internal{CLOUDFLARE_ROUTING_ROUTE_PREFIX}/epochs/{}/{}",
            hex::encode(entry.we_epoch_id),
            hex::encode(entry.gid)
        );
        let request = Request::new(&route, Method::Put)?;
        let mut response = stub.fetch_with_request(request).await?;
        if response.status_code() != 204 {
            let message = response.text().await.unwrap_or_default();
            return Err(worker::Error::from(format!(
                "routing index upsert failed with status {}: {message}",
                response.status_code()
            )));
        }
    }
    Ok(())
}

async fn register_room_gid(env: &Env, gid: [u8; 32]) -> Result<()> {
    let namespace = env.durable_object(CLOUDFLARE_ROOM_REGISTRY_NAMESPACE_BINDING)?;
    let stub = namespace
        .id_from_name(GLOBAL_ROOM_REGISTRY_OBJECT_NAME)?
        .get_stub()?;
    let route = format!(
        "https://cityg.internal{CLOUDFLARE_ROOM_REGISTRY_ROUTE_PREFIX}/rooms/{}",
        hex::encode(gid)
    );
    let request = Request::new(&route, Method::Put)?;
    let mut response = stub.fetch_with_request(request).await?;
    if response.status_code() == 204 {
        return Ok(());
    }
    let message = response.text().await.unwrap_or_default();
    Err(worker::Error::from(format!(
        "room registry upsert failed with status {}: {message}",
        response.status_code()
    )))
}

async fn sync_room_routing_entries(env: &Env, gid_hex: &str) -> Result<()> {
    let namespace = env.durable_object(CLOUDFLARE_ROOM_NAMESPACE_BINDING)?;
    let stub = namespace.id_from_name(gid_hex)?.get_stub()?;
    let route =
        format!("https://cityg.internal{CLOUDFLARE_ROOM_ROUTE_PREFIX}/{gid_hex}/sync-routing");
    let request = Request::new(&route, Method::Post)?;
    let mut response = stub.fetch_with_request(request).await?;
    if response.status_code() == 200 {
        return Ok(());
    }
    let message = response.text().await.unwrap_or_default();
    Err(worker::Error::from(format!(
        "room routing sync failed for gid {gid_hex} with status {}: {message}",
        response.status_code()
    )))
}

fn infer_room_gid_from_store(
    store: &DurableObjectRoomStateStore<CloudflareSqlDurableObjectStorage>,
) -> Result<Option<[u8; 32]>> {
    let keys = store
        .storage()
        .list_prefix(ROOM_STORAGE_PREFIX)?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    unique_room_gid_from_keys(keys.iter().map(String::as_str))
}

fn unique_room_gid_from_keys<'a, I>(keys: I) -> Result<Option<[u8; 32]>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut gid = None;
    for key in keys {
        let rest = key.strip_prefix(ROOM_STORAGE_PREFIX).ok_or_else(|| {
            worker::Error::from(format!("unexpected room storage key outside prefix: {key}"))
        })?;
        let gid_hex = rest
            .split('/')
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| worker::Error::from(format!("malformed room storage key: {key}")))?;
        let parsed = parse_gid(gid_hex)?;
        match gid {
            Some(existing) if existing != parsed => {
                return Err(worker::Error::from(
                    "room durable object storage contains multiple gids",
                ));
            }
            None => gid = Some(parsed),
            Some(_) => {}
        }
    }
    Ok(gid)
}

fn route_we_epoch_id(target: &RoomScopedRequestTarget) -> Result<[u8; 32]> {
    match target.key {
        RoomScopedRoutingKey::WeEpochId(we_epoch_id) => Ok(we_epoch_id),
        RoomScopedRoutingKey::Gid(_) => Err(worker::Error::from(
            "expected a we_epoch_id-keyed room route",
        )),
    }
}

fn route_gid(target: &RoomScopedRequestTarget) -> Result<[u8; 32]> {
    match target.key {
        RoomScopedRoutingKey::Gid(gid) => Ok(gid),
        RoomScopedRoutingKey::WeEpochId(_) => {
            Err(worker::Error::from("expected a gid-keyed room route"))
        }
    }
}

#[derive(Debug)]
struct WebSocketSubscription {
    gid: [u8; 32],
    leaf_id: [u8; 32],
}

#[derive(Debug, Default)]
struct RoomRealtimeState {
    next_sequence: u64,
    replay_buffer: VecDeque<BufferedWebSocketEvent>,
}

#[derive(Clone, Debug)]
struct BufferedWebSocketEvent {
    sequence: u64,
    payload: serde_json::Value,
    timestamp_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct WebSocketSessionAttachment {
    gid: [u8; 32],
    leaf_id: [u8; 32],
    #[serde(default)]
    last_client_activity_ms: u64,
    #[serde(default)]
    last_acknowledged_sequence: u64,
    #[serde(default)]
    last_sent_sequence: u64,
    #[serde(default)]
    last_lag_notice_acknowledged_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebSocketClientSignal {
    Ack {
        acknowledged_sequence: u64,
    },
    Ping {
        acknowledged_sequence: u64,
        json: bool,
    },
    Pong {
        acknowledged_sequence: u64,
    },
    Resume {
        acknowledged_sequence: u64,
    },
}

impl WebSocketClientSignal {
    const fn acknowledged_sequence(self) -> u64 {
        match self {
            Self::Ack {
                acknowledged_sequence,
            }
            | Self::Ping {
                acknowledged_sequence,
                ..
            }
            | Self::Pong {
                acknowledged_sequence,
            }
            | Self::Resume {
                acknowledged_sequence,
            } => acknowledged_sequence,
        }
    }

    const fn should_reply_with_pong(self) -> bool {
        matches!(self, Self::Ping { .. })
    }

    const fn prefers_json_reply(self) -> bool {
        matches!(self, Self::Ping { json: true, .. })
    }
}

#[derive(Deserialize)]
struct WebSocketSignalEnvelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    last_sequence: u64,
}

fn parse_ws_max_lag(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(WS_MAX_LAG_DEFAULT)
}

fn configured_ws_max_lag(env: &Env) -> u64 {
    let raw = env.var(WS_MAX_LAG_ENV).ok().map(|value| value.to_string());
    parse_ws_max_lag(raw.as_deref())
}

fn parse_websocket_client_signal(text: &str) -> Option<WebSocketClientSignal> {
    match text {
        WEBSOCKET_PING_REQUEST => {
            return Some(WebSocketClientSignal::Ping {
                acknowledged_sequence: 0,
                json: false,
            });
        }
        WEBSOCKET_PING_RESPONSE => {
            return Some(WebSocketClientSignal::Pong {
                acknowledged_sequence: 0,
            });
        }
        _ => {}
    }

    let envelope: WebSocketSignalEnvelope = serde_json::from_str(text).ok()?;
    match envelope.kind.as_str() {
        WEBSOCKET_ACK_TYPE => Some(WebSocketClientSignal::Ack {
            acknowledged_sequence: envelope.last_sequence,
        }),
        WEBSOCKET_PING_REQUEST => Some(WebSocketClientSignal::Ping {
            acknowledged_sequence: envelope.last_sequence,
            json: true,
        }),
        WEBSOCKET_PING_RESPONSE => Some(WebSocketClientSignal::Pong {
            acknowledged_sequence: envelope.last_sequence,
        }),
        WEBSOCKET_RESUME_TYPE => Some(WebSocketClientSignal::Resume {
            acknowledged_sequence: envelope.last_sequence,
        }),
        _ => None,
    }
}

fn websocket_lagged_messages(attachment: &WebSocketSessionAttachment, sequence: u64) -> u64 {
    if attachment.last_acknowledged_sequence == 0 {
        0
    } else {
        sequence.saturating_sub(attachment.last_acknowledged_sequence)
    }
}

fn websocket_lag_warning_threshold(max_lag: u64) -> u64 {
    (max_lag / 2).max(1)
}

fn websocket_replay_buffer_capacity(max_lag: u64) -> usize {
    usize::try_from(max_lag.max(1)).unwrap_or(usize::MAX)
}

fn push_websocket_replay_event(
    replay_buffer: &mut VecDeque<BufferedWebSocketEvent>,
    event: BufferedWebSocketEvent,
    capacity: usize,
) {
    replay_buffer.push_back(event);
    while replay_buffer.len() > capacity {
        replay_buffer.pop_front();
    }
}

fn websocket_oldest_buffered_sequence(
    replay_buffer: &VecDeque<BufferedWebSocketEvent>,
) -> Option<u64> {
    replay_buffer.front().map(|event| event.sequence)
}

fn buffered_websocket_events_after(
    replay_buffer: &VecDeque<BufferedWebSocketEvent>,
    after_sequence: u64,
    up_to_sequence: u64,
) -> Vec<BufferedWebSocketEvent> {
    replay_buffer
        .iter()
        .filter(|event| event.sequence > after_sequence && event.sequence <= up_to_sequence)
        .cloned()
        .collect()
}

fn should_emit_websocket_lag_notice(
    attachment: &WebSocketSessionAttachment,
    lagged_messages: u64,
    max_lag: u64,
) -> bool {
    attachment.last_acknowledged_sequence > 0
        && lagged_messages >= websocket_lag_warning_threshold(max_lag)
        && lagged_messages <= max_lag
        && attachment.last_lag_notice_acknowledged_sequence != attachment.last_acknowledged_sequence
}

fn websocket_gap_is_irrecoverable(
    attachment: &WebSocketSessionAttachment,
    oldest_retained_sequence: Option<u64>,
) -> bool {
    attachment.last_acknowledged_sequence > 0
        && oldest_retained_sequence
            .is_some_and(|oldest| attachment.last_acknowledged_sequence.saturating_add(1) < oldest)
}

fn decorate_websocket_payload(
    payload: serde_json::Value,
    sequence: u64,
    timestamp_ms: u64,
    attachment: &WebSocketSessionAttachment,
) -> serde_json::Value {
    let lagged_messages = websocket_lagged_messages(attachment, sequence);
    match payload {
        serde_json::Value::Object(mut object) => {
            object.insert("sequence".to_string(), sequence.into());
            object.insert("server_time_ms".to_string(), timestamp_ms.into());
            object.insert(
                "last_client_activity_ms".to_string(),
                attachment.last_client_activity_ms.into(),
            );
            object.insert("connection_healthy".to_string(), true.into());
            if lagged_messages > 0 {
                object.insert("lagged_messages".to_string(), lagged_messages.into());
            }
            serde_json::Value::Object(object)
        }
        other => other,
    }
}

fn mark_replayed_websocket_payload(payload: serde_json::Value) -> serde_json::Value {
    match payload {
        serde_json::Value::Object(mut object) => {
            object.insert("replayed".to_string(), true.into());
            serde_json::Value::Object(object)
        }
        other => other,
    }
}

fn websocket_lag_disconnect_payload(
    lagged_messages: u64,
    max_lag: u64,
    sequence: u64,
    timestamp_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "type": "lag_disconnect",
        "lagged_messages": lagged_messages,
        "max_lag": max_lag,
        "sequence": sequence,
        "server_time_ms": timestamp_ms,
    })
}

fn websocket_lag_payload(
    lagged_messages: u64,
    max_lag: u64,
    sequence: u64,
    timestamp_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "type": "lag",
        "lagged_messages": lagged_messages,
        "max_lag": max_lag,
        "sequence": sequence,
        "server_time_ms": timestamp_ms,
        "recommendation": "consider reconnecting",
    })
}

fn parse_websocket_subscription(
    req: &Request,
) -> std::result::Result<WebSocketSubscription, &'static str> {
    let url = req.url().map_err(|_| "failed to parse websocket url")?;
    parse_websocket_subscription_url(url.as_str())
}

fn parse_websocket_subscription_url(
    url: &str,
) -> std::result::Result<WebSocketSubscription, &'static str> {
    let query = url
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default();
    let mut gid = None;
    let mut leaf_id = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "gid" => gid = Some(parse_hex_32_query(value, "gid")?),
            "leaf_id" => leaf_id = Some(parse_hex_32_query(value, "leaf_id")?),
            _ => {}
        }
    }
    Ok(WebSocketSubscription {
        gid: gid.ok_or("gid must be provided")?,
        leaf_id: leaf_id.ok_or("leaf_id must be provided")?,
    })
}

fn parse_hex_32_query(
    value: &str,
    label: &'static str,
) -> std::result::Result<[u8; 32], &'static str> {
    if value.len() != 64 {
        return Err(match label {
            "gid" => "gid must be 64 hex characters",
            "leaf_id" => "leaf_id must be 64 hex characters",
            _ => "value must be 64 hex characters",
        });
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| match label {
        "gid" => "gid must be 64 hex characters",
        "leaf_id" => "leaf_id must be 64 hex characters",
        _ => "value must be 64 hex characters",
    })?;
    Ok(bytes)
}

fn websocket_upgrade_requested(req: &Request) -> bool {
    websocket_upgrade_requested_value(req.headers().get("Upgrade").ok().flatten().as_deref())
}

fn websocket_upgrade_requested_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

fn export_server_runtime_metadata_bytes(server: &cityg_server::CityGServer) -> Result<Vec<u8>> {
    server
        .export_runtime_metadata_bytes()
        .map_err(|error| worker::Error::from(error.to_string()))
}

fn room_snapshot_with_server_state(
    gid: [u8; 32],
    previous_checkpoint: Option<&RoomStateCheckpoint>,
    server_state_bytes: Vec<u8>,
    persisted_at_ms: u64,
) -> RoomSnapshot {
    let accepted_bundle_count = previous_checkpoint
        .map(|checkpoint| {
            checkpoint
                .snapshot
                .accepted_bundle_count
                .max(checkpoint.accepted_bundles.len() as u64)
        })
        .unwrap_or(0);
    RoomSnapshot {
        gid,
        format_version: previous_checkpoint
            .map(|checkpoint| checkpoint.snapshot.format_version)
            .filter(|version| *version != 0)
            .unwrap_or(ROOM_SNAPSHOT_FORMAT_VERSION),
        server_state_bytes,
        last_parent_root: previous_checkpoint
            .and_then(|checkpoint| checkpoint.snapshot.last_parent_root),
        last_we_epoch_id: previous_checkpoint
            .and_then(|checkpoint| checkpoint.snapshot.last_we_epoch_id),
        accepted_bundle_count,
        persisted_at_ms,
    }
}

fn room_snapshot_after_accept(
    gid: [u8; 32],
    previous_checkpoint: Option<&RoomStateCheckpoint>,
    server_state_bytes: Vec<u8>,
    accepted: &AcceptedRoomEpoch,
    persisted_at_ms: u64,
) -> RoomSnapshot {
    let mut snapshot = room_snapshot_with_server_state(
        gid,
        previous_checkpoint,
        server_state_bytes,
        persisted_at_ms,
    );
    snapshot.last_parent_root = Some(accepted.outcome.parent_root);
    snapshot.last_we_epoch_id = Some(accepted.outcome.we_epoch_id);
    snapshot.accepted_bundle_count = snapshot.accepted_bundle_count.saturating_add(1);
    snapshot
}

fn accept_epoch_error_response(err: RoomAcceptEpochError) -> Result<Response> {
    match err {
        RoomAcceptEpochError::Client(ClientError::InvalidInput(_))
        | RoomAcceptEpochError::Client(ClientError::Acceptance(AcceptanceError::Msphf(
            MsphfError::InvalidInput(_),
        ))) => Response::error("invalid bundle components", 400),
        RoomAcceptEpochError::Client(ClientError::Acceptance(AcceptanceError::Freeze(freeze))) => {
            Response::error(format!("acceptance error: {}", freeze.reason), 500)
        }
        RoomAcceptEpochError::Client(ClientError::Acceptance(other)) => {
            Response::error(format!("acceptance error: {other:?}"), 500)
        }
        RoomAcceptEpochError::Client(other) => Response::error(other.to_string(), 500),
        RoomAcceptEpochError::Materialization(error) => Response::error(error.to_string(), 500),
        RoomAcceptEpochError::Service(RoomServiceError::InvalidGidLength) => {
            Response::error("invalid gid length in bundle", 500)
        }
        RoomAcceptEpochError::Service(RoomServiceError::MembershipDelta(message)) => {
            Response::error(
                format!("failed to compute membership delta: {message}"),
                500,
            )
        }
    }
}

fn barrier_client_error_response(err: ClientError) -> Result<Response> {
    match err {
        ClientError::InvalidInput("group not found")
        | ClientError::InvalidInput("historical barrier public tree snapshot unavailable") => {
            Response::error("resource not found", 404)
        }
        ClientError::InvalidInput(message) => Response::error(message, 400),
        other => Response::error(other.to_string(), 500),
    }
}

fn barrier_envelope_error_response(err: RoomBarrierEnvelopeError) -> Result<Response> {
    match err {
        RoomBarrierEnvelopeError::Client(err) => barrier_client_error_response(err),
        other => Response::error(other.to_string(), 500),
    }
}

fn barrier_pagination_error_response(err: BarrierPaginationError) -> Result<Response> {
    match err {
        BarrierPaginationError::MaxEntriesExceedsLimit => {
            Response::error("max_entries exceeds MAX_BARRIER_HELPER_PAGE_ENTRIES", 400)
        }
        BarrierPaginationError::PageOffsetOutOfRange => {
            Response::error("page_offset out of range", 400)
        }
        BarrierPaginationError::MaxEntriesOutOfRange => {
            Response::error("max_entries out of range", 400)
        }
        BarrierPaginationError::TotalEntriesOverflow
        | BarrierPaginationError::NextPageOffsetOverflow => Response::error(err.to_string(), 500),
    }
}

fn barrier_helper_error_response(err: RoomBarrierHelperPreparationError) -> Result<Response> {
    match err {
        RoomBarrierHelperPreparationError::Client(err) => barrier_client_error_response(err),
        RoomBarrierHelperPreparationError::Envelope(err) => barrier_envelope_error_response(err),
        RoomBarrierHelperPreparationError::Pagination(err) => {
            barrier_pagination_error_response(err)
        }
    }
}

fn full_verification_witness_error_response(
    err: RoomFullVerificationWitnessPreparationError,
) -> Result<Response> {
    match err {
        RoomFullVerificationWitnessPreparationError::Client(err) => {
            Response::error(err.to_string(), 500)
        }
        RoomFullVerificationWitnessPreparationError::HelperClient(err) => {
            barrier_client_error_response(err)
        }
        RoomFullVerificationWitnessPreparationError::Ticket(err) => {
            ticket_preparation_error_response(err)
        }
        RoomFullVerificationWitnessPreparationError::GroupNotFound => {
            Response::error("group not found", 400)
        }
        RoomFullVerificationWitnessPreparationError::CurrentHistoryCommitmentMismatch => {
            Response::error(
                "current_history_commitment mismatch with authenticated current state",
                400,
            )
        }
        RoomFullVerificationWitnessPreparationError::JoinsPrevBarrierVersionMismatch => {
            Response::error(
                "joins_prev_barrier_version mismatch with authenticated current state",
                400,
            )
        }
        RoomFullVerificationWitnessPreparationError::GlobalHistoryAttestationMismatch => {
            Response::error(
                "current_global_history_attestation mismatch with authenticated current state",
                400,
            )
        }
        RoomFullVerificationWitnessPreparationError::DeploymentProfileManifestMismatch => {
            Response::error(
                "deployment_profile_manifest mismatch with authenticated current state",
                400,
            )
        }
        RoomFullVerificationWitnessPreparationError::MergeTicketArtifactMismatch => {
            Response::error(
                "merge_ticket_artifact mismatch with authenticated current state",
                400,
            )
        }
        RoomFullVerificationWitnessPreparationError::RevocationRootsHashMismatch => {
            Response::error(
                "revocation_roots_hash mismatch with authenticated current state",
                400,
            )
        }
        RoomFullVerificationWitnessPreparationError::JoinHelperDataMismatch => Response::error(
            "join helper data mismatch with authenticated current state",
            400,
        ),
        RoomFullVerificationWitnessPreparationError::RevokedHelperDataMismatch => Response::error(
            "revoked helper data mismatch with authenticated current state",
            400,
        ),
        RoomFullVerificationWitnessPreparationError::CoverLeafIndexOutOfRange => {
            Response::error("cover_leaf_index out of range", 400)
        }
    }
}

fn ticket_preparation_error_response(err: RoomTicketPreparationError) -> Result<Response> {
    match err {
        RoomTicketPreparationError::Client(ClientError::InvalidInput(message)) => {
            Response::error(message, 400)
        }
        RoomTicketPreparationError::Client(other) => Response::error(other.to_string(), 500),
        other => Response::error(other.to_string(), 500),
    }
}

fn client_error_response(err: ClientError) -> Result<Response> {
    match err {
        ClientError::InvalidInput(message) => Response::error(message, 400),
        other => Response::error(other.to_string(), 500),
    }
}

fn refresh_pivot_error_response(err: ClientError) -> Result<Response> {
    match err {
        ClientError::InvalidInput(message)
            if classify_refresh_pivot_conflict(message).is_some() =>
        {
            Response::error(err.to_string(), 409)
        }
        other => Response::error(other.to_string(), 500),
    }
}

fn room_admin_proof_validation_error_response(
    err: RoomAdminProofValidationError,
) -> Result<Response> {
    match err {
        RoomAdminProofValidationError::InvalidPublicKeyLength => {
            Response::error("invalid room admin public key length", 400)
        }
        RoomAdminProofValidationError::InvalidSignatureLength => {
            Response::error("invalid room admin signature length", 400)
        }
        RoomAdminProofValidationError::MissingRoomId => {
            Response::error("room_id must be provided", 400)
        }
        RoomAdminProofValidationError::EncodeProofMessage => {
            Response::error("failed to encode room admin proof message", 400)
        }
        RoomAdminProofValidationError::InvalidPublicKey => {
            Response::error("invalid room admin public key", 400)
        }
        RoomAdminProofValidationError::InvalidSignature => {
            Response::error("invalid room admin signature", 400)
        }
        RoomAdminProofValidationError::VerificationFailed => {
            Response::error("room admin proof verification failed", 400)
        }
        RoomAdminProofValidationError::MissingKbroadPublic => {
            Response::error("kbroad_public must be provided", 400)
        }
        RoomAdminProofValidationError::EncodePayload => {
            Response::error("failed to encode room admin proof payload", 400)
        }
        RoomAdminProofValidationError::ReplayKey(message) => Response::error(message, 500),
    }
}

fn room_admin_request_validation_error_response(
    err: RoomAdminRequestValidationError,
) -> Result<Response> {
    if err.is_unauthorized() {
        Response::error(err.to_string(), 401)
    } else {
        Response::error(err.to_string(), 400)
    }
}

fn expel_member_ticket_request_validation_error_response(
    err: ExpelMemberTicketRequestValidationError,
) -> Result<Response> {
    if err.is_unauthorized() {
        Response::error(err.to_string(), 401)
    } else {
        Response::error(err.to_string(), 400)
    }
}

fn merge_ticket_request_validation_error_response(
    err: MergeTicketRequestValidationError,
) -> Result<Response> {
    Response::error(err.to_string(), 400)
}

fn fetch_messages_request_validation_error_response(
    err: FetchMessagesRequestValidationError,
) -> Result<Response> {
    Response::error(err.to_string(), 400)
}

fn members_request_validation_error_response(
    err: MembersRequestValidationError,
) -> Result<Response> {
    Response::error(err.to_string(), 400)
}

fn search_members_request_validation_error_response(
    err: SearchMembersRequestValidationError,
) -> Result<Response> {
    Response::error(err.to_string(), 400)
}

fn join_ticket_request_preparation_error_response(
    err: JoinTicketRequestPreparationError,
) -> Result<Response> {
    if err.is_client_error() {
        Response::error(err.api_message().as_ref(), 400)
    } else {
        Response::error(err.api_message().into_owned(), 500)
    }
}

fn send_message_request_validation_error_response(
    err: SendMessageRequestValidationError,
) -> Result<Response> {
    Response::error(err.to_string(), 400)
}

fn get_bundle_request_validation_error_response(
    err: GetBundleRequestValidationError,
) -> Result<Response> {
    Response::error(err.to_string(), 400)
}

fn bundle_cbor_request_decode_error_response(
    err: BundleCborRequestDecodeError,
) -> Result<Response> {
    match err {
        BundleCborRequestDecodeError::MissingBundleCbor => {
            Response::error("bundle_cbor must be provided", 400)
        }
        BundleCborRequestDecodeError::InvalidBundleEncoding => {
            Response::error("invalid bundle encoding", 400)
        }
        BundleCborRequestDecodeError::DecodeFailure(message) => Response::error(message, 500),
    }
}

#[derive(Clone, Copy, Debug)]
enum RoomAdminMutationKind {
    Grant,
    Revoke,
}

impl RoomAdminMutationKind {
    const fn operation(self) -> &'static str {
        match self {
            Self::Grant => "grant_room_admin_v1",
            Self::Revoke => "revoke_room_admin_v1",
        }
    }

    const fn status(self, applied: bool) -> &'static str {
        match (self, applied) {
            (Self::Grant, true) => "granted",
            (Self::Grant, false) => "already_granted",
            (Self::Revoke, true) => "revoked",
            (Self::Revoke, false) => "already_revoked",
        }
    }
}

fn configured_message_auth_token(env: &Env) -> Option<String> {
    env.var(MESSAGE_AUTH_TOKEN_ENV)
        .ok()
        .map(|value| value.to_string().trim().to_string())
        .filter(|value| !value.is_empty())
}

fn enforce_message_auth_header(
    req: &Request,
    expected_token: Option<&str>,
) -> std::result::Result<(), &'static str> {
    let Some(expected_token) = expected_token else {
        return Err("message auth token is not configured");
    };
    let provided = req.headers().get(MESSAGE_AUTH_HEADER).ok().flatten();
    if provided.as_deref() == Some(expected_token) {
        Ok(())
    } else {
        Err("missing or invalid message auth token")
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn message_retention() -> Duration {
    Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS)
}

fn protobuf_response<M: Message>(message: &M) -> Result<Response> {
    let mut response = Response::from_bytes(message.encode_to_vec())?;
    response
        .headers_mut()
        .set("content-type", "application/x-protobuf")?;
    Ok(response)
}

fn protobuf_response_bytes(payload: Vec<u8>) -> Result<Response> {
    let mut response = Response::from_bytes(payload)?;
    response
        .headers_mut()
        .set("content-type", "application/x-protobuf")
        .map_err(worker::Error::from)?;
    Ok(response)
}

pub struct CloudflareRoutingDurableObject {
    index: Option<CloudflareWeEpochRoutingIndex>,
    init_error: Option<String>,
}

impl CloudflareRoutingDurableObject {
    #[must_use]
    pub fn new(state: State, _env: Env) -> Self {
        match CloudflareWeEpochRoutingIndex::new(state.storage().sql()) {
            Ok(index) => Self {
                index: Some(index),
                init_error: None,
            },
            Err(error) => Self {
                index: None,
                init_error: Some(error.to_string()),
            },
        }
    }

    pub async fn fetch(&self, req: Request) -> Result<Response> {
        if let Some(init_error) = &self.init_error {
            return Response::error(
                format!("failed to initialize Cloudflare routing index: {init_error}"),
                500,
            );
        }

        let path = req.path();
        let route = parse_routing_index_route(&path)
            .ok_or_else(|| worker::Error::from("unsupported Cloudflare routing index route"))?;
        let index = self
            .index
            .as_ref()
            .ok_or_else(|| worker::Error::from("routing index was not initialized"))?;

        match (req.method(), route.action) {
            (Method::Get, RoutingIndexRouteAction::Resolve) => {
                let Some(gid_hex) = index.lookup_gid_hex(route.we_epoch_id_hex)? else {
                    return Response::error("routing entry not found", 404);
                };
                Response::ok(gid_hex)
            }
            (Method::Put, RoutingIndexRouteAction::Upsert { gid_hex }) => {
                validate_hex_32(route.we_epoch_id_hex, "we_epoch_id")?;
                validate_hex_32(gid_hex, "gid")?;
                index.upsert(route.we_epoch_id_hex, gid_hex)?;
                Response::empty().map(|response| response.with_status(204))
            }
            _ => Response::error("method not allowed", 405),
        }
    }
}

pub struct CloudflareRoomRegistryDurableObject {
    registry: Option<CloudflareRoomRegistry>,
    env: Env,
    init_error: Option<String>,
}

impl CloudflareRoomRegistryDurableObject {
    #[must_use]
    pub fn new(state: State, env: Env) -> Self {
        match CloudflareRoomRegistry::new(state.storage().sql()) {
            Ok(registry) => Self {
                registry: Some(registry),
                env,
                init_error: None,
            },
            Err(error) => Self {
                registry: None,
                env,
                init_error: Some(error.to_string()),
            },
        }
    }

    pub async fn fetch(&self, req: Request) -> Result<Response> {
        if let Some(init_error) = &self.init_error {
            return Response::error(
                format!("failed to initialize Cloudflare room registry: {init_error}"),
                500,
            );
        }

        let path = req.path();
        let route = parse_room_registry_route(&path)
            .ok_or_else(|| worker::Error::from("unsupported Cloudflare room registry route"))?;
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| worker::Error::from("room registry was not initialized"))?;

        match (req.method(), route.action) {
            (Method::Put, RoomRegistryRouteAction::Register { gid_hex }) => {
                validate_hex_32(gid_hex, "gid")?;
                registry.upsert(gid_hex)?;
                Response::empty().map(|response| response.with_status(204))
            }
            (Method::Post, RoomRegistryRouteAction::Resolve { we_epoch_id_hex }) => {
                validate_hex_32(we_epoch_id_hex, "we_epoch_id")?;
                let mut we_epoch_id = [0u8; 32];
                hex::decode_to_slice(we_epoch_id_hex, &mut we_epoch_id).map_err(|error| {
                    worker::Error::from(format!("we_epoch_id must be valid hex: {error}"))
                })?;

                if let Some(gid_hex) = resolve_gid_for_we_epoch_id(&self.env, &we_epoch_id).await? {
                    return Response::ok(gid_hex);
                }

                for gid_hex in registry.list_gid_hexes()? {
                    sync_room_routing_entries(&self.env, gid_hex.as_str()).await?;
                    if let Some(resolved_gid_hex) =
                        resolve_gid_for_we_epoch_id(&self.env, &we_epoch_id).await?
                    {
                        return Response::ok(resolved_gid_hex);
                    }
                }

                Response::error("routing entry not found", 404)
            }
            _ => Response::error("method not allowed", 405),
        }
    }
}

pub struct CloudflareAliasDurableObject {
    storage: Option<RefCell<CloudflareSqlDurableObjectStorage>>,
    init_error: Option<String>,
}

impl CloudflareAliasDurableObject {
    #[must_use]
    pub fn new(state: State, _env: Env) -> Self {
        match CloudflareSqlDurableObjectStorage::new(state.storage().sql()) {
            Ok(storage) => Self {
                storage: Some(RefCell::new(storage)),
                init_error: None,
            },
            Err(error) => Self {
                storage: None,
                init_error: Some(error.to_string()),
            },
        }
    }

    pub async fn fetch(&self, req: Request) -> Result<Response> {
        if let Some(init_error) = &self.init_error {
            return Response::error(
                format!("failed to initialize Cloudflare alias registry: {init_error}"),
                500,
            );
        }

        let path = req.path();
        let route = parse_alias_route(&path)
            .ok_or_else(|| worker::Error::from("unsupported Cloudflare alias registry route"))?;

        match (req.method(), route.action) {
            (Method::Post, AliasRouteAction::Register) => {
                let request: AliasRegisterRequest = decode_json_request(req).await?;
                let leaf_id = parse_gid(request.leaf_id_hex.as_str())?;
                let pop_public_key = hex::decode(request.pop_public_key_hex)
                    .map_err(|_| worker::Error::from("pop_public_key must be valid hex"))?;

                let mut registry = self.load_alias_registry()?;
                let outcome = match registry.register_alias(
                    request.alias.as_str(),
                    leaf_id,
                    pop_public_key,
                ) {
                    Ok(outcome) => outcome,
                    Err(AliasRegistrationError::Conflict) => {
                        return Response::error("alias already bound to a different identity", 409);
                    }
                };
                self.persist_alias_registry(&registry)?;

                Response::from_json(&AliasRegisterResponse {
                    registered_new_alias: outcome.is_new(),
                    updated_leaf_binding: matches!(
                        outcome,
                        cityg_runtime::AliasRegistrationOutcome::UpdatedLeafBinding
                    ),
                })
            }
            (Method::Post, AliasRouteAction::LookupByLeaf) => {
                let request: AliasLeafLookupRequest = decode_json_request(req).await?;
                let mut leaves = Vec::with_capacity(request.leaf_ids_hex.len());
                for leaf_id_hex in request.leaf_ids_hex {
                    leaves.push(parse_gid(leaf_id_hex.as_str())?);
                }
                let lookup = self.load_alias_registry()?.leaf_lookup_for(leaves);
                Response::from_json(&AliasLeafLookupResponse {
                    bindings: lookup
                        .into_iter()
                        .map(|(leaf_id, entry)| AliasLeafLookupEntry {
                            leaf_id_hex: hex::encode(leaf_id),
                            alias: entry.alias,
                            pop_public_key_hex: hex::encode(entry.pop_public_key),
                        })
                        .collect(),
                })
            }
            (Method::Post, AliasRouteAction::UnbindRevoked) => {
                let request: AliasLeafLookupRequest = decode_json_request(req).await?;
                let mut leaves = Vec::with_capacity(request.leaf_ids_hex.len());
                for leaf_id_hex in request.leaf_ids_hex {
                    leaves.push(parse_gid(leaf_id_hex.as_str())?);
                }

                let mut registry = self.load_alias_registry()?;
                let removed_count = registry.remove_revoked_slice(leaves.as_slice());
                self.persist_alias_registry(&registry)?;
                Response::from_json(&AliasMutationResponse {
                    updated_count: removed_count,
                })
            }
            _ => Response::error("method not allowed", 405),
        }
    }

    fn load_alias_registry(&self) -> Result<AliasRegistry> {
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| worker::Error::from("alias storage was not initialized"))?;
        let borrowed = storage.borrow();
        let Some(bytes) = borrowed.get_bytes(ALIAS_REGISTRY_STORAGE_KEY)? else {
            return Ok(AliasRegistry::default());
        };
        ciborium::from_reader(bytes.as_slice()).map_err(|error| {
            worker::Error::from(format!("failed to decode alias registry: {error}"))
        })
    }

    fn persist_alias_registry(&self, registry: &AliasRegistry) -> Result<()> {
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| worker::Error::from("alias storage was not initialized"))?;
        let mut bytes = Vec::new();
        ciborium::into_writer(registry, &mut bytes).map_err(|error| {
            worker::Error::from(format!("failed to encode alias registry: {error}"))
        })?;
        storage
            .borrow_mut()
            .put_bytes(ALIAS_REGISTRY_STORAGE_KEY, bytes)
    }
}

pub struct CloudflareSqlDurableObjectStorage {
    sql: SqlStorage,
}

impl CloudflareSqlDurableObjectStorage {
    pub fn new(sql: SqlStorage) -> Result<Self> {
        sql.exec(
            &format!(
                "CREATE TABLE IF NOT EXISTS {ROOM_STATE_TABLE} (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                ) WITHOUT ROWID"
            ),
            None,
        )?;
        Ok(Self { sql })
    }

    #[must_use]
    pub fn database_size_bytes(&self) -> usize {
        self.sql.database_size()
    }
}

pub struct CloudflareWeEpochRoutingIndex {
    sql: SqlStorage,
}

impl CloudflareWeEpochRoutingIndex {
    pub fn new(sql: SqlStorage) -> Result<Self> {
        sql.exec(
            &format!(
                "CREATE TABLE IF NOT EXISTS {ROUTING_INDEX_TABLE} (
                    we_epoch_id_hex TEXT PRIMARY KEY NOT NULL,
                    gid_hex TEXT NOT NULL
                ) WITHOUT ROWID"
            ),
            None,
        )?;
        Ok(Self { sql })
    }

    pub fn lookup_gid_hex(&self, we_epoch_id_hex: &str) -> Result<Option<String>> {
        let mut rows = self
            .sql
            .exec(
                &format!(
                    "SELECT gid_hex FROM {ROUTING_INDEX_TABLE}
                     WHERE we_epoch_id_hex = ?
                     LIMIT 1"
                ),
                vec![we_epoch_id_hex.into()],
            )?
            .raw();
        match rows.next() {
            Some(Ok(row)) => match row.as_slice() {
                [SqlStorageValue::String(gid_hex)] => Ok(Some(gid_hex.clone())),
                _ => Err(worker::Error::from("unexpected routing index row shape")),
            },
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    pub fn upsert(&self, we_epoch_id_hex: &str, gid_hex: &str) -> Result<()> {
        self.sql.exec(
            &format!(
                "INSERT INTO {ROUTING_INDEX_TABLE} (we_epoch_id_hex, gid_hex)
                 VALUES (?, ?)
                 ON CONFLICT(we_epoch_id_hex) DO UPDATE SET gid_hex = excluded.gid_hex"
            ),
            vec![we_epoch_id_hex.into(), gid_hex.into()],
        )?;
        Ok(())
    }
}

pub struct CloudflareRoomRegistry {
    sql: SqlStorage,
}

impl CloudflareRoomRegistry {
    pub fn new(sql: SqlStorage) -> Result<Self> {
        sql.exec(
            &format!(
                "CREATE TABLE IF NOT EXISTS {ROOM_REGISTRY_TABLE} (
                    gid_hex TEXT PRIMARY KEY NOT NULL
                ) WITHOUT ROWID"
            ),
            None,
        )?;
        Ok(Self { sql })
    }

    pub fn upsert(&self, gid_hex: &str) -> Result<()> {
        self.sql.exec(
            &format!(
                "INSERT INTO {ROOM_REGISTRY_TABLE} (gid_hex)
                 VALUES (?)
                 ON CONFLICT(gid_hex) DO NOTHING"
            ),
            vec![gid_hex.into()],
        )?;
        Ok(())
    }

    pub fn list_gid_hexes(&self) -> Result<Vec<String>> {
        let mut rows = self
            .sql
            .exec(
                &format!("SELECT gid_hex FROM {ROOM_REGISTRY_TABLE} ORDER BY gid_hex ASC"),
                None,
            )?
            .raw();
        let mut gids = Vec::new();
        while let Some(row) = rows.next() {
            match row? {
                row if matches!(row.as_slice(), [SqlStorageValue::String(_)]) => {
                    let SqlStorageValue::String(gid_hex) = &row.as_slice()[0] else {
                        unreachable!();
                    };
                    gids.push(gid_hex.clone());
                }
                _ => return Err(worker::Error::from("unexpected room registry row shape")),
            }
        }
        Ok(gids)
    }
}

impl DurableObjectStorage for CloudflareSqlDurableObjectStorage {
    type Error = worker::Error;

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let mut rows = self
            .sql
            .exec(
                &format!("SELECT value FROM {ROOM_STATE_TABLE} WHERE key = ? LIMIT 1"),
                vec![key.into()],
            )?
            .raw();
        match rows.next() {
            Some(Ok(row)) => match row.as_slice() {
                [SqlStorageValue::Blob(buffer)] => Ok(Some(buffer.clone())),
                _ => Err(worker::Error::from(
                    "unexpected durable object value row shape",
                )),
            },
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    fn put_bytes(&mut self, key: &str, value: Vec<u8>) -> Result<(), Self::Error> {
        self.sql.exec(
            &format!(
                "INSERT INTO {ROOM_STATE_TABLE} (key, value)
                 VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ),
            vec![key.into(), value.into()],
        )?;
        Ok(())
    }

    fn delete_bytes(&mut self, key: &str) -> Result<(), Self::Error> {
        self.sql.exec(
            &format!("DELETE FROM {ROOM_STATE_TABLE} WHERE key = ?"),
            vec![key.into()],
        )?;
        Ok(())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Self::Error> {
        let rows = self
            .sql
            .exec(
                &format!(
                    "SELECT key, value FROM {ROOM_STATE_TABLE}
                     WHERE key LIKE ?
                     ORDER BY key ASC"
                ),
                vec![format!("{prefix}%").into()],
            )?
            .raw();

        let mut entries = Vec::new();
        for row in rows {
            match row?.as_slice() {
                [SqlStorageValue::String(key), SqlStorageValue::Blob(buffer)] => {
                    entries.push((key.clone(), buffer.clone()));
                }
                _ => {
                    return Err(worker::Error::from(
                        "unexpected durable object key/value row shape",
                    ));
                }
            }
        }
        Ok(entries)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoomRouteAction {
    Status,
    Checkpoint,
    SyncRouting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RoomRoute<'a> {
    gid_hex: &'a str,
    action: RoomRouteAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoutingIndexRouteAction<'a> {
    Resolve,
    Upsert { gid_hex: &'a str },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RoutingIndexRoute<'a> {
    we_epoch_id_hex: &'a str,
    action: RoutingIndexRouteAction<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoomRegistryRouteAction<'a> {
    Register { gid_hex: &'a str },
    Resolve { we_epoch_id_hex: &'a str },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RoomRegistryRoute<'a> {
    action: RoomRegistryRouteAction<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AliasRouteAction {
    Register,
    LookupByLeaf,
    UnbindRevoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AliasRoute<'a> {
    action: AliasRouteAction,
    _marker: std::marker::PhantomData<&'a ()>,
}

#[derive(Debug, Serialize)]
struct RoomStatusResponse {
    gid: String,
    durable_object_id: String,
    storage_backend: &'static str,
    sqlite_database_size_bytes: usize,
    routing_entry_count: usize,
    rehydration: Option<RoomRehydrationSummary>,
    checkpoint: Option<RoomCheckpointSummary>,
}

#[derive(Debug, Serialize)]
struct RoomRoutingSyncResponse {
    gid: String,
    synced_entries: usize,
}

#[derive(Debug, Serialize)]
struct RoomRehydrationSummary {
    replay_ready: bool,
    accepted_bundle_replay_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RoomCheckpointSummary {
    accepted_bundle_count: usize,
    member_metadata_count: usize,
    epoch_scope_count: usize,
    message_count: usize,
    stored_bundle_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct AliasRegisterRequest {
    alias: String,
    leaf_id_hex: String,
    pop_public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AliasRegisterResponse {
    registered_new_alias: bool,
    updated_leaf_binding: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct AliasLeafLookupRequest {
    leaf_ids_hex: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AliasLeafLookupEntry {
    leaf_id_hex: String,
    alias: String,
    pop_public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AliasLeafLookupResponse {
    bindings: Vec<AliasLeafLookupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AliasMutationResponse {
    updated_count: usize,
}

#[derive(Debug)]
enum AliasRemoteError {
    Conflict,
    Backend(String),
}

impl From<&cityg_runtime::RoomStateCheckpoint> for RoomCheckpointSummary {
    fn from(checkpoint: &cityg_runtime::RoomStateCheckpoint) -> Self {
        Self {
            accepted_bundle_count: checkpoint.accepted_bundles.len(),
            member_metadata_count: checkpoint.volatile.member_metadata.len(),
            epoch_scope_count: checkpoint.volatile.epoch_scopes.len(),
            message_count: checkpoint.volatile.messages.len(),
            stored_bundle_count: checkpoint.volatile.bundles.len(),
        }
    }
}

fn parse_room_route(path: &str) -> Option<RoomRoute<'_>> {
    let mut segments = path.trim_matches('/').split('/');
    if segments.next()? != "__cloudflare" {
        return None;
    }
    if segments.next()? != "rooms" {
        return None;
    }
    let gid_hex = segments.next()?;
    let action = match segments.next()? {
        "status" => RoomRouteAction::Status,
        "checkpoint" => RoomRouteAction::Checkpoint,
        "sync-routing" => RoomRouteAction::SyncRouting,
        _ => return None,
    };
    if segments.next().is_some() {
        return None;
    }
    Some(RoomRoute { gid_hex, action })
}

fn parse_gid(gid_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(gid_hex).map_err(|error| worker::Error::from(error.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| worker::Error::from("expected a 32-byte gid hex string"))
}

fn parse_routing_index_route(path: &str) -> Option<RoutingIndexRoute<'_>> {
    let mut segments = path.trim_matches('/').split('/');
    if segments.next()? != "__cloudflare" {
        return None;
    }
    if segments.next()? != "routing" {
        return None;
    }
    if segments.next()? != "epochs" {
        return None;
    }
    let we_epoch_id_hex = segments.next()?;
    let action = match segments.next() {
        None => RoutingIndexRouteAction::Resolve,
        Some(gid_hex) => RoutingIndexRouteAction::Upsert { gid_hex },
    };
    if segments.next().is_some() {
        return None;
    }
    Some(RoutingIndexRoute {
        we_epoch_id_hex,
        action,
    })
}

fn parse_room_registry_route(path: &str) -> Option<RoomRegistryRoute<'_>> {
    let mut segments = path.trim_matches('/').split('/');
    if segments.next()? != "__cloudflare" {
        return None;
    }
    if segments.next()? != "room-registry" {
        return None;
    }
    let action = match segments.next()? {
        "rooms" => RoomRegistryRouteAction::Register {
            gid_hex: segments.next()?,
        },
        "epochs" => RoomRegistryRouteAction::Resolve {
            we_epoch_id_hex: segments.next()?,
        },
        _ => return None,
    };
    match action {
        RoomRegistryRouteAction::Register { .. } => {
            if segments.next().is_some() {
                return None;
            }
        }
        RoomRegistryRouteAction::Resolve { .. } => {
            if segments.next()? != "resolve" || segments.next().is_some() {
                return None;
            }
        }
    }
    Some(RoomRegistryRoute { action })
}

fn parse_alias_route(path: &str) -> Option<AliasRoute<'_>> {
    let mut segments = path.trim_matches('/').split('/');
    if segments.next()? != "__cloudflare" {
        return None;
    }
    if segments.next()? != "aliases" {
        return None;
    }
    let action = match segments.next()? {
        "register" => AliasRouteAction::Register,
        "lookup-by-leaf" => AliasRouteAction::LookupByLeaf,
        "unbind-revoked" => AliasRouteAction::UnbindRevoked,
        _ => return None,
    };
    if segments.next().is_some() {
        return None;
    }
    Some(AliasRoute {
        action,
        _marker: std::marker::PhantomData,
    })
}

fn validate_hex_32(value: &str, label: &str) -> Result<()> {
    let bytes = hex::decode(value)
        .map_err(|_| worker::Error::from(format!("{label} must be a 64-character hex string")))?;
    let _: [u8; 32] = bytes
        .try_into()
        .map_err(|_| worker::Error::from(format!("{label} must be 32 bytes")))?;
    Ok(())
}

fn rehydration_bootstrap() -> WorkerRoomBootstrap {
    WorkerRoomBootstrap {
        history_authority: WorkerHistoryAuthority::Disabled,
        ..WorkerRoomBootstrap::default()
    }
}

fn configured_room_bootstrap(env: &Env) -> Result<WorkerRoomBootstrap> {
    match env.var(WORKER_CONFIG_JSON_ENV) {
        Ok(value) => WorkerRoomBootstrap::from_config_json(&value.to_string()).map_err(|error| {
            worker::Error::from(format!("invalid {WORKER_CONFIG_JSON_ENV}: {error}"))
        }),
        Err(_) => Ok(rehydration_bootstrap()),
    }
}

fn configured_known_room_gids(env: &Env) -> Result<Vec<[u8; 32]>> {
    match env.var(WORKER_KNOWN_GIDS_JSON_ENV) {
        Ok(value) => parse_known_room_gids_json(&value.to_string()).map_err(|error| {
            worker::Error::from(format!("invalid {WORKER_KNOWN_GIDS_JSON_ENV}: {error}"))
        }),
        Err(_) => Ok(Vec::new()),
    }
}

fn parse_known_room_gids_json(json: &str) -> std::result::Result<Vec<[u8; 32]>, String> {
    let gid_hexes = serde_json::from_str::<Vec<String>>(json).map_err(|error| error.to_string())?;
    gid_hexes
        .into_iter()
        .enumerate()
        .map(|(index, gid_hex)| {
            validate_hex_32(gid_hex.as_str(), "gid")
                .map_err(|error| format!("entry {index}: {error}"))?;
            parse_gid(gid_hex.as_str()).map_err(|error| format!("entry {index}: {error}"))
        })
        .collect()
}

fn room_member_response(
    leaf: &[u8; 32],
    alias_lookup: &AliasLeafLookup,
    metadata: &ahash::AHashMap<[u8; 32], cityg_runtime::MemberMetadata>,
) -> pb::Member {
    schema_pb_member(
        leaf,
        alias_entry_for_member(alias_lookup, leaf),
        metadata.get(leaf),
    )
}

async fn register_alias_binding(
    env: &Env,
    alias: &str,
    leaf_id: [u8; 32],
    pop_public_key: &[u8],
) -> std::result::Result<(), AliasRemoteError> {
    let request = AliasRegisterRequest {
        alias: alias.to_string(),
        leaf_id_hex: hex::encode(leaf_id),
        pop_public_key_hex: hex::encode(pop_public_key),
    };
    let mut response = alias_registry_request(
        env,
        Method::Post,
        format!("{CLOUDFLARE_ALIAS_ROUTE_PREFIX}/register").as_str(),
        Some(&request),
    )
    .await
    .map_err(|error| AliasRemoteError::Backend(error.to_string()))?;

    match response.status_code() {
        200 => {
            let _: AliasRegisterResponse = decode_json_response(&mut response)
                .await
                .map_err(AliasRemoteError::Backend)?;
            Ok(())
        }
        409 => Err(AliasRemoteError::Conflict),
        status => Err(AliasRemoteError::Backend(
            response
                .text()
                .await
                .unwrap_or_else(|_| format!("alias registry request failed with status {status}")),
        )),
    }
}

async fn lookup_alias_bindings_by_leaf(
    env: &Env,
    leaves: &[[u8; 32]],
) -> std::result::Result<AliasLeafLookup, String> {
    if leaves.is_empty() {
        return Ok(AliasLeafLookup::default());
    }

    let request = AliasLeafLookupRequest {
        leaf_ids_hex: leaves.iter().map(hex::encode).collect(),
    };
    let mut response = alias_registry_request(
        env,
        Method::Post,
        format!("{CLOUDFLARE_ALIAS_ROUTE_PREFIX}/lookup-by-leaf").as_str(),
        Some(&request),
    )
    .await
    .map_err(|error| error.to_string())?;
    if response.status_code() != 200 {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "alias registry lookup failed".to_string()));
    }
    let payload: AliasLeafLookupResponse = decode_json_response(&mut response)
        .await
        .map_err(|error| error.to_string())?;
    let mut lookup = AliasLeafLookup::default();
    for binding in payload.bindings {
        let leaf_id = parse_gid(binding.leaf_id_hex.as_str()).map_err(|error| error.to_string())?;
        let pop_public_key = hex::decode(binding.pop_public_key_hex)
            .map_err(|_| "alias registry returned invalid pop_public_key hex".to_string())?;
        lookup.insert(
            leaf_id,
            cityg_runtime::AliasLeafEntry {
                alias: binding.alias,
                pop_public_key,
            },
        );
    }
    Ok(lookup)
}

async fn remove_alias_bindings_for_revoked_leaves(
    env: &Env,
    leaves: &[[u8; 32]],
) -> std::result::Result<(), String> {
    if leaves.is_empty() {
        return Ok(());
    }

    let request = AliasLeafLookupRequest {
        leaf_ids_hex: leaves.iter().map(hex::encode).collect(),
    };
    let mut response = alias_registry_request(
        env,
        Method::Post,
        format!("{CLOUDFLARE_ALIAS_ROUTE_PREFIX}/unbind-revoked").as_str(),
        Some(&request),
    )
    .await
    .map_err(|error| error.to_string())?;
    if response.status_code() != 200 {
        return Err(response
            .text()
            .await
            .unwrap_or_else(|_| "alias registry revoke request failed".to_string()));
    }
    let _: AliasMutationResponse = decode_json_response(&mut response)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn alias_registry_request<T: Serialize>(
    env: &Env,
    method: Method,
    path: &str,
    body: Option<&T>,
) -> Result<Response> {
    let namespace = env.durable_object(CLOUDFLARE_ALIAS_NAMESPACE_BINDING)?;
    let stub = namespace
        .id_from_name(GLOBAL_ALIAS_OBJECT_NAME)?
        .get_stub()?;
    let route = format!("https://cityg.internal{path}");
    let request = if let Some(body) = body {
        let mut init = RequestInit::new();
        init.with_method(method);
        init.with_body(Some(JsValue::from_str(
            &serde_json::to_string(body).map_err(|error| worker::Error::from(error.to_string()))?,
        )));
        Request::new_with_init(&route, &init)?
    } else {
        Request::new(&route, method)?
    };
    stub.fetch_with_request(request).await
}

async fn decode_json_request<T: for<'de> Deserialize<'de>>(mut req: Request) -> Result<T> {
    let text = req.text().await?;
    serde_json::from_str(&text).map_err(|error| worker::Error::from(error.to_string()))
}

async fn decode_json_response<T: for<'de> Deserialize<'de>>(
    response: &mut Response,
) -> std::result::Result<T, String> {
    let text = response.text().await.map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use cityg_api_schema::{RoomScopedApiRoute, is_room_scoped_api_path, pb};
    use cityg_client::demo::demo_bundle;
    use cityg_runtime::RoomVolatileState;
    use prost::Message;

    use super::*;

    #[test]
    fn room_route_parses_status_paths() {
        let route = parse_room_route(
            "/__cloudflare/rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/status",
        )
        .expect("route");

        assert_eq!(
            route.gid_hex,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(route.action, RoomRouteAction::Status);
    }

    #[test]
    fn room_route_parses_sync_routing_paths() {
        let route = parse_room_route(
            "/__cloudflare/rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/sync-routing",
        )
        .expect("route");

        assert_eq!(
            route.gid_hex,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(route.action, RoomRouteAction::SyncRouting);
    }

    #[test]
    fn room_route_rejects_unknown_suffixes() {
        assert!(parse_room_route(
            "/__cloudflare/rooms/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/accept"
        )
        .is_none());
    }

    #[test]
    fn gid_parser_requires_exactly_32_bytes() {
        let gid = parse_gid("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("valid gid");
        assert_eq!(gid, [0xff; 32]);

        assert!(parse_gid("abcd").is_err());
    }

    #[test]
    fn routing_index_route_parses_resolve_and_upsert_paths() {
        let resolve = parse_routing_index_route(
            "/__cloudflare/routing/epochs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("resolve route");
        assert_eq!(
            resolve,
            RoutingIndexRoute {
                we_epoch_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                action: RoutingIndexRouteAction::Resolve,
            }
        );

        let upsert = parse_routing_index_route(
            "/__cloudflare/routing/epochs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("upsert route");
        assert_eq!(
            upsert,
            RoutingIndexRoute {
                we_epoch_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                action: RoutingIndexRouteAction::Upsert {
                    gid_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
            }
        );
    }

    #[test]
    fn room_registry_route_parses_register_and_resolve_paths() {
        let register = parse_room_registry_route(
            "/__cloudflare/room-registry/rooms/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("register route");
        assert_eq!(
            register,
            RoomRegistryRoute {
                action: RoomRegistryRouteAction::Register {
                    gid_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
            }
        );

        let resolve = parse_room_registry_route(
            "/__cloudflare/room-registry/epochs/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/resolve",
        )
        .expect("resolve route");
        assert_eq!(
            resolve,
            RoomRegistryRoute {
                action: RoomRegistryRouteAction::Resolve {
                    we_epoch_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            }
        );
    }

    #[test]
    fn alias_route_parses_register_and_lookup_paths() {
        let register = parse_alias_route("/__cloudflare/aliases/register").expect("register");
        assert_eq!(register.action, AliasRouteAction::Register);

        let lookup =
            parse_alias_route("/__cloudflare/aliases/lookup-by-leaf").expect("lookup route");
        assert_eq!(lookup.action, AliasRouteAction::LookupByLeaf);

        let unbind =
            parse_alias_route("/__cloudflare/aliases/unbind-revoked").expect("unbind route");
        assert_eq!(unbind.action, AliasRouteAction::UnbindRevoked);
    }

    #[test]
    fn alias_route_rejects_unknown_suffixes() {
        assert!(parse_alias_route("/__cloudflare/aliases/nope").is_none());
        assert!(parse_alias_route("/__cloudflare/aliases/register/extra").is_none());
    }

    #[test]
    fn room_scoped_api_path_helper_matches_worker_expectations() {
        assert!(is_room_scoped_api_path(
            RoomScopedApiRoute::JoinTicket.path()
        ));
        assert!(!is_room_scoped_api_path("/health"));
    }

    #[test]
    fn native_room_route_errors_remain_room_scoped() {
        let request = pb::MergeTicketRequest {
            room_id: "abcd".to_string(),
            leaf_id: vec![0; 32],
            intent: 0,
        };
        let parsed = extract_room_scoped_request_target(
            RoomScopedApiRoute::MergeTicket.path(),
            &request.encode_to_vec(),
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn unique_room_gid_from_keys_accepts_single_gid_prefix() {
        let gid = unique_room_gid_from_keys([
            "rooms/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/snapshot.cbor",
            "rooms/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/volatile.cbor",
        ])
        .expect("single gid");

        assert_eq!(gid, Some([0xaa; 32]));
    }

    #[test]
    fn unique_room_gid_from_keys_rejects_mixed_gids() {
        let err = unique_room_gid_from_keys([
            "rooms/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/snapshot.cbor",
            "rooms/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/volatile.cbor",
        ])
        .expect_err("mixed gids should fail");

        assert!(err.to_string().contains("multiple gids"));
    }

    #[test]
    fn rehydration_bootstrap_matches_fallback_without_worker_config() {
        let bootstrap = rehydration_bootstrap();
        assert_eq!(
            bootstrap.history_authority,
            WorkerHistoryAuthority::Disabled
        );
        assert!(bootstrap.acceptance_options.is_none());
    }

    #[test]
    fn parse_known_room_gids_json_accepts_hex_gid_arrays() {
        let gids = parse_known_room_gids_json(
            r#"[
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ]"#,
        )
        .expect("known gids");
        assert_eq!(gids, vec![[0xaa; 32], [0xbb; 32]]);
    }

    #[test]
    fn parse_known_room_gids_json_rejects_invalid_entries() {
        let err = parse_known_room_gids_json(r#"["abcd"]"#).expect_err("invalid gid");
        assert!(err.contains("entry 0"));
    }

    #[test]
    fn websocket_subscription_parses_room_query() {
        let subscription = parse_websocket_subscription_url(
            "https://cityg.internal/v1/ws?gid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&leaf_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .expect("subscription");
        assert_eq!(subscription.gid, [0xaa; 32]);
        assert_eq!(subscription.leaf_id, [0xbb; 32]);
    }

    #[test]
    fn websocket_subscription_requires_gid_and_leaf_id() {
        assert_eq!(
            parse_websocket_subscription_url("https://cityg.internal/v1/ws?gid=abcd")
                .expect_err("invalid gid"),
            "gid must be 64 hex characters"
        );

        assert_eq!(
            parse_websocket_subscription_url(
                "https://cityg.internal/v1/ws?gid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect_err("missing leaf"),
            "leaf_id must be provided"
        );
    }

    #[test]
    fn websocket_upgrade_detection_is_case_insensitive() {
        assert!(websocket_upgrade_requested_value(Some("WebSocket")));
        assert!(websocket_upgrade_requested_value(Some("websocket")));
        assert!(!websocket_upgrade_requested_value(Some("h2c")));
        assert!(!websocket_upgrade_requested_value(None));
    }

    #[test]
    fn websocket_session_attachment_round_trips_shape() {
        let attachment = WebSocketSessionAttachment {
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            last_client_activity_ms: 33,
            last_acknowledged_sequence: 44,
            last_sent_sequence: 55,
            last_lag_notice_acknowledged_sequence: 44,
        };

        let encoded = serde_json::to_value(&attachment).expect("encode attachment");
        let decoded: WebSocketSessionAttachment =
            serde_json::from_value(encoded).expect("decode attachment");
        assert_eq!(decoded, attachment);
    }

    #[test]
    fn parse_ws_max_lag_uses_default_on_invalid_input() {
        assert_eq!(parse_ws_max_lag(None), WS_MAX_LAG_DEFAULT);
        assert_eq!(parse_ws_max_lag(Some("0")), WS_MAX_LAG_DEFAULT);
        assert_eq!(parse_ws_max_lag(Some("nope")), WS_MAX_LAG_DEFAULT);
        assert_eq!(parse_ws_max_lag(Some("512")), 512);
    }

    #[test]
    fn websocket_lag_warning_threshold_halves_max_with_floor() {
        assert_eq!(websocket_lag_warning_threshold(1), 1);
        assert_eq!(websocket_lag_warning_threshold(2), 1);
        assert_eq!(websocket_lag_warning_threshold(256), 128);
    }

    #[test]
    fn websocket_replay_buffer_trims_to_capacity() {
        let mut replay_buffer = VecDeque::new();
        push_websocket_replay_event(
            &mut replay_buffer,
            BufferedWebSocketEvent {
                sequence: 1,
                payload: serde_json::json!({"type":"message"}),
                timestamp_ms: 10,
            },
            2,
        );
        push_websocket_replay_event(
            &mut replay_buffer,
            BufferedWebSocketEvent {
                sequence: 2,
                payload: serde_json::json!({"type":"message"}),
                timestamp_ms: 20,
            },
            2,
        );
        push_websocket_replay_event(
            &mut replay_buffer,
            BufferedWebSocketEvent {
                sequence: 3,
                payload: serde_json::json!({"type":"message"}),
                timestamp_ms: 30,
            },
            2,
        );

        assert_eq!(replay_buffer.len(), 2);
        assert_eq!(websocket_oldest_buffered_sequence(&replay_buffer), Some(2));
    }

    #[test]
    fn websocket_client_signal_parses_text_and_json_heartbeat_frames() {
        assert_eq!(
            parse_websocket_client_signal("ping"),
            Some(WebSocketClientSignal::Ping {
                acknowledged_sequence: 0,
                json: false,
            })
        );
        assert_eq!(
            parse_websocket_client_signal("pong"),
            Some(WebSocketClientSignal::Pong {
                acknowledged_sequence: 0,
            })
        );
        assert_eq!(
            parse_websocket_client_signal(r#"{"type":"ping","last_sequence":12}"#),
            Some(WebSocketClientSignal::Ping {
                acknowledged_sequence: 12,
                json: true,
            })
        );
        assert_eq!(
            parse_websocket_client_signal(r#"{"type":"pong","last_sequence":34}"#),
            Some(WebSocketClientSignal::Pong {
                acknowledged_sequence: 34,
            })
        );
        assert_eq!(
            parse_websocket_client_signal(r#"{"type":"ack","last_sequence":56}"#),
            Some(WebSocketClientSignal::Ack {
                acknowledged_sequence: 56,
            })
        );
        assert_eq!(
            parse_websocket_client_signal(r#"{"type":"resume","last_sequence":78}"#),
            Some(WebSocketClientSignal::Resume {
                acknowledged_sequence: 78,
            })
        );
        assert_eq!(parse_websocket_client_signal(r#"{"type":"message"}"#), None);
    }

    #[test]
    fn websocket_lag_notice_emits_once_per_acknowledged_sequence() {
        let attachment = WebSocketSessionAttachment {
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            last_client_activity_ms: 0,
            last_acknowledged_sequence: 10,
            last_sent_sequence: 20,
            last_lag_notice_acknowledged_sequence: 0,
        };
        assert!(should_emit_websocket_lag_notice(&attachment, 8, 12));

        let warned = WebSocketSessionAttachment {
            last_lag_notice_acknowledged_sequence: 10,
            ..attachment.clone()
        };
        assert!(!should_emit_websocket_lag_notice(&warned, 8, 12));
        assert!(!should_emit_websocket_lag_notice(&attachment, 3, 12));
        assert!(!should_emit_websocket_lag_notice(
            &WebSocketSessionAttachment {
                last_acknowledged_sequence: 0,
                ..attachment
            },
            8,
            12,
        ));
    }

    #[test]
    fn websocket_gap_becomes_irrecoverable_once_ack_falls_behind_buffer() {
        let attachment = WebSocketSessionAttachment {
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            last_client_activity_ms: 0,
            last_acknowledged_sequence: 10,
            last_sent_sequence: 15,
            last_lag_notice_acknowledged_sequence: 0,
        };
        assert!(!websocket_gap_is_irrecoverable(&attachment, Some(11)));
        assert!(websocket_gap_is_irrecoverable(&attachment, Some(12)));
        assert!(!websocket_gap_is_irrecoverable(
            &WebSocketSessionAttachment {
                last_acknowledged_sequence: 0,
                ..attachment
            },
            Some(12),
        ));
    }

    #[test]
    fn buffered_websocket_events_after_selects_replay_window() {
        let replay_buffer = VecDeque::from([
            BufferedWebSocketEvent {
                sequence: 10,
                payload: serde_json::json!({"type":"message","id":10}),
                timestamp_ms: 10,
            },
            BufferedWebSocketEvent {
                sequence: 11,
                payload: serde_json::json!({"type":"message","id":11}),
                timestamp_ms: 11,
            },
            BufferedWebSocketEvent {
                sequence: 12,
                payload: serde_json::json!({"type":"message","id":12}),
                timestamp_ms: 12,
            },
        ]);

        let events = buffered_websocket_events_after(&replay_buffer, 10, 11);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 11);
    }

    #[test]
    fn decorate_websocket_payload_adds_sequence_and_lag_fields() {
        let payload = serde_json::json!({
            "type": "message",
            "gid": "abc",
        });
        let attachment = WebSocketSessionAttachment {
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            last_client_activity_ms: 77,
            last_acknowledged_sequence: 40,
            last_sent_sequence: 40,
            last_lag_notice_acknowledged_sequence: 0,
        };

        let decorated = decorate_websocket_payload(payload, 45, 99, &attachment);
        assert_eq!(decorated["type"], "message");
        assert_eq!(decorated["sequence"], 45);
        assert_eq!(decorated["server_time_ms"], 99);
        assert_eq!(decorated["last_client_activity_ms"], 77);
        assert_eq!(decorated["lagged_messages"], 5);
        assert_eq!(decorated["connection_healthy"], true);
    }

    #[test]
    fn mark_replayed_websocket_payload_sets_replayed_flag() {
        let payload = mark_replayed_websocket_payload(serde_json::json!({
            "type": "message",
            "sequence": 12,
        }));
        assert_eq!(payload["replayed"], true);
    }

    #[test]
    fn websocket_lag_payload_matches_native_signal_shape() {
        let payload = websocket_lag_payload(7, 12, 44, 88);
        assert_eq!(payload["type"], "lag");
        assert_eq!(payload["lagged_messages"], 7);
        assert_eq!(payload["max_lag"], 12);
        assert_eq!(payload["sequence"], 44);
        assert_eq!(payload["server_time_ms"], 88);
        assert_eq!(payload["recommendation"], "consider reconnecting");
    }

    #[test]
    fn room_snapshot_after_accept_advances_checkpoint_metadata() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let gid = route_gid(&RoomScopedRequestTarget {
            route: RoomScopedApiRoute::AcceptEpoch,
            key: RoomScopedRoutingKey::Gid(
                bundle
                    .gid()
                    .try_into()
                    .expect("demo gid should be 32 bytes"),
            ),
        })
        .expect("gid route");
        let bootstrap = WorkerRoomBootstrap::from_cityg_config(&{
            let mut cfg = cityg_config::CityGConfig::default();
            cfg.server.seed_demo_room = true;
            cfg
        });
        let room = RuntimeRoom::new(cityg_server::CityGServer::new(bootstrap.to_server_config()));
        let (mut server, mut room_state) = room.into_parts();
        let accepted = accept_room_epoch(
            &mut server,
            &mut room_state,
            &bundle,
            55,
            message_retention(),
            MESSAGE_PRUNE_INTERVAL_MS,
        )
        .expect("accept room epoch");

        let snapshot = room_snapshot_after_accept(
            gid,
            None,
            export_server_runtime_metadata_bytes(&server).expect("export runtime metadata"),
            &accepted,
            55,
        );
        assert_eq!(snapshot.gid, gid);
        assert_eq!(snapshot.format_version, ROOM_SNAPSHOT_FORMAT_VERSION);
        assert_eq!(snapshot.last_we_epoch_id, Some(bundle.we_epoch_id));
        assert_eq!(
            snapshot.last_parent_root,
            Some(accepted.outcome.parent_root)
        );
        assert_eq!(snapshot.accepted_bundle_count, 1);

        let next_snapshot = room_snapshot_after_accept(
            gid,
            Some(&RoomStateCheckpoint {
                snapshot,
                accepted_bundles: vec![cityg_runtime::AcceptedBundleRecord {
                    we_epoch_id: accepted.outcome.we_epoch_id,
                    parent_root: accepted.outcome.parent_root,
                    new_root: accepted.outcome.new_root,
                    bytes: accepted.stored_bundle_bytes.clone(),
                    accepted_at_ms: 55,
                }],
                volatile: RoomVolatileState::default().snapshot(),
            }),
            export_server_runtime_metadata_bytes(&server).expect("export runtime metadata"),
            &accepted,
            77,
        );
        assert_eq!(next_snapshot.accepted_bundle_count, 2);
        assert_eq!(next_snapshot.persisted_at_ms, 77);
    }
}
