use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use cityg_runtime::{
    RoomMessageStoreError, RoomMessageWrite, RoomRetentionPolicy,
    fetch_room_messages as runtime_fetch_room_messages,
    store_room_message as runtime_store_room_message,
};

use crate::{
    ApiError, ApiState, ChatMessage, FetchMessagesRequest, FetchMessagesResponse,
    MESSAGE_PRUNE_INTERVAL_MS, SendMessageRequest, SendMessageResponse,
    configured_message_auth_token, current_timestamp_ms, enforce_message_auth_header,
    map_fetch_messages_request_validation_error, map_send_message_request_validation_error,
    protobuf_response, schema_validate_fetch_messages_request,
    schema_validate_send_message_request,
};

pub(crate) async fn send_message(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_send_message_request(SendMessageRequest::decode(body)?)
        .map_err(map_send_message_request_validation_error)?;
    let timestamp_ms = current_timestamp_ms();
    let scope = {
        let epoch_scope = state
            .epoch_scope_for_weid(&request.we_epoch_id)
            .await
            .ok_or(ApiError::NotFound)?;
        let lane = state.server_for_gid(&epoch_scope.gid);
        let guard = lane.read().await;
        let mut room_state = state.room_state.write().await;
        runtime_store_room_message(
            &guard,
            &mut room_state,
            RoomMessageWrite {
                we_epoch_id: request.we_epoch_id,
                sender_leaf: request.sender_leaf,
                ciphertext: request.ciphertext,
                sender: request.sender,
                timestamp_ms,
            },
            RoomRetentionPolicy {
                retention: state.message_retention,
                prune_interval_ms: MESSAGE_PRUNE_INTERVAL_MS,
            },
        )
        .map_err(|error| match error {
            RoomMessageStoreError::NotFound => ApiError::NotFound,
            RoomMessageStoreError::EpochUnauthorized => {
                ApiError::Unauthorized("leaf is not a member for epoch")
            }
            RoomMessageStoreError::RoomUnauthorized => {
                ApiError::Unauthorized("leaf is not a member for room")
            }
        })?
    };

    let notification = crate::MessageNotification {
        gid: scope.gid,
        we_epoch_id: request.we_epoch_id,
        timestamp_ms,
    };
    state.broadcast_message(notification);

    let reply = SendMessageResponse {
        status: "stored".to_string(),
    };
    Ok(protobuf_response(&reply))
}

pub(crate) async fn fetch_messages(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_fetch_messages_request(FetchMessagesRequest::decode(body)?)
        .map_err(map_fetch_messages_request_validation_error)?;
    let now_ms = current_timestamp_ms();
    let scope = state
        .epoch_scope_for_weid(&request.we_epoch_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let lane = state.server_for_gid(&scope.gid);
    let guard = lane.read().await;
    let messages = {
        let mut room_state = state.room_state.write().await;
        runtime_fetch_room_messages(
            &guard,
            &mut room_state,
            &request.we_epoch_id,
            request.leaf_id,
            now_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
        .map_err(|err| match err {
            cityg_runtime::RoomAuthorizationError::NotFound => ApiError::NotFound,
            cityg_runtime::RoomAuthorizationError::Unauthorized => {
                ApiError::Unauthorized("leaf is not a member for epoch")
            }
        })?
    };

    let reply = FetchMessagesResponse {
        messages: messages
            .into_iter()
            .map(|msg| ChatMessage {
                ciphertext: msg.ciphertext,
                we_epoch_id: msg.we_epoch_id.to_vec(),
                sender: msg.sender,
                timestamp_ms: msg.timestamp_ms,
            })
            .collect(),
    };

    Ok(protobuf_response(&reply))
}
