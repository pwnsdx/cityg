use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use ahash::AHashMap;
use cityg_api_schema::{
    encode_members_response, encode_search_members_response, pb, pb::Member,
    pb_member as schema_pb_member, validate_members_request as schema_validate_members_request,
    validate_search_members_request as schema_validate_search_members_request,
};
use cityg_runtime::{
    AliasLeafLookup, MemberMetadata, RoomMemberListingError, alias_entry_for_member,
    fetch_room_members as runtime_fetch_room_members, filter_room_members_by_query,
    paginate_room_members,
};

use crate::{
    ApiError, ApiState, MembersRequest, configured_message_auth_token,
    enforce_expensive_rate_limit, enforce_message_auth_header,
    map_members_request_validation_error, map_search_members_request_validation_error,
    message_scoped_rate_limit_key, protobuf_response_bytes,
};

pub(crate) async fn members_for_request(
    state: &ApiState,
    gid: &[u8; 32],
    parent_root: Option<[u8; 32]>,
) -> Result<(Vec<[u8; 32]>, [u8; 32]), ApiError> {
    let lane = state.server_for_gid_bytes(gid);
    let guard = lane.read().await;
    runtime_fetch_room_members(&guard, gid, parent_root).map_err(|err| match err {
        RoomMemberListingError::NotFound => ApiError::NotFound,
    })
}

pub(crate) async fn alias_lookup_by_leaf(state: &ApiState) -> AliasLeafLookup {
    let registry = state.alias_registry.read().await;
    registry.leaf_lookup()
}

pub(crate) fn member_response(
    leaf: &[u8; 32],
    alias_lookup: &AliasLeafLookup,
    metadata: &AHashMap<[u8; 32], MemberMetadata>,
) -> Member {
    schema_pb_member(
        leaf,
        alias_entry_for_member(alias_lookup, leaf),
        metadata.get(leaf),
    )
}

pub(crate) async fn members(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = MembersRequest::decode(body)?;
    let request =
        schema_validate_members_request(request).map_err(map_members_request_validation_error)?;
    enforce_expensive_rate_limit(
        &state,
        "members",
        message_scoped_rate_limit_key(&headers, request.gid.as_ref()),
    )
    .await?;
    let (members, root) = members_for_request(&state, &request.gid, request.parent_root).await?;

    let page = paginate_room_members(members.as_slice(), request.offset, request.limit);

    let alias_lookup = alias_lookup_by_leaf(&state).await;
    let room_state = state.room_state.read().await;

    Ok(protobuf_response_bytes(encode_members_response(
        page.members
            .iter()
            .map(|leaf| member_response(leaf, &alias_lookup, room_state.member_metadata()))
            .collect(),
        root,
        page.total_count,
        page.next_offset,
    )))
}

pub(crate) async fn search_members(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = pb::SearchMembersRequest::decode(body)?;
    let request = schema_validate_search_members_request(request)
        .map_err(map_search_members_request_validation_error)?;
    enforce_expensive_rate_limit(
        &state,
        "search_members",
        message_scoped_rate_limit_key(&headers, request.gid.as_ref()),
    )
    .await?;
    let (members, root) = members_for_request(&state, &request.gid, request.parent_root).await?;

    let alias_lookup = alias_lookup_by_leaf(&state).await;
    let room_state = state.room_state.read().await;

    let filtered_members =
        filter_room_members_by_query(members.as_slice(), &alias_lookup, request.query.as_str());
    let page = paginate_room_members(filtered_members.as_slice(), request.offset, request.limit);

    Ok(protobuf_response_bytes(encode_search_members_response(
        page.members
            .iter()
            .map(|leaf| member_response(leaf, &alias_lookup, room_state.member_metadata()))
            .collect(),
        root,
        page.total_count,
        page.next_offset,
    )))
}
