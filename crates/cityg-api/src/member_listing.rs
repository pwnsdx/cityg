use ahash::AHashMap;
use cityg_api_schema::{pb::Member, pb_member as schema_pb_member};
use cityg_runtime::{
    AliasLeafLookup, MemberMetadata, RoomMemberListingError, alias_entry_for_member,
    fetch_room_members as runtime_fetch_room_members,
};

use crate::{ApiError, ApiState};

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
