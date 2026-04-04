#![forbid(unsafe_code)]

//! Shared runtime building blocks for City-G deployment adapters.
//!
//! This crate intentionally contains neutral seams that can be reused by the
//! native API runtime and the Cloudflare Worker runtime.

pub mod alias;
pub mod bootstrap;
pub mod room;
pub mod service;
pub mod storage;
pub mod volatile;

pub use alias::{
    AliasBinding, AliasLeafEntry, AliasLeafLookup, AliasRegistrationError,
    AliasRegistrationOutcome, AliasRegistry, normalize_alias,
};
pub use bootstrap::{
    aligned_fs_epoch_base_ts, lane_state_path, server_config_from_cityg_config,
    server_from_cityg_config, server_from_cityg_config_for_lane,
};
pub use room::RuntimeRoom;
pub use service::{
    AcceptedRoomEpoch, AppliedBundleIndexes, BarrierPage, BarrierPaginationError,
    BundleIndexUpdate, FullVerificationWitnessRequest, MAX_MESSAGE_CIPHERTEXT_BYTES,
    PaginatedMembers, PreparedAcceptedBundle, PreparedBarrierEnvelope, PreparedBarrierPublicTree,
    PreparedJoinTicket, PreparedMergeAcceptanceLookup, PreparedMergeTicket,
    PreparedResolvedJoinOccupancies, PreparedResolvedJoins, PreparedResolvedRevokedLeaves,
    PreparedResolvedRevokedOccupancies, RoomAcceptEpochError, RoomAuthorizationError,
    RoomBarrierEnvelopeError, RoomBarrierHelperPreparationError, RoomBundleMaterializationError,
    RoomFullVerificationWitnessPreparationError, RoomMemberListingError, RoomMessageStoreError,
    RoomMessageWrite, RoomRetentionPolicy, RoomServiceError, RoomTelemetrySnapshotEntry,
    RoomTicketPreparationError, RoomWindowConfigError, RoomWindowEntrySnapshot,
    RoomWindowHeadSnapshot, RoomWindowLimitUpdate, RoomWindowLimits, RoomWindowSeedError,
    accept_room_epoch, alias_entry_for_member, apply_bundle_indexes,
    apply_room_window_limit_update, bootstrap_room_with_admin, classify_refresh_pivot_conflict,
    commit_prepared_accepted_bundle, encode_pivot_parity_cbor, ensure_leaf_member_for_epoch,
    ensure_leaf_member_for_room, fetch_room_bundle, fetch_room_members, fetch_room_messages,
    filter_room_members_by_query, grant_room_admin, list_room_admins, materialize_replayed_bundle,
    materialize_stored_bundle, paginate_barrier_helper_slice, paginate_room_members,
    parse_room_window_limit_update, prepare_accepted_bundle, prepare_barrier_envelope,
    prepare_barrier_public_tree, prepare_current_barrier_envelope, prepare_expel_member_ticket,
    prepare_full_verification_witness, prepare_join_ticket, prepare_merge_acceptance_lookup,
    prepare_merge_ticket, prepare_merge_ticket_from_bundle, prepare_resolved_join_occupancies,
    prepare_resolved_joins, prepare_resolved_revoked_leaves, prepare_resolved_revoked_occupancies,
    refresh_room_pivot, revoke_room_admin, rotate_room_kbroad, seed_room_window_head,
    snapshot_room_telemetry, snapshot_room_window, store_room_message,
};
pub use storage::{
    AcceptedBundleRecord, EpochLeafBindingRecord, EpochScopeRecord, MemberMetadataRecord,
    MemoryRoomStateStore, RoomRoutingEntry, RoomSnapshot, RoomStateCheckpoint, RoomStateStore,
    RoomVolatileSnapshot, StoredBundleRecord, derive_room_routing_entries,
};
pub use volatile::{
    BundleBacklog, EpochScope, MemberMetadata, MessageBacklog, RoomIndexes, RoomVolatileState,
    StoredBundle, StoredMessage, index_member_join, prune_epoch_indexes, prune_expired_bundles,
    prune_expired_messages, revoke_members, should_prune,
};
