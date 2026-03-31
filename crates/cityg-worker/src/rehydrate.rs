use cityg_client::ClientEpochBundle;
use cityg_runtime::{RoomStateCheckpoint, RoomVolatileState, RuntimeRoom};
use cityg_server::CityGServer;
use thiserror::Error;

use crate::WorkerRoomBootstrap;

/// Errors raised while reconstructing a room runtime from a persisted checkpoint.
#[derive(Debug, Error)]
pub enum WorkerRoomRehydrationError {
    #[error("accepted bundle {index} has an invalid gid length during room rehydration")]
    InvalidBundleGidLength { index: usize },
    #[error("accepted bundle {index} failed to decode during room rehydration: {message}")]
    DecodeAcceptedBundle { index: usize, message: String },
    #[error("accepted bundle {index} targets gid {bundle_gid_hex}, expected {checkpoint_gid_hex}")]
    AcceptedBundleGidMismatch {
        index: usize,
        bundle_gid_hex: String,
        checkpoint_gid_hex: String,
    },
    #[error("accepted bundle {index} failed to replay during room rehydration: {message}")]
    ReplayAcceptedBundle { index: usize, message: String },
    #[error("persisted server runtime metadata failed to apply during room rehydration: {message}")]
    RestoreRuntimeMetadata { message: String },
}

/// Rebuild a room runtime from the persisted checkpoint contract.
///
/// The current worker path replays accepted bundles to rebuild the authoritative
/// `CityGServer` state, then restores the shared volatile snapshot. This keeps
/// the runtime adapter honest without depending on the native daemon's
/// filesystem recovery path.
pub fn rehydrate_runtime_room_from_checkpoint(
    checkpoint: &RoomStateCheckpoint,
    bootstrap: &WorkerRoomBootstrap,
) -> Result<RuntimeRoom, WorkerRoomRehydrationError> {
    let mut room = RuntimeRoom::new(CityGServer::new(bootstrap.to_server_config()));
    replay_accepted_bundles(&mut room, checkpoint)?;
    room.server_mut()
        .restore_runtime_metadata_bytes(
            checkpoint.snapshot.server_state_bytes.as_slice(),
            !checkpoint.accepted_bundles.is_empty(),
        )
        .map_err(|error| WorkerRoomRehydrationError::RestoreRuntimeMetadata {
            message: error.to_string(),
        })?;
    *room.volatile_mut() = RoomVolatileState::from_snapshot(checkpoint.volatile.clone());
    Ok(room)
}

fn replay_accepted_bundles(
    room: &mut RuntimeRoom,
    checkpoint: &RoomStateCheckpoint,
) -> Result<(), WorkerRoomRehydrationError> {
    for (index, record) in checkpoint.accepted_bundles.iter().enumerate() {
        let bundle = ClientEpochBundle::from_cbor(&record.bytes).map_err(|error| {
            WorkerRoomRehydrationError::DecodeAcceptedBundle {
                index,
                message: error.to_string(),
            }
        })?;
        let bundle_gid: [u8; 32] = bundle
            .gid()
            .try_into()
            .map_err(|_| WorkerRoomRehydrationError::InvalidBundleGidLength { index })?;
        if bundle_gid != checkpoint.snapshot.gid {
            return Err(WorkerRoomRehydrationError::AcceptedBundleGidMismatch {
                index,
                bundle_gid_hex: hex::encode(bundle_gid),
                checkpoint_gid_hex: hex::encode(checkpoint.snapshot.gid),
            });
        }
        room.server_mut().accept_epoch(&bundle).map_err(|error| {
            WorkerRoomRehydrationError::ReplayAcceptedBundle {
                index,
                message: error.to_string(),
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeMap;
    use std::time::Duration;

    use cityg_client::demo::{demo_bundle, demo_member_leaf};
    use cityg_runtime::{
        AcceptedBundleRecord, BundleIndexUpdate, RoomRetentionPolicy, RoomSnapshot,
        apply_bundle_indexes,
    };
    use msphf_orchestrator::{AcceptanceOptions, BootstrapPolicy};

    use super::*;

    fn test_bootstrap() -> WorkerRoomBootstrap {
        let mut kbroad_registry = BTreeMap::new();
        kbroad_registry.insert(
            cityg_client::demo::DEMO_GID.to_vec(),
            cityg_client::demo::kbroad_public().to_vec(),
        );
        WorkerRoomBootstrap {
            history_authority: crate::WorkerHistoryAuthority::Disabled,
            acceptance_options: Some(AcceptanceOptions {
                bootstrap_policy: BootstrapPolicy::CaMlDsa {
                    public_key: cityg_client::demo::bootstrap_public().to_vec(),
                },
                kbroad_registry: Some(kbroad_registry),
                ..AcceptanceOptions::default()
            }),
            ..WorkerRoomBootstrap::default()
        }
    }

    #[test]
    fn checkpoint_rehydrates_runtime_room_by_replaying_accepted_bundles() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let gid: [u8; 32] = bundle.gid().try_into().expect("gid");
        let bundle_bytes = bundle.to_cbor().expect("bundle cbor");

        let mut room = RuntimeRoom::new(CityGServer::new(test_bootstrap().to_server_config()));
        let outcome = room
            .server_mut()
            .accept_epoch(&bundle)
            .expect("accept demo bundle");
        apply_bundle_indexes(
            room.volatile_mut(),
            &bundle,
            BundleIndexUpdate {
                we_epoch_id: bundle.we_epoch_id,
                bytes: bundle_bytes.clone(),
                membership_root: outcome.new_root,
                timestamp_ms: 55,
            },
            RoomRetentionPolicy {
                retention: Duration::from_secs(60),
                prune_interval_ms: 1_000,
            },
        )
        .expect("apply bundle indexes");

        let checkpoint = RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid,
                format_version: 1,
                server_state_bytes: room
                    .server()
                    .export_runtime_metadata_bytes()
                    .expect("export runtime metadata"),
                last_parent_root: Some(outcome.parent_root),
                last_we_epoch_id: Some(bundle.we_epoch_id),
                accepted_bundle_count: 1,
                persisted_at_ms: 55,
            },
            accepted_bundles: vec![AcceptedBundleRecord {
                we_epoch_id: bundle.we_epoch_id,
                parent_root: outcome.parent_root,
                new_root: outcome.new_root,
                bytes: bundle_bytes,
                accepted_at_ms: 55,
            }],
            volatile: room.volatile().snapshot(),
        };

        let rehydrated = rehydrate_runtime_room_from_checkpoint(&checkpoint, &test_bootstrap())
            .expect("rehydrate room");

        assert!(
            rehydrated
                .server()
                .members(&gid)
                .contains(&demo_member_leaf("alice"))
        );
        assert_eq!(
            rehydrated
                .epoch_scope_for_weid(&checkpoint.accepted_bundles[0].we_epoch_id)
                .expect("epoch scope")
                .gid,
            gid
        );
    }

    #[test]
    fn checkpoint_rehydrates_runtime_metadata_without_replayed_bundles() {
        let gid = [0x7A; 32];
        let admin_pop_key = vec![0x55; 32];
        let mut server = CityGServer::new(test_bootstrap().to_server_config());
        server
            .register_group_with_admin(&gid, vec![0x44; 32], admin_pop_key.clone())
            .expect("register group with admin");

        let checkpoint = RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid,
                format_version: 1,
                server_state_bytes: server
                    .export_runtime_metadata_bytes()
                    .expect("export runtime metadata"),
                ..RoomSnapshot::default()
            },
            accepted_bundles: Vec::new(),
            volatile: RoomVolatileState::default().snapshot(),
        };

        let rehydrated = rehydrate_runtime_room_from_checkpoint(&checkpoint, &test_bootstrap())
            .expect("rehydrate runtime metadata");

        assert!(rehydrated.server().room_uses_explicit_admins(&gid));
        assert_eq!(
            rehydrated
                .server()
                .list_room_admins(&gid, &admin_pop_key)
                .expect("list room admins"),
            vec![admin_pop_key]
        );
    }

    #[test]
    fn checkpoint_rehydration_rejects_gid_mismatches() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let bundle_bytes = bundle.to_cbor().expect("bundle cbor");
        let checkpoint = RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid: [0xAB; 32],
                ..RoomSnapshot::default()
            },
            accepted_bundles: vec![AcceptedBundleRecord {
                we_epoch_id: bundle.we_epoch_id,
                parent_root: [0x01; 32],
                new_root: [0x02; 32],
                bytes: bundle_bytes,
                accepted_at_ms: 1,
            }],
            volatile: RoomVolatileState::default().snapshot(),
        };

        let err = match rehydrate_runtime_room_from_checkpoint(&checkpoint, &test_bootstrap()) {
            Ok(_) => panic!("gid mismatch should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            WorkerRoomRehydrationError::AcceptedBundleGidMismatch { .. }
        ));
    }
}
