//! Room engine: the GUI's bridge to the City-G v0.3 member driver.
//!
//! Everything here is independent of gpui. A [`SharedMember`] is the member
//! driver behind an async mutex, shared between the UI thread (which only
//! reads the [`SessionView`] snapshots returned by the operations) and the
//! Tokio tasks that talk to the delivery service.
//!
//! Members are named by their occupancy, a [`MemberRef`] (leaf index and
//! the epoch the occupancy began): it is what message senders and removal
//! proposals name, and it survives device-key rotations.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use cityg_api_client::cityg_core::commit::CommitKind;
use cityg_api_client::cityg_core::identity::DeviceIdentity;
use cityg_api_client::cityg_core::message::ReceivedMessage;
pub(crate) use cityg_api_client::cityg_core::tree::MemberRef;
use cityg_api_client::{ClientError, DsClient, InviteLink, Member, SyncReport};
use tokio::sync::Mutex;

/// The member driver shared between the UI and background tasks.
pub(crate) type SharedMember = Arc<Mutex<Member>>;

/// Leaf capacity of the rooms the GUI creates.
pub(crate) const DEFAULT_ROOM_CAPACITY: u32 = 64;
/// Lifetime of the invite links the GUI creates.
pub(crate) const INVITE_TTL_MS: u64 = 7 * 24 * 3_600_000;
/// How many devices one invite link the GUI creates may admit.
pub(crate) const INVITE_MAX_USES: u64 = 64;
/// Maximum age of this member's own leaf keys before it re-keys (the FS/PCS
/// window of the profile, P-1).
pub(crate) const SELF_UPDATE_INTERVAL_MS: u64 = 24 * 3_600_000;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// `leaf.since`: the text form of an occupancy (display and storage).
pub(crate) fn member_ref_text(member: MemberRef) -> String {
    format!("{}.{}", member.leaf, member.since)
}

/// Parse the text form of an occupancy.
pub(crate) fn parse_member_ref(text: &str) -> Option<MemberRef> {
    let (leaf, since) = text.trim().split_once('.')?;
    Some(MemberRef {
        leaf: leaf.parse().ok()?,
        since: since.parse().ok()?,
    })
}

/// One member as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RosterEntry {
    pub(crate) member: MemberRef,
    pub(crate) device_public_key: Vec<u8>,
    pub(crate) admin: bool,
    pub(crate) alias: Option<String>,
    pub(crate) pending_removal: bool,
}

/// Snapshot of a member's group state for rendering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionView {
    pub(crate) epoch: u64,
    /// This device's occupancy.
    pub(crate) me: MemberRef,
    pub(crate) capacity: u32,
    pub(crate) roster: Vec<RosterEntry>,
    pub(crate) is_admin: bool,
    pub(crate) transcript_fingerprint: [u8; 32],
    pub(crate) tree_hash: [u8; 32],
    pub(crate) registry_hash: [u8; 32],
    pub(crate) epochs_since_own_update: u64,
    pub(crate) log_seq: u64,
    pub(crate) pending_removals: usize,
    pub(crate) pending_joins: usize,
    pub(crate) has_previous_epoch_keys: bool,
}

/// Build the view of `member`, labelling members with `aliases`.
pub(crate) fn view_of(member: &Member, aliases: &BTreeMap<MemberRef, String>) -> SessionView {
    let session = member.session();
    let tree = session.tree();
    let registry = session.registry();
    let pending: Vec<MemberRef> = member
        .pending_removals()
        .iter()
        .map(|proposal| MemberRef {
            leaf: proposal.proposal().target_leaf,
            since: proposal.proposal().target_since,
        })
        .collect();
    let context = session.group_context();
    SessionView {
        epoch: session.epoch(),
        me: session.me(),
        capacity: session.public_state().capacity(),
        roster: tree
            .members()
            .map(|(leaf, node)| {
                let member = MemberRef {
                    leaf,
                    since: node.since,
                };
                RosterEntry {
                    member,
                    device_public_key: node.device_pk.clone(),
                    admin: registry.is_admin(leaf),
                    alias: aliases.get(&member).cloned(),
                    pending_removal: pending.contains(&member),
                }
            })
            .collect(),
        is_admin: session.is_admin(),
        transcript_fingerprint: session.transcript_fingerprint(),
        tree_hash: context.tree_hash,
        registry_hash: context.registry_hash,
        epochs_since_own_update: session.epochs_since_own_update(),
        log_seq: member.log_seq(),
        pending_removals: pending.len(),
        pending_joins: member.pending_joins().len(),
        has_previous_epoch_keys: session.previous_epochs().next().is_some(),
    }
}

/// A message received from another member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IncomingMessage {
    pub(crate) sender: MemberRef,
    pub(crate) text: String,
    pub(crate) signed_timestamp_ms: u64,
    pub(crate) epoch: u64,
    pub(crate) generation: u32,
}

impl IncomingMessage {
    fn from_received(message: ReceivedMessage) -> Self {
        Self {
            sender: message.sender,
            text: String::from_utf8_lossy(&message.plaintext).into_owned(),
            signed_timestamp_ms: message.signed_timestamp_ms,
            epoch: message.epoch,
            generation: message.generation,
        }
    }

    /// Stable key of the message (sender, epoch, generation).
    pub(crate) fn key(&self) -> String {
        message_key(self.sender, self.epoch, self.generation)
    }
}

fn message_key(sender: MemberRef, epoch: u64, generation: u32) -> String {
    format!("{}:{epoch}:{generation}", member_ref_text(sender))
}

/// A membership change seen during a sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RosterChange {
    Joined(MemberRef),
    Removed(MemberRef),
    Resynced(MemberRef),
    LeaveRequested(MemberRef),
    KeyRotated(MemberRef),
    AdminsChanged,
}

/// What a sync produced.
#[derive(Clone, Debug, Default)]
pub(crate) struct SyncOutcome {
    pub(crate) messages: Vec<IncomingMessage>,
    pub(crate) changes: Vec<RosterChange>,
    pub(crate) rejected: usize,
    pub(crate) removed: bool,
    pub(crate) resynced: bool,
    pub(crate) view: SessionView,
    pub(crate) aliases: BTreeMap<MemberRef, String>,
}

fn changes_of(report: &SyncReport) -> Vec<RosterChange> {
    let mut changes = Vec::new();
    for proposal in &report.proposals {
        changes.push(RosterChange::LeaveRequested(MemberRef {
            leaf: proposal.proposal().target_leaf,
            since: proposal.proposal().target_since,
        }));
    }
    for commit in &report.commits {
        for removed in &commit.removed {
            changes.push(RosterChange::Removed(removed.member));
        }
        if let Some(entry) = &commit.author_entry {
            changes.push(match commit.kind {
                CommitKind::Resync => RosterChange::Resynced(entry.member),
                _ => RosterChange::Joined(entry.member),
            });
        }
        for joined in &commit.joined {
            changes.push(RosterChange::Joined(joined.member));
        }
        if commit.rotated_device_pk.is_some() {
            changes.push(RosterChange::KeyRotated(commit.author));
        }
        if !commit.admin_changes.is_empty() || commit.promoted_admin.is_some() {
            changes.push(RosterChange::AdminsChanged);
        }
    }
    changes
}

/// A freshly generated device identity.
pub(crate) fn new_identity() -> DeviceIdentity {
    use rand::RngExt;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand::rng().fill(seed.as_mut_slice());
    DeviceIdentity::from_seed(&seed)
}

fn client_for(server_url: &str) -> Result<DsClient> {
    if server_url.trim().is_empty() {
        return Err(anyhow!("the server URL must not be empty"));
    }
    Ok(DsClient::new(server_url.trim())?)
}

/// Create a room of `capacity` leaves; this device becomes its first admin.
pub(crate) async fn create_room(server_url: &str, alias: &str, capacity: u32) -> Result<Member> {
    let mut member = Member::create(client_for(server_url)?, new_identity(), capacity)
        .await
        .context("failed to create the room")?;
    member
        .bind_alias(alias)
        .await
        .context("failed to publish the alias")?;
    Ok(member)
}

/// Join a room through an invite link.
pub(crate) async fn join_room(link: &InviteLink, alias: &str) -> Result<Member> {
    let mut member = Member::join_with_invite(client_for(&link.server_url)?, new_identity(), link)
        .await
        .context("failed to join the room")?;
    member
        .bind_alias(alias)
        .await
        .context("failed to publish the alias")?;
    Ok(member)
}

/// Follow the room log and refresh aliases.
pub(crate) async fn sync_room(member: &SharedMember) -> Result<SyncOutcome> {
    let mut member = member.lock().await;
    let report = member.sync().await.context("failed to sync the room")?;
    let changes = changes_of(&report);
    let aliases = if report.removed {
        BTreeMap::new()
    } else {
        member.aliases().await.unwrap_or_default()
    };
    Ok(SyncOutcome {
        changes,
        rejected: report.rejected,
        removed: report.removed,
        resynced: report.resynced,
        view: view_of(&member, &aliases),
        aliases,
        messages: report
            .messages
            .into_iter()
            .map(IncomingMessage::from_received)
            .collect(),
    })
}

/// A message this device sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SentOutcome {
    pub(crate) key: String,
    pub(crate) signed_timestamp_ms: u64,
    pub(crate) seq: u64,
}

/// Encrypt, sign and send a text message.
pub(crate) async fn send_text(member: &SharedMember, text: &str) -> Result<SentOutcome> {
    let mut member = member.lock().await;
    let generation = member.session().next_own_generation();
    let sent = member
        .send_text(text)
        .await
        .context("failed to send the message")?;
    Ok(SentOutcome {
        key: message_key(member.session().me(), sent.epoch, generation),
        signed_timestamp_ms: sent.signed_timestamp_ms,
        seq: sent.seq,
    })
}

/// Result of a membership operation.
#[derive(Clone, Debug)]
pub(crate) struct RosterOutcome {
    pub(crate) view: SessionView,
}

async fn roster_outcome(member: &mut Member) -> Result<RosterOutcome> {
    let aliases = member.aliases().await.unwrap_or_default();
    Ok(RosterOutcome {
        view: view_of(member, &aliases),
    })
}

/// Leave the room: record this device's leave proposal (another member
/// commits it).
pub(crate) async fn leave_room(member: &SharedMember) -> Result<()> {
    let mut member = member.lock().await;
    member.leave().await.context("failed to request the leave")
}

/// Remove the member `target` (admins).
pub(crate) async fn expel(member: &SharedMember, target: MemberRef) -> Result<RosterOutcome> {
    let mut member = member.lock().await;
    if member.session().tree().member_by_ref(target).is_none() {
        return Err(anyhow!("that device is no longer a member"));
    }
    member
        .remove_member(target.leaf)
        .await
        .context("failed to remove the member")?;
    roster_outcome(&mut member).await
}

/// Grant or revoke admin rights of the member whose device key is
/// `device_public_key` (admins).
pub(crate) async fn set_admin(
    member: &SharedMember,
    device_public_key: &[u8],
    grant: bool,
) -> Result<RosterOutcome> {
    let mut member = member.lock().await;
    let leaf = member
        .session()
        .tree()
        .find_device(device_public_key)
        .ok_or_else(|| anyhow!("that identity key is not a member of this room"))?;
    member.set_admin(leaf, grant).await.context(if grant {
        "failed to grant admin rights"
    } else {
        "failed to revoke admin rights"
    })?;
    roster_outcome(&mut member).await
}

/// Re-key this device's leaf and path (forward secrecy and PCS).
pub(crate) async fn refresh_keys(member: &SharedMember) -> Result<RosterOutcome> {
    let mut member = member.lock().await;
    member
        .self_update()
        .await
        .context("failed to refresh the room keys")?;
    roster_outcome(&mut member).await
}

/// Commit the recorded proposals (other members' leave requests and join
/// requests), if any.
pub(crate) async fn commit_pending(member: &SharedMember) -> Result<Option<RosterOutcome>> {
    let mut member = member.lock().await;
    if !member
        .commit_pending()
        .await
        .context("failed to commit the pending proposals")?
    {
        return Ok(None);
    }
    Ok(Some(roster_outcome(&mut member).await?))
}

/// Create an invite link (admins).
pub(crate) async fn create_invite(member: &SharedMember) -> Result<String> {
    let mut member = member.lock().await;
    let server_url = member.client().base_url().to_string();
    let link = member
        .create_invite_link(&server_url, INVITE_TTL_MS, INVITE_MAX_USES)
        .await
        .context("failed to create the invite")?;
    Ok(link.encode())
}

/// Erase the previous epochs' message keys (end of the grace window).
pub(crate) async fn expire_previous_epochs(member: &SharedMember) -> Result<()> {
    let mut member = member.lock().await;
    Ok(member.expire_previous_epochs()?)
}

/// Whether an error means this device is no longer a member.
pub(crate) fn is_membership_loss(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<ClientError>()
            .and_then(ClientError::api_code)
            .is_some_and(|code| {
                matches!(
                    code,
                    cityg_api_client::cityg_proto::ErrorCode::Forbidden
                        | cityg_api_client::cityg_proto::ErrorCode::NotFound
                )
            })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;

    /// Start an in-process v3 delivery service; returns its URL.
    pub(crate) async fn spawn_server() -> String {
        use cityg_api::routes::{ServiceState, router};
        use cityg_runtime::{NativeRoomStore, ServiceConfig};
        let state = ServiceState::new(
            ServiceConfig::default(),
            NativeRoomStore::for_state_path(None).unwrap(),
            64,
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn shared(member: Member) -> SharedMember {
        Arc::new(Mutex::new(member))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn engine_drives_a_room_end_to_end() {
        let url = spawn_server().await;
        assert!(create_room("  ", "alice", 8).await.is_err());
        let alice = shared(create_room(&url, "alice", 8).await.unwrap());
        let invite = create_invite(&alice).await.unwrap();
        let link = InviteLink::parse(&invite).unwrap().unwrap();
        // Two concurrent joiners enter with one commit.
        let (bob, carol) = tokio::join!(join_room(&link, "bob"), join_room(&link, "carol"));
        let (bob, carol) = (shared(bob.unwrap()), shared(carol.unwrap()));

        let outcome = sync_room(&alice).await.unwrap();
        assert_eq!(outcome.view.roster.len(), 3);
        assert_eq!(outcome.view.capacity, 8);
        assert!(outcome.view.is_admin);
        assert!(
            outcome
                .changes
                .iter()
                .any(|c| matches!(c, RosterChange::Joined(_)))
        );
        assert_eq!(outcome.aliases.values().filter(|a| *a == "bob").count(), 1);

        let sent = send_text(&alice, "hello").await.unwrap();
        let bob_outcome = sync_room(&bob).await.unwrap();
        let received = bob_outcome
            .messages
            .iter()
            .find(|message| message.text == "hello")
            .unwrap();
        assert_eq!(received.key(), sent.key);
        assert_eq!(received.sender, outcome.view.me);
        assert_eq!(received.signed_timestamp_ms, sent.signed_timestamp_ms);
        assert!(!bob_outcome.view.is_admin);

        // A joiner waits for an online member to commit its request.
        let joiner = tokio::spawn({
            let link = link.clone();
            async move { join_room(&link, "dave").await }
        });
        let mut seen_request = false;
        for _ in 0..100 {
            let seen = sync_room(&alice).await.unwrap();
            if seen.view.pending_joins == 1 {
                seen_request = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(seen_request);
        assert!(commit_pending(&alice).await.unwrap().is_some());
        let dave = shared(joiner.await.unwrap().unwrap());
        assert_eq!(
            sync_room(&dave).await.unwrap().view.roster.len(),
            4,
            "dave entered through the welcome"
        );

        // Carol leaves; Bob commits her removal.
        leave_room(&carol).await.unwrap();
        let seen = sync_room(&bob).await.unwrap();
        assert!(
            seen.changes
                .iter()
                .any(|c| matches!(c, RosterChange::LeaveRequested(_)))
        );
        assert_eq!(seen.view.pending_removals, 1);
        assert!(
            seen.view
                .roster
                .iter()
                .any(|entry| entry.pending_removal && entry.alias.as_deref() == Some("carol"))
        );
        assert!(commit_pending(&bob).await.unwrap().is_some());
        assert!(commit_pending(&bob).await.unwrap().is_none());
        assert!(sync_room(&carol).await.unwrap().removed);

        // Admin operations.
        let bob_key = bob.lock().await.identity().public_key().to_vec();
        let granted = set_admin(&alice, &bob_key, true).await.unwrap();
        assert!(
            granted
                .view
                .roster
                .iter()
                .any(|entry| entry.admin && entry.device_public_key == bob_key)
        );
        assert!(set_admin(&alice, &[1, 2, 3], true).await.is_err());
        let refreshed = refresh_keys(&bob).await.unwrap();
        assert_eq!(refreshed.view.epochs_since_own_update, 0);
        let bob_ref = bob.lock().await.session().me();
        sync_room(&alice).await.unwrap();
        let expelled = expel(&alice, bob_ref).await.unwrap();
        assert_eq!(expelled.view.roster.len(), 2);
        assert!(expel(&alice, bob_ref).await.is_err());
        let error = send_text(&bob, "am I still here?").await.unwrap_err();
        assert!(!format!("{error:#}").is_empty());
        assert!(sync_room(&bob).await.unwrap().removed);
        expire_previous_epochs(&alice).await.unwrap();
        assert!(
            alice
                .lock()
                .await
                .session()
                .previous_epochs()
                .next()
                .is_none()
        );
    }

    #[test]
    fn membership_loss_detection() {
        let forbidden: anyhow::Error =
            ClientError::Api(cityg_api_client::cityg_proto::ApiError::new(
                cityg_api_client::cityg_proto::ErrorCode::Forbidden,
                "not a member",
            ))
            .into();
        assert!(is_membership_loss(&forbidden.context("sending")));
        assert!(!is_membership_loss(&anyhow!("network down")));
        let entry = IncomingMessage {
            sender: MemberRef { leaf: 1, since: 4 },
            text: "x".into(),
            signed_timestamp_ms: 1,
            epoch: 2,
            generation: 3,
        };
        assert_eq!(entry.key(), "1.4:2:3");
        assert!(now_ms() > 0);
    }

    #[test]
    fn member_refs_round_trip_through_text() {
        let member = MemberRef { leaf: 7, since: 42 };
        assert_eq!(member_ref_text(member), "7.42");
        assert_eq!(parse_member_ref(" 7.42 "), Some(member));
        assert_eq!(parse_member_ref("7"), None);
        assert_eq!(parse_member_ref("x.1"), None);
        assert_eq!(parse_member_ref("1.y"), None);
    }

    #[test]
    fn sync_reports_become_roster_changes() {
        use cityg_api_client::cityg_core::state::MemberChange;
        let summary = |kind| cityg_api_client::cityg_core::session::CommitSummary {
            epoch: 3,
            kind,
            author: MemberRef { leaf: 0, since: 0 },
            author_device_pk: vec![1],
            removed: vec![MemberChange {
                member: MemberRef { leaf: 2, since: 1 },
                device_pk: vec![2],
            }],
            author_entry: Some(MemberChange {
                member: MemberRef { leaf: 3, since: 3 },
                device_pk: vec![3],
            }),
            joined: vec![MemberChange {
                member: MemberRef { leaf: 4, since: 3 },
                device_pk: vec![4],
            }],
            admin_changes: Vec::new(),
            promoted_admin: Some(0),
            rotated_device_pk: Some(vec![5]),
        };
        let report = SyncReport {
            commits: vec![
                summary(CommitKind::Resync),
                summary(CommitKind::ExternalJoin),
            ],
            ..SyncReport::default()
        };
        let changes = changes_of(&report);
        assert!(changes.contains(&RosterChange::Resynced(MemberRef { leaf: 3, since: 3 })));
        assert!(changes.contains(&RosterChange::Joined(MemberRef { leaf: 3, since: 3 })));
        assert!(changes.contains(&RosterChange::Joined(MemberRef { leaf: 4, since: 3 })));
        assert!(changes.contains(&RosterChange::Removed(MemberRef { leaf: 2, since: 1 })));
        assert!(changes.contains(&RosterChange::KeyRotated(MemberRef { leaf: 0, since: 0 })));
        assert!(changes.contains(&RosterChange::AdminsChanged));
    }
}
