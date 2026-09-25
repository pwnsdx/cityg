use super::*;

pub(super) use super::engine::{
    MemberRef, RosterEntry, SessionView, SharedMember, member_ref_text, parse_member_ref,
};

/// An active room session.
///
/// The member driver lives behind [`SharedMember`]; the UI renders the
/// [`SessionView`] snapshot that every background operation returns.
#[derive(Clone)]
pub(super) struct AppSession {
    pub(super) server_url: String,
    /// Hex of the group identifier.
    pub(super) room_id: String,
    pub(super) alias: String,
    /// ML-DSA-65 device public key (the member's identity key).
    pub(super) pop_public_key: Vec<u8>,
    pub(super) member: SharedMember,
    pub(super) view: SessionView,
    /// When this device last re-keyed its own leaf (ms since the epoch);
    /// shared with the persistence sink.
    pub(super) self_update_clock: Arc<std::sync::atomic::AtomicU64>,
    /// When the current epoch became active locally (ms since the epoch).
    pub(super) epoch_started_ms: u64,
}

impl AppSession {
    /// Build the session of a member that just joined, created or restored.
    pub(super) fn new(
        server_url: String,
        alias: String,
        member: Member,
        last_self_update_ms: u64,
    ) -> Self {
        let view = engine::view_of(&member, &BTreeMap::new());
        Self {
            server_url,
            room_id: hex_encode(member.gid()),
            alias,
            pop_public_key: member.identity().public_key().to_vec(),
            member: Arc::new(tokio::sync::Mutex::new(member)),
            view,
            self_update_clock: Arc::new(std::sync::atomic::AtomicU64::new(last_self_update_ms)),
            epoch_started_ms: engine::now_ms(),
        }
    }

    /// When this device last re-keyed its own leaf.
    pub(super) fn last_self_update_ms(&self) -> u64 {
        self.self_update_clock
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record a self-update now.
    pub(super) fn mark_self_update(&self) {
        self.self_update_clock
            .store(engine::now_ms(), std::sync::atomic::Ordering::SeqCst);
    }

    /// Record a new view; returns whether the epoch changed.
    pub(super) fn apply_view(&mut self, view: SessionView) -> bool {
        let changed = view.epoch != self.view.epoch;
        if changed {
            self.epoch_started_ms = engine::now_ms();
        }
        self.view = view;
        changed
    }

    /// Whether this device holds admin rights in the current epoch.
    pub(super) fn is_admin(&self) -> bool {
        self.view.is_admin
    }

    /// This device's occupancy (it changes when the device resyncs).
    pub(super) fn me(&self) -> MemberRef {
        self.view.me
    }

    /// Whether a removal of this device is recorded and awaits a commit.
    pub(super) fn removal_pending(&self) -> bool {
        self.roster_entry(self.me())
            .is_some_and(|entry| entry.pending_removal)
    }

    /// Roster entry of `member`.
    pub(super) fn roster_entry(&self, member: MemberRef) -> Option<&RosterEntry> {
        self.view.roster.iter().find(|entry| entry.member == member)
    }
}
