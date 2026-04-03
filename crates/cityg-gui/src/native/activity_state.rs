#[derive(Clone, Default)]
pub(super) enum MembersMode {
    #[default]
    Full,
    Search {
        query: String,
    },
}

#[derive(Clone)]
pub(super) struct SecurityEvent {
    pub(super) alias: String,
    pub(super) description: String,
    pub(super) timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActivityKind {
    Connection,
    Roster,
    Message,
    Sync,
    System,
}

#[derive(Clone, Debug)]
pub(super) struct ActivityEvent {
    pub(super) kind: ActivityKind,
    pub(super) summary: String,
    pub(super) detail: Option<String>,
    pub(super) timestamp_ms: u64,
}

#[derive(Clone)]
pub(super) struct ChatMessageEntry {
    pub(super) sender_leaf: Option<[u8; 32]>,
    pub(super) fallback_label: String,
    pub(super) plaintext: String,
    pub(super) ciphertext_hex: String,
    pub(super) timestamp_ms: u64,
    pub(super) delivery: MessageDelivery,
    pub(super) pending_id: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum MessageDelivery {
    Pending,
    Sent,
    Failed,
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(super) struct MessageKey {
    pub(super) ciphertext_hex: String,
    pub(super) sender_leaf: Option<[u8; 32]>,
}

#[derive(Clone)]
pub(super) struct MemberEntry {
    pub(super) leaf_id: [u8; 32],
    pub(super) alias: Option<String>,
    pub(super) pop_public_key: Option<Vec<u8>>,
    pub(super) join_timestamp_ms: Option<u64>,
    pub(super) last_seen_timestamp_ms: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AliasBindingRecord {
    pub(super) pop_public_key: Vec<u8>,
    pub(super) leaf_id: [u8; 32],
}
