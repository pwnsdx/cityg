//! Invite links.
//!
//! ```text
//! cityg-invite:{"version":4,"server_url":"...","room_id":"<gid hex>",
//!               "invite_seed":"<32-byte seed hex>"}
//! ```
//!
//! The seed derives the invite key pair; whoever holds the link can sign an
//! admission with it until the admin-signed invite expires. Links are
//! capabilities: share them over a channel you trust.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::client::ClientError;

/// Prefix of an invite link.
pub const INVITE_PREFIX: &str = "cityg-invite:";
/// Version of the invite links of profile v0.2.
pub const INVITE_VERSION: u8 = 4;

/// A parsed invite link.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteLink {
    pub server_url: String,
    pub gid: [u8; 32],
    pub invite_seed: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InviteLink")
            .field("server_url", &self.server_url)
            .field("gid", &hex::encode(self.gid))
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    version: u8,
    server_url: String,
    room_id: String,
    #[serde(default)]
    invite_seed: String,
}

fn hex32(value: &str, what: &'static str) -> Result<[u8; 32], ClientError> {
    hex::decode(value.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ClientError::InvalidInvite(what))
}

impl InviteLink {
    /// Encode the link.
    #[must_use]
    pub fn encode(&self) -> String {
        let payload = Payload {
            version: INVITE_VERSION,
            server_url: self.server_url.clone(),
            room_id: hex::encode(self.gid),
            invite_seed: hex::encode(*self.invite_seed),
        };
        let json = serde_json::to_string(&payload).unwrap_or_default();
        format!("{INVITE_PREFIX}{json}")
    }

    /// Parse a link; `Ok(None)` when `raw` is not an invite link at all.
    pub fn parse(raw: &str) -> Result<Option<Self>, ClientError> {
        let Some(json) = raw.trim().strip_prefix(INVITE_PREFIX) else {
            return Ok(None);
        };
        let payload: Payload = serde_json::from_str(json)
            .map_err(|_| ClientError::InvalidInvite("malformed payload"))?;
        if payload.version != INVITE_VERSION {
            return Err(ClientError::InvalidInvite(
                "unsupported invite version (v0.2 links are version 4)",
            ));
        }
        if payload.server_url.trim().is_empty() {
            return Err(ClientError::InvalidInvite("missing server URL"));
        }
        Ok(Some(Self {
            server_url: payload.server_url,
            gid: hex32(&payload.room_id, "room id")?,
            invite_seed: Zeroizing::new(hex32(&payload.invite_seed, "invite seed")?),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn links_round_trip_and_reject_old_versions() {
        let link = InviteLink {
            server_url: "https://example.test".into(),
            gid: [3; 32],
            invite_seed: Zeroizing::new([4; 32]),
        };
        let encoded = link.encode();
        assert!(encoded.starts_with(INVITE_PREFIX));
        assert_eq!(InviteLink::parse(&encoded).unwrap(), Some(link.clone()));
        assert!(
            !format!("{link:?}").contains("0404"),
            "the seed is not printed"
        );
        assert_eq!(InviteLink::parse("hello").unwrap(), None);
        let v3 = r#"cityg-invite:{"version":3,"server_url":"x","room_id":"00"}"#;
        assert!(InviteLink::parse(v3).is_err());
        let bad_seed = format!(
            r#"cityg-invite:{{"version":4,"server_url":"x","room_id":"{}","invite_seed":"zz"}}"#,
            "00".repeat(32)
        );
        assert!(InviteLink::parse(&bad_seed).is_err());
        let no_server = format!(
            r#"cityg-invite:{{"version":4,"server_url":" ","room_id":"{}","invite_seed":"{}"}}"#,
            "00".repeat(32),
            "00".repeat(32)
        );
        assert!(InviteLink::parse(&no_server).is_err());
        assert!(InviteLink::parse("cityg-invite:{").is_err());
    }
}
