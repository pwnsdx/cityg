//! Member sessions: bearer tokens issued against a signed [`SessionAuth`].
//!
//! A token binds one member device key of one group until it expires. It is
//! checked on every request that reads or writes group traffic, together
//! with the key's current membership, so a removed member's tokens stop
//! working as soon as the commit removing it is accepted, and the tokens of
//! a rotated key as soon as the rotation is.

use std::collections::HashMap;

use cityg_core::binding::SessionAuth;
use cityg_core::hash::Digest;
use cityg_proto::{ApiError, ErrorCode};
use cityg_server::Room;
use rand_core::CryptoRngCore;

use super::handlers::core_error;

/// What a token grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub gid: Digest,
    pub device_pk: Vec<u8>,
    pub expires_at_ms: u64,
}

/// Issued tokens.
#[derive(Clone, Debug, Default)]
pub struct SessionRegistry {
    grants: HashMap<[u8; 32], Grant>,
}

/// Most live tokens kept; the soonest to expire go first beyond it.
const MAX_SESSIONS: usize = 100_000;

impl SessionRegistry {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a token for the member that signed `auth`.
    pub fn open(
        &mut self,
        room: &Room,
        auth: &[u8],
        now_ms: u64,
        ttl_ms: u64,
        max_skew_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<([u8; 32], u64), ApiError> {
        let auth = SessionAuth::decode(auth).map_err(core_error)?;
        if &auth.gid != room.gid() {
            return Err(ApiError::new(
                ErrorCode::Unprocessable,
                "session auth for another group",
            ));
        }
        auth.check_fresh(now_ms, max_skew_ms).map_err(core_error)?;
        if room.member(&auth.device_pk).is_none() {
            return Err(ApiError::new(ErrorCode::Forbidden, "not a member"));
        }
        self.prune(now_ms);
        if self.grants.len() >= MAX_SESSIONS
            && let Some(oldest) = self
                .grants
                .iter()
                .min_by_key(|(_, grant)| grant.expires_at_ms)
                .map(|(token, _)| *token)
        {
            self.grants.remove(&oldest);
        }
        let mut token = [0u8; 32];
        rng.fill_bytes(&mut token);
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        self.grants.insert(
            token,
            Grant {
                gid: *room.gid(),
                device_pk: auth.device_pk.clone(),
                expires_at_ms,
            },
        );
        Ok((token, expires_at_ms))
    }

    /// Check `token` for a request on `room`; returns the member's device
    /// key.
    pub fn check(
        &mut self,
        token: Option<&[u8; 32]>,
        room: &Room,
        now_ms: u64,
    ) -> Result<Vec<u8>, ApiError> {
        let token = token.ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "missing token"))?;
        let grant = self
            .grants
            .get(token)
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "unknown token"))?;
        if grant.expires_at_ms < now_ms {
            self.grants.remove(token);
            return Err(ApiError::new(ErrorCode::Unauthorized, "expired token"));
        }
        if &grant.gid != room.gid() {
            return Err(ApiError::new(
                ErrorCode::Unauthorized,
                "token for another group",
            ));
        }
        if room.member(&grant.device_pk).is_none() {
            self.grants.remove(token);
            return Err(ApiError::new(ErrorCode::Forbidden, "not a member"));
        }
        Ok(grant.device_pk)
    }

    /// Drop expired tokens.
    pub fn prune(&mut self, now_ms: u64) {
        self.grants.retain(|_, grant| grant.expires_at_ms >= now_ms);
    }

    /// Number of live tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether no token is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}
