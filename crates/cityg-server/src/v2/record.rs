//! Journal records of a room.
//!
//! Every accepted mutation of a room is journaled as one record before the
//! request is acknowledged. Replaying the records of a room in order rebuilds
//! exactly the same room: every check the room runs is a deterministic
//! function of the record, the ledger clock included.
//!
//! ```text
//! RoomRecord := [0, commit, group_info, at_ms]   ; genesis
//!             | [1, commit, group_info, at_ms]   ; commit
//!             | [2, envelope, at_ms]             ; message
//!             | [3, proposal, at_ms]             ; removal proposal
//!             | [4, invite, at_ms]               ; invite
//!             | [5, binding]                     ; alias binding
//!             | [6, report]                      ; cover-failure report
//! ```

use ciborium::value::Value;
use cityg_core::cbor::{
    array, bytes, decode, encode, expect_bytes, expect_list, expect_uint, uint,
};
use cityg_core::{CoreError, CoreResult};

/// Largest encoded record (a commit of the largest tree plus its GroupInfo).
pub const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

/// One journaled mutation of a room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomRecord {
    Genesis {
        commit: Vec<u8>,
        group_info: Vec<u8>,
        at_ms: u64,
    },
    Commit {
        commit: Vec<u8>,
        group_info: Vec<u8>,
        at_ms: u64,
    },
    Message {
        envelope: Vec<u8>,
        at_ms: u64,
    },
    RemoveProposal {
        proposal: Vec<u8>,
        at_ms: u64,
    },
    Invite {
        invite: Vec<u8>,
        at_ms: u64,
    },
    Alias {
        binding: Vec<u8>,
    },
    CoverFailure {
        report: Vec<u8>,
    },
}

impl RoomRecord {
    /// Deterministic CBOR encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let value = match self {
            RoomRecord::Genesis {
                commit,
                group_info,
                at_ms,
            } => array(vec![
                uint(0),
                bytes(commit),
                bytes(group_info),
                uint(*at_ms),
            ]),
            RoomRecord::Commit {
                commit,
                group_info,
                at_ms,
            } => array(vec![
                uint(1),
                bytes(commit),
                bytes(group_info),
                uint(*at_ms),
            ]),
            RoomRecord::Message { envelope, at_ms } => {
                array(vec![uint(2), bytes(envelope), uint(*at_ms)])
            }
            RoomRecord::RemoveProposal { proposal, at_ms } => {
                array(vec![uint(3), bytes(proposal), uint(*at_ms)])
            }
            RoomRecord::Invite { invite, at_ms } => {
                array(vec![uint(4), bytes(invite), uint(*at_ms)])
            }
            RoomRecord::Alias { binding } => array(vec![uint(5), bytes(binding)]),
            RoomRecord::CoverFailure { report } => array(vec![uint(6), bytes(report)]),
        };
        encode(&value)
    }

    /// Decode a record.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_list(
            decode(encoded, MAX_RECORD_BYTES, "room record")?,
            "room record",
        )?
        .into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed("room record"));
        let tag = expect_uint(&next()?, "room record tag")?;
        let blob = |value: Value| expect_bytes(value, "room record field");
        let record = match tag {
            0 | 1 => {
                let commit = blob(next()?)?;
                let group_info = blob(next()?)?;
                let at_ms = expect_uint(&next()?, "room record time")?;
                if tag == 0 {
                    RoomRecord::Genesis {
                        commit,
                        group_info,
                        at_ms,
                    }
                } else {
                    RoomRecord::Commit {
                        commit,
                        group_info,
                        at_ms,
                    }
                }
            }
            2 => RoomRecord::Message {
                envelope: blob(next()?)?,
                at_ms: expect_uint(&next()?, "room record time")?,
            },
            3 => RoomRecord::RemoveProposal {
                proposal: blob(next()?)?,
                at_ms: expect_uint(&next()?, "room record time")?,
            },
            4 => RoomRecord::Invite {
                invite: blob(next()?)?,
                at_ms: expect_uint(&next()?, "room record time")?,
            },
            5 => RoomRecord::Alias {
                binding: blob(next()?)?,
            },
            6 => RoomRecord::CoverFailure {
                report: blob(next()?)?,
            },
            _ => return Err(CoreError::Malformed("room record tag")),
        };
        if items.next().is_some() {
            return Err(CoreError::Malformed("room record"));
        }
        Ok(record)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        let records = [
            RoomRecord::Genesis {
                commit: vec![1],
                group_info: vec![2],
                at_ms: 3,
            },
            RoomRecord::Commit {
                commit: vec![4],
                group_info: vec![5],
                at_ms: 6,
            },
            RoomRecord::Message {
                envelope: vec![7],
                at_ms: 8,
            },
            RoomRecord::RemoveProposal {
                proposal: vec![9],
                at_ms: 10,
            },
            RoomRecord::Invite {
                invite: vec![10],
                at_ms: 11,
            },
            RoomRecord::Alias { binding: vec![12] },
            RoomRecord::CoverFailure { report: vec![13] },
        ];
        for record in records {
            assert_eq!(
                RoomRecord::decode(&record.encode().unwrap()).unwrap(),
                record
            );
        }
        let unknown = encode(&array(vec![uint(9), bytes(&[1])])).unwrap();
        assert!(RoomRecord::decode(&unknown).is_err());
        let long = encode(&array(vec![uint(5), bytes(&[1]), uint(2)])).unwrap();
        assert!(RoomRecord::decode(&long).is_err());
        assert!(RoomRecord::decode(&[0x80]).is_err());
    }
}
