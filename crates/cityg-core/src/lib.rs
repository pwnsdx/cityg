#![forbid(unsafe_code)]
//! City-G v0.3 protocol core.
//!
//! This crate holds the whole cryptographic state machine of the v0.3
//! profile and performs no I/O: the server stores and orders what it
//! produces, clients drive it, and every input of randomness comes from a
//! caller-provided [`rand_core::CryptoRngCore`] so that runs and test
//! vectors are reproducible.
//!
//! Layers, bottom-up:
//! * [`cbor`], [`hash`]: deterministic CBOR and the labelled hash / key
//!   derivation functions (`H`, `H_L`, `Extract`, `ExpandLabel`, `MAC`);
//! * [`kem`], [`identity`]: X-Wing and ML-DSA-65 keys, `device_id`, `gid`;
//! * [`tree`]: the ratchet tree (TreeKEM in the RFC 9420 array layout),
//!   which also holds the members;
//! * [`registry`]: capacity, admins and retired admissions
//!   (`registry_hash`);
//! * [`key_schedule`]: GroupContext, transcript hashes, joiner and epoch
//!   secrets;
//! * [`proposal`], [`join`], [`admission`], [`cover`]: signed removal
//!   proposals, join requests and welcomes, invites and admissions,
//!   cover-failure reports;
//! * [`commit`], [`group_info`], [`state`]: commits, the signed GroupInfo
//!   and the public commit transition;
//! * [`message`]: message plane v4;
//! * [`session`]: the member state machine;
//! * [`light`]: light members, which keep no public tree and verify commits
//!   with Merkle proofs of the records they refer to;
//! * [`ledger`]: the delivery-service state machine;
//! * [`binding`]: deployment binding objects (aliases, session tokens), which
//!   are outside the group protocol.

pub mod admission;
pub mod binding;
pub mod cbor;
pub mod commit;
pub mod cover;
pub mod error;
pub mod group_info;
pub mod hash;
pub mod identity;
pub mod join;
pub mod kem;
pub mod key_schedule;
pub mod ledger;
pub mod light;
pub mod message;
pub mod proposal;
pub mod registry;
pub mod session;
mod signed;
pub mod state;
pub mod tree;

pub use error::{CoreError, CoreResult};
