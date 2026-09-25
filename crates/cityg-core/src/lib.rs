#![forbid(unsafe_code)]
//! City-G v0.2 protocol core.
//!
//! This crate holds the whole cryptographic state machine of the v0.2
//! profile and performs no I/O: the server stores and orders what it
//! produces, clients drive it, and every input of randomness comes from a
//! caller-provided [`rand_core::CryptoRngCore`] so that runs and test
//! vectors are reproducible.
//!
//! Layers, bottom-up:
//! * [`cbor`], [`hash`]: deterministic CBOR and the labelled hash / key
//!   derivation functions (`H`, `H_L`, `Extract`, `ExpandLabel`, `MAC`);
//! * [`kem`], [`identity`]: ML-KEM-768 and ML-DSA-87 keys, `leaf_id`, `gid`;
//! * [`tree`]: the barrier tree v2 (TreeKEM-style ratchet tree);
//! * [`roster`]: members, admins and slot generations (`roster_hash`);
//! * [`key_schedule`]: GroupContext, transcript hashes and epoch secrets;
//! * [`proposal`], [`admission`], [`cover`]: signed removal proposals,
//!   invites and admissions, cover-failure reports;
//! * [`commit`], [`group_info`], [`state`]: the v0.2 anchors (commits), the
//!   signed GroupInfo and the public commit transition;
//! * [`message`]: message plane v3;
//! * [`session`]: the member state machine;
//! * [`ledger`]: the delivery-service state machine.

pub mod admission;
pub mod cbor;
pub mod commit;
pub mod cover;
pub mod error;
pub mod group_info;
pub mod hash;
pub mod identity;
pub mod kem;
pub mod key_schedule;
pub mod ledger;
pub mod message;
pub mod proposal;
pub mod roster;
pub mod session;
mod signed;
pub mod state;
pub mod tree;

pub use error::{CoreError, CoreResult};
