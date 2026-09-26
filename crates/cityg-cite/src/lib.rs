//! City-G profile v0.4-draft ("Cité"): a prototype of the protocol drafted in
//! `docs/specs-v0.4-draft.md`, for groups of millions of members.
//!
//! Profile v0.3 (`cityg-core`) stays the normative profile. This crate
//! reuses its primitives (X-Wing, ML-DSA-65, BLAKE3, ChaCha20-Poly1305,
//! deterministic CBOR) under v0.4 domain separation, and adds:
//!
//! * a sparse public tree split into districts under a city ([`tree`]);
//! * the multi-path re-key of a district or of the city, with taints
//!   ([`rekey`]);
//! * district commits and seals, one epoch per window ([`commit`]);
//! * the key schedule with the init chain and external init ([`schedule`]);
//! * district welcomes ([`welcome`]);
//! * the registry as sparse Merkle maps ([`smm`], [`registry`]);
//! * the signed requests of members, joiners and admins ([`objects`]);
//! * members: windows, roles, catch-up and re-entry ([`member`]);
//! * an in-memory delivery service: queues, placement, windows, validation,
//!   packets, zero-online operation, eviction and audits ([`ds`]).
//!
//! The crate has no I/O and is not wired to the `/v3` stack.

pub mod audit;
mod codec;
pub mod commit;
pub mod crypto;
pub mod ds;
pub mod member;
pub mod objects;
pub mod packet;
pub mod registry;
pub mod rekey;
pub mod roles;
pub mod schedule;
pub mod smm;
pub mod tree;
pub mod welcome;
pub mod window;
