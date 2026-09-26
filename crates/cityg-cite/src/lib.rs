#![forbid(unsafe_code)]
//! City-G profile v0.4-draft ("Cité"): a prototype of the protocol drafted in
//! `docs/specs-v0.4-draft.md`, for groups of millions of members.
//!
//! Profile v0.3 (`cityg-core`) stays the normative profile. This crate
//! reuses its primitives (X-Wing, ML-DSA-65, BLAKE3, ChaCha20-Poly1305,
//! deterministic CBOR) under v0.4 domain separation, and adds, bottom-up:
//!
//! * hashing, derivation and wraps with the v0.4 tags ([`crypto`]);
//! * a sparse public tree split into districts under a city, with taints,
//!   leaf proofs and the hashes of a window before it is applied
//!   ([`tree`]);
//! * the multi-path re-key of a district or of the city, and the paths of
//!   members ([`rekey`]);
//! * the registry as sparse Merkle maps ([`smm`], [`registry`]);
//! * the key schedule with the init chain and external init ([`schedule`]);
//! * the signed requests of members, joiners and admins ([`objects`]);
//! * district commits and seals, one epoch per window ([`commit`]), and
//!   welcomes ([`welcome`]);
//! * the public state and the checked transition of a window ([`window`]);
//! * what committers and sealers compute ([`roles`]);
//! * packets, seal links and entries ([`packet`]);
//! * members, joiners and returning members, including windows an entrant
//!   seals when no member is online ([`member`]);
//! * an in-memory delivery service: queues, placement, roles, checks,
//!   packets, recorded removals, eviction and audit records ([`ds`]);
//! * audits of a window's entries and fraud proofs ([`audit`]).
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
