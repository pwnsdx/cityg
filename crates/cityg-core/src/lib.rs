#![forbid(unsafe_code)]
//! City-G protocol core, profile `city-g/v0.5-draft`, stages 1 and 2 but
//! disputes (`docs/specs-v0.5-draft.md`, a delta on `city-g/v0.4`,
//! `docs/specs.md`): end-to-end encrypted groups of up to millions of
//! members, whose tree is split into districts under a city of sub-cities
//! and a top, re-keyed once per window by district commits and city tasks
//! that members and the window's joiners perform, and read by island
//! through relays.
//!
//! The crate performs no I/O. Every input of randomness comes from a
//! caller-provided [`rand_core::CryptoRngCore`], so that runs are
//! reproducible. Layers, bottom-up:
//!
//! * deterministic CBOR ([`cbor`]) and errors ([`error`]);
//! * X-Wing ([`kem`]) and ML-DSA-65 device identities ([`identity`]);
//! * hashing, derivation and wraps ([`crypto`]);
//! * a sparse public tree split into districts under a city, with taints,
//!   leaf proofs and the hashes of a window before it is applied
//!   ([`tree`]);
//! * the multi-path re-key of a district or of a part of the city (a
//!   sub-city or the top), and the paths of members ([`rekey`]);
//! * the registry as sparse Merkle maps ([`smm`], [`registry`]);
//! * the key schedule with the init chain and external init ([`schedule`]);
//! * the signed requests of members, joiners and admins ([`objects`]);
//! * district commits, city tasks and seals, one epoch per window
//!   ([`commit`]), and welcomes ([`welcome`]);
//! * the public state and the checked transition of a window ([`window`]);
//! * what committers, performers of city tasks and sealers compute
//!   ([`roles`]);
//! * packets, seal links and entries, whole or by island ([`packet`]), and
//!   the top of an island follower's path: relay elements, flat elements,
//!   refreshes, and repairs ([`top`]);
//! * members, joiners and returning members, including windows an entrant
//!   seals when no member is online ([`member`]);
//! * an in-memory delivery service: queues, placement, roles, checks,
//!   packets, recorded removals, eviction, audit records, repair requests
//!   and the exclusion of performers they blame ([`ds`]);
//! * audits of a window's entries and fraud proofs ([`audit`]);
//! * disputes of faulty wraps, their public inputs and the interface of the
//!   proof system that checks them ([`dispute`]).

pub mod audit;
pub mod cbor;
mod codec;
pub mod commit;
pub mod crypto;
pub mod dispute;
pub mod ds;
pub mod error;
pub mod identity;
pub mod kem;
pub mod member;
pub mod objects;
pub mod packet;
pub mod registry;
pub mod rekey;
pub mod roles;
pub mod schedule;
pub mod smm;
pub mod top;
pub mod tree;
pub mod welcome;
pub mod window;

pub use error::{CoreError, CoreResult};
