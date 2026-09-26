#![forbid(unsafe_code)]
//! City-G protocol core, profile `city-g/v0.4` (`docs/specs.md`): end-to-end
//! encrypted groups of up to millions of members, whose tree is split into
//! districts under a city and re-keyed once per window.
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

pub mod audit;
pub mod cbor;
mod codec;
pub mod commit;
pub mod crypto;
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
pub mod tree;
pub mod welcome;
pub mod window;

pub use error::{CoreError, CoreResult};
