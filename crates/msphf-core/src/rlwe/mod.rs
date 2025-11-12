//! RLWE primitives for the `rlwe-merkle/v1` SPHF instantiation (profile A1).
//!
//! This module implements the low-level arithmetic, NTT, noise samplers and
//! polynomial/vec helpers needed by the HPS pipeline described in Annex K of
//! the City‑G specification.

pub mod arithmetic;
pub mod constants;
pub mod matrix;
pub mod noise;
pub mod ntt;
pub mod poly;
pub mod polyvec;

pub use constants::{K, N, Q};
