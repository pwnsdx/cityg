// #![cfg_attr(feature = "cargo-clippy", deny(warnings))]

// Re-export for internal crate usage and tests
pub use rand;
pub use rand_chacha;
pub use sha2;

pub mod error;
pub mod keypair;
pub mod lbvrf;
pub mod ntt;
pub mod param;
pub mod poly;
pub mod poly256;
pub mod poly32;
pub mod serde;
#[cfg(test)]
mod test;

pub use error::{Error, Result};
pub use keypair::{MasterSecretKey, PublicKey, SecretKey};

pub trait VRF {
    type PubParam;
    type PublicKey;
    type SecretKey;
    type Proof;
    type VrfOutput;

    /// input some seed, generate public parameters
    fn paramgen(seed: [u8; 32]) -> Result<Self::PubParam>;
    /// input a seed and a parameter output a pair of keys
    fn keygen(seed: [u8; 32], pp: Self::PubParam) -> Result<(Self::PublicKey, Self::SecretKey)>;

    /// input a message, a public parameter, a pair of keys
    /// generate a vrf proof
    fn prove<Blob: AsRef<[u8]>>(
        message: Blob,
        pp: Self::PubParam,
        pk: Self::PublicKey,
        sk: Self::SecretKey,
        seed: [u8; 32],
    ) -> Result<Self::Proof>;

    /// input a message, a public parameter, the public key, and a proof
    /// generate an output if proof is valid
    fn verify<Blob: AsRef<[u8]>>(
        message: Blob,
        pp: Self::PubParam,
        pk: Self::PublicKey,
        proof: Self::Proof,
    ) -> Result<Option<Self::VrfOutput>>;
}
