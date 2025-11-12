use blake3::Hasher;

use crate::field::BaseField;

use super::commit::bytes_to_field;

/// Deterministic randomness tree shared across the SmallWood prover components.
#[derive(Clone, Debug)]
pub struct SmallwoodSeeder {
    master: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RoundSeeder {
    master: [u8; 32],
}

impl SmallwoodSeeder {
    /// Derive the master seed from the transcript context (domain + statement bytes).
    pub fn new(fs_domain: &str, statement_bytes: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"smallwood/seed/master");
        hasher.update(fs_domain.as_bytes());
        hasher.update(statement_bytes);
        let digest = hasher.finalize();
        let mut master = [0u8; 32];
        master.copy_from_slice(digest.as_bytes());
        Self { master }
    }

    /// Derive a per-round seeder used for salts and other round-specific material.
    pub fn round(&self, round: u64) -> RoundSeeder {
        let mut hasher = Hasher::new();
        hasher.update(b"smallwood/seed/round");
        hasher.update(&self.master);
        hasher.update(&round.to_le_bytes());
        let digest = hasher.finalize();
        let mut master = [0u8; 32];
        master.copy_from_slice(digest.as_bytes());
        RoundSeeder { master }
    }

    /// Deterministic field element for witness high coefficients.
    pub fn witness_high(&self, row_idx: usize, coeff_idx: usize) -> BaseField {
        let mut context = Vec::with_capacity(16);
        context.extend_from_slice(&(row_idx as u64).to_le_bytes());
        context.extend_from_slice(&(coeff_idx as u64).to_le_bytes());
        let bytes = derive_bytes(&self.master, b"witness/high", &context, 32);
        bytes_to_field(&bytes)
    }

    /// Deterministic field element for mask polynomial high coefficients.
    pub fn mask_high(&self, mask_idx: usize, coeff_idx: usize) -> BaseField {
        let mut context = Vec::with_capacity(16);
        context.extend_from_slice(&(mask_idx as u64).to_le_bytes());
        context.extend_from_slice(&(coeff_idx as u64).to_le_bytes());
        let bytes = derive_bytes(&self.master, b"mask/high", &context, 32);
        bytes_to_field(&bytes)
    }

    pub fn master_bytes(&self) -> [u8; 32] {
        self.master
    }
}

impl RoundSeeder {
    /// Derive a salt of the requested length for this round.
    pub fn salt(&self, len: usize) -> Vec<u8> {
        derive_bytes(&self.master, b"round/salt", &[], len)
    }

    /// Generic byte derivation helper for other per-round needs.
    pub fn bytes(&self, label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
        derive_bytes(&self.master, label, context, len)
    }

    /// Derive a new seeder namespace for subcomponents.
    pub fn branch(&self, label: &[u8], context: &[u8]) -> RoundSeeder {
        let bytes = derive_bytes(&self.master, label, context, 32);
        let mut master = [0u8; 32];
        master.copy_from_slice(&bytes);
        RoundSeeder { master }
    }

    /// Deterministically sample a field element from the namespace.
    pub fn field(&self, label: &[u8], context: &[u8]) -> BaseField {
        let bytes = derive_bytes(&self.master, label, context, 32);
        bytes_to_field(&bytes)
    }

    pub fn master_bytes(&self) -> [u8; 32] {
        self.master
    }
}

fn derive_bytes(master: &[u8; 32], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(b"smallwood/seed/derive");
    hasher.update(master);
    hasher.update(&(len as u64).to_le_bytes());
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(context.len() as u64).to_le_bytes());
    hasher.update(context);
    let mut xof = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    xof.fill(&mut out);
    out
}
