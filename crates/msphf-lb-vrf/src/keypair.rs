// use crate::poly::PolyArith;
use crate::poly256::Poly256;
use zeroize::Zeroize;

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct PublicKey {
    pub(crate) t: [Poly256; 4],
}

#[derive(PartialEq, Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    pub(crate) s: [Poly256; 9],
}

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct MasterSecretKey {
    pub(crate) seed: [u8; 32],
}

impl MasterSecretKey {
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.seed
    }
}
