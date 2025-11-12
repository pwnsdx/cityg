//! Shared types exposed by the CAPSS scaffold.

use crate::field::FieldElement;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapssPublicKey {
    /// Initialization vector for the permutation-based OWF.
    pub iv: Vec<FieldElement>,
    /// One-way function output.
    pub y: FieldElement,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapssStatement {
    /// Public key associated with the signature.
    pub public_key: CapssPublicKey,
    /// Message digest or additional public inputs.
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapssProof {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapssSignature {
    pub proof: CapssProof,
}
