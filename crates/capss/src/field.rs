//! Field abstraction for CAPSS experiments. We define a local BN254-compatible field so we can
//! attach Poseidon parameters without breaking orphan rules.

use ark_ff::{
    BigInteger, PrimeField, Zero,
    fields::{Fp256, MontBackend, MontConfig},
};

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
pub struct CapssFieldConfig;

pub use CapssFieldConfig as FieldConfig;

pub type BaseField = Fp256<MontBackend<CapssFieldConfig, 4>>;

/// Wrapper around the CAPSS field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldElement(pub BaseField);

impl Default for FieldElement {
    fn default() -> Self {
        Self(BaseField::zero())
    }
}

impl FieldElement {
    pub fn zero() -> Self {
        Self(BaseField::zero())
    }

    pub fn from_base(value: BaseField) -> Self {
        Self(value)
    }

    pub fn as_base(&self) -> BaseField {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let repr: <BaseField as PrimeField>::BigInt = self.0.into_bigint();
        let repr_bytes = repr.to_bytes_le();
        bytes[..repr_bytes.len()].copy_from_slice(&repr_bytes);
        bytes
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(BaseField::from_le_bytes_mod_order(&bytes))
    }
}

impl serde::Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FieldElementVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldElementVisitor {
            type Value = FieldElement;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("32-byte field element")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 32 {
                    return Err(E::custom("expected 32 bytes"));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(v);
                Ok(FieldElement::from_bytes(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut buf = Vec::with_capacity(32);
                while let Some(byte) = seq.next_element::<u8>()? {
                    buf.push(byte);
                }
                if buf.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&buf);
                Ok(FieldElement::from_bytes(arr))
            }
        }

        deserializer.deserialize_bytes(FieldElementVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::FieldElement;

    #[test]
    fn zero_default_and_accessors_are_consistent() {
        let zero = FieldElement::zero();
        let defaulted = FieldElement::default();
        assert_eq!(zero, defaulted);
        assert_eq!(zero.as_base(), super::BaseField::from(0u64));

        let from_base = FieldElement::from_base(super::BaseField::from(7u64));
        assert_eq!(from_base.as_base(), super::BaseField::from(7u64));
    }

    #[test]
    fn to_bytes_and_from_bytes_roundtrip() {
        let elem = FieldElement::from_base(super::BaseField::from(42u64));
        let bytes = elem.to_bytes();
        let recovered = FieldElement::from_bytes(bytes);
        assert_eq!(elem, recovered);
    }

    #[test]
    fn serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let elem = FieldElement::from_base(super::BaseField::from(123456u64));
        let json = serde_json::to_string(&elem)?;
        let parsed: FieldElement = serde_json::from_str(&json)?;
        assert_eq!(elem, parsed);
        Ok(())
    }

    #[test]
    fn serde_rejects_wrong_length() {
        let invalid_json = format!("[{}]", vec!["0"; 31].join(","));
        let result: Result<FieldElement, _> = serde_json::from_str(&invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn binary_serde_roundtrip_and_length_validation() -> Result<(), Box<dyn std::error::Error>> {
        let elem = FieldElement::from_base(super::BaseField::from(777u64));
        let encoded = bincode::serialize(&elem)?;
        let decoded: FieldElement = bincode::deserialize(&encoded)?;
        assert_eq!(decoded, elem);

        let short_bytes = bincode::serialize(&vec![0u8; 31])?;
        let short: Result<FieldElement, _> = bincode::deserialize(&short_bytes);
        assert!(short.is_err());
        Ok(())
    }
}
