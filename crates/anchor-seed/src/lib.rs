//! Utilities to derive the ANCHOR_SEED_CTX context, its hash (header key 91)
//! and the `seed_commit` value consumed by KGen.

use std::collections::BTreeMap;

use ciborium::value::Value;
use msphf_core::{MsphfError, ds, hash};
use serde::Serialize;

/// Header keys marked `volatile=true` in the published ANCHOR header map.
const VOLATILE_KEYS: [u64; 6] = [11, 16, 43, 46, 89, 91];
/// Header keys that must never appear in `ANCHOR_SEED_CTX`.
// The unified spec excludes proof (95, 118, 119, 125), SRX (120–124) and bootstrap (130–132) keys.
// FS metadata (139–142) and device-chain keys (152–153) are retained per docs/specs.md.
const FORBIDDEN_SEED_CTX_KEYS: &[u64] = &[
    93, 94, // rho commit and seed bundle commit must be excluded
    95, 96, 97, 98, 99, 100, // msphf_hp + proof artifacts
    102, // join/merge note labels (e.g. script identifiers)
    107, 108, 109, // join PoP keys
    116, // meor_vrf_id
    118, 119, 125, // proof suite keys
    120, 121, 122, 123, 124, // SRX keys
    130, 131, 132, 133, 134, 135, 136, // rollup + merge telemetry keys
    137, 138, // bootstrap profile + rollup FS mode keys
    144, // FS evolution boundary flag
    145, // HDR_FS_PURGE_TIMES (merge-only)
    146, // CAPSS proof bytes
    147, // Merge-only SRX telemetry flag
    148, // FS checkpoint EC counter
    154, 155, 156, // VRF mask digests + VRF public key
    170, 171, 172, // bootstrap signature fields
];

/// Build the deterministic CBOR encoding of `ANCHOR_SEED_CTX` by removing the
/// keys listed in [`VOLATILE_KEYS`] and excluding proof/SRX/bootstrap keys.
pub fn build_anchor_seed_ctx(header_map: &BTreeMap<u64, Value>) -> Result<Vec<u8>, MsphfError> {
    let mut filtered = BTreeMap::new();
    for (key, value) in header_map.iter() {
        if VOLATILE_KEYS.contains(key) || FORBIDDEN_SEED_CTX_KEYS.contains(key) {
            continue;
        }
        filtered.insert(*key, value.clone());
    }

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&filtered, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}

/// Compute header key 91 (`msphf_seed_ctx_hash`).
pub fn compute_seed_ctx_hash(anchor_seed_ctx: &[u8]) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Ctx<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    hash::h_l(ds::MSPHF_SEED_CTX, &Ctx(anchor_seed_ctx))
}

/// Helper struct collecting the mandatory fields that feed into the
/// `seed_commit` derivation.
#[derive(Debug, Clone, Serialize)]
pub struct SeedCommitFields<'a> {
    #[serde(with = "serde_bytes")]
    pub gid: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub cat: &'a [u8],
    /// `we_epoch_id` is a 32-byte identifier derived from the City‑G joiner spec.
    pub we_epoch_id: [u8; 32],
}

/// Compute `seed_commit = H_L("msphf/kgen/seed", [ BYTES(ANCHOR_SEED_CTX), gid, cat, we_epoch_id ])`.
pub fn compute_seed_commit(
    anchor_seed_ctx: &[u8],
    fields: &SeedCommitFields,
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct SeedTuple<'a> {
        #[serde(with = "serde_bytes")]
        anchor_seed_ctx: &'a [u8],
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        cat: &'a [u8],
        #[serde(with = "serde_bytes")]
        we_epoch_id: &'a [u8],
    }

    let tuple = SeedTuple {
        anchor_seed_ctx,
        gid: fields.gid,
        cat: fields.cat,
        we_epoch_id: &fields.we_epoch_id,
    };

    hash::h_l(ds::MSPHF_KGEN_SEED, &tuple)
}

/// Compute `seed_bundle_commit = H_L("msphf/seed/bundle", [ BYTES(ANCHOR_SEED_CTX), rho_commit, gid, cat, parent_root ])`.
pub fn compute_seed_bundle_commit(
    anchor_seed_ctx: &[u8],
    rho_commit: &[u8; 32],
    gid: &[u8],
    cat: &[u8],
    parent_root: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct SeedBundle<'a> {
        #[serde(with = "serde_bytes")]
        anchor_seed_ctx: &'a [u8],
        #[serde(with = "serde_bytes")]
        rho_commit: &'a [u8],
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        cat: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8],
    }

    let bundle = SeedBundle {
        anchor_seed_ctx,
        rho_commit,
        gid,
        cat,
        parent_root,
    };

    hash::h_l("msphf/seed/bundle", &bundle)
}

/// Convenience function that performs the full seed-binding pipeline:
/// 1. remove suppression keys, 2. compute key 91, 3. compute `seed_commit`.
pub type SeedArtifacts = (Vec<u8>, [u8; 32], [u8; 32]);

pub fn derive_seed_artifacts(
    header_map: &BTreeMap<u64, Value>,
    fields: &SeedCommitFields,
) -> Result<SeedArtifacts, MsphfError> {
    let ctx = build_anchor_seed_ctx(header_map)?;
    let ctx_hash = compute_seed_ctx_hash(&ctx)?;
    let seed_commit = compute_seed_commit(&ctx, fields)?;
    Ok((ctx, ctx_hash, seed_commit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    fn sample_header() -> BTreeMap<u64, Value> {
        let mut map = BTreeMap::new();
        map.insert(10, Value::Bytes(vec![0xAA]));
        map.insert(20, Value::Bytes(vec![0xBB]));
        map.insert(90, Value::Integer((31_i64).into()));
        map.insert(110, Value::Bytes(vec![0x10]));
        map.insert(94, Value::Bytes(vec![0xAB]));
        map.insert(93, Value::Bytes(vec![0xDD]));
        map.insert(91, Value::Bytes(vec![0xCC]));
        map.insert(97, Value::Bytes(vec![0xEE]));
        map.insert(98, Value::Bytes(vec![0xFF]));
        map.insert(99, Value::Bytes(vec![0x11]));
        map.insert(95, Value::Bytes(vec![0x22]));
        map.insert(107, Value::Bytes(vec![0x33]));
        map.insert(108, Value::Bytes(vec![0x44]));
        map.insert(109, Value::Bytes(vec![0x55]));
        map.insert(116, Value::Text("lb-vrf/v1".to_string()));
        map.insert(118, Value::Bytes(vec![0x66]));
        map.insert(119, Value::Text("lin+zkvrf".to_string()));
        map.insert(125, Value::Bytes(vec![0x77]));
        map.insert(120, Value::Bytes(vec![0xEE]));
        map.insert(123, Value::Bytes(vec![0x01]));
        map.insert(124, Value::Bytes(vec![0x02]));
        map
    }

    #[test]
    fn anchor_seed_ctx_excludes_reserved_keys() -> Result<(), Box<dyn std::error::Error>> {
        let header = sample_header();
        let ctx = build_anchor_seed_ctx(&header)?;
        // Deserialize back to check keys.
        let value: BTreeMap<u64, Value> = ciborium::de::from_reader(ctx.as_slice())?;
        let observed: std::collections::BTreeSet<u64> = value.keys().copied().collect();
        let expected: std::collections::BTreeSet<u64> =
            [10_u64, 20_u64, 90_u64, 110_u64].into_iter().collect();
        assert_eq!(observed, expected, "unexpected key set: {:?}", observed);
        Ok(())
    }

    #[test]
    fn derive_seed_commit_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let header = sample_header();
        let fields = SeedCommitFields {
            gid: b"group-id",
            cat: b"category",
            we_epoch_id: [0x2A; 32],
        };
        let (_ctx, ctx_hash, seed_commit) = derive_seed_artifacts(&header, &fields)?;
        assert_ne!(ctx_hash, [0u8; 32]);
        assert_ne!(seed_commit, [0u8; 32]);
        Ok(())
    }
}
