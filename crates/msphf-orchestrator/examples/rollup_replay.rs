//! Demonstrates how a client can consume `epoch_replay`/`kbroad_replay`
//! metadata emitted by a rollup merge. The example uses synthetic
//! values to keep it self-contained; the structure mirrors the real headers
//! produced by `joiner_kgen_merge_or`.
//!
//! Run with:
//! ```
//! cargo run -p msphf-orchestrator --example rollup_replay
//! ```

use std::collections::BTreeMap;

use ciborium::ser::into_writer;
use ciborium::value::Value;
use hex::ToHex;
use msphf_core::hash::h_l;
use msphf_orchestrator::hdr::{
    HDR_KBROAD_REPLAY, HDR_MH_HEADS, HDR_ROLLUP_EPOCH_REPLAY, HDR_ROLLUP_PIVOT_WEID,
    HDR_ROLLUP_PROVENANCE_COMMIT, HDR_ROLLUP_VCK_COMMIT,
};
use serde::Serialize;

#[derive(Serialize)]
struct RollupCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

fn main() -> anyhow::Result<()> {
    let header = sample_rollup_header()?;
    consume_rollup_metadata(&header)?;
    Ok(())
}

fn consume_rollup_metadata(header: &BTreeMap<u64, Value>) -> anyhow::Result<()> {
    let mh_heads = parse_sorted_unique_bytes(
        header
            .get(&HDR_MH_HEADS)
            .ok_or_else(|| anyhow::anyhow!("mh_heads (130) missing"))?,
    )?;
    println!("Retired heads (mh_heads):");
    for head in &mh_heads {
        println!("  {}", head.encode_hex::<String>());
    }

    let epoch_replay = parse_epoch_replay(
        header
            .get(&HDR_ROLLUP_EPOCH_REPLAY)
            .ok_or_else(|| anyhow::anyhow!("epoch_replay (133) missing"))?,
    )?;
    println!("\nEpoch replay entries:");
    for entry in &epoch_replay {
        println!(
            "  weid={} join={} parent_root={}",
            entry.weid.encode_hex::<String>(),
            entry.is_join,
            entry.parent_root.encode_hex::<String>()
        );
    }

    // Map kbroad clones for quick lookup.
    let kbroad_map = parse_kbroad_replay(
        header
            .get(&HDR_KBROAD_REPLAY)
            .ok_or_else(|| anyhow::anyhow!("kbroad_replay (136) missing"))?,
    )?;

    // Demonstrate how a client would fetch the KBROAD envelope for a join epoch.
    println!("\nKBROAD clones:");
    for entry in &epoch_replay {
        if !entry.is_join {
            continue;
        }
        let envelope = kbroad_map.get(&entry.weid).ok_or_else(|| {
            anyhow::anyhow!(
                "missing KBROAD clone for {}",
                entry.weid.encode_hex::<String>()
            )
        })?;
        println!(
            "  weid={} envelope_len={} (first bytes: {})",
            entry.weid.encode_hex::<String>(),
            envelope.len(),
            hex::encode(&envelope[..std::cmp::min(8, envelope.len())])
        );
    }

    // Recompute provenance and optional VCK commits to show the hashes verify.
    let provenance_commit = header
        .get(&HDR_ROLLUP_PROVENANCE_COMMIT)
        .ok_or_else(|| anyhow::anyhow!("rollup_provenance_commit (132) missing"))?;
    let vck_commit = header
        .get(&HDR_ROLLUP_VCK_COMMIT)
        .ok_or_else(|| anyhow::anyhow!("rollup_vck_commit (134) missing"))?;

    verify_commits(provenance_commit, vck_commit, &epoch_replay)?;

    // Pivot weid identifies which antecedent contributed the inherited ρ (field 93).
    let pivot_weid = match header
        .get(&HDR_ROLLUP_PIVOT_WEID)
        .ok_or_else(|| anyhow::anyhow!("pivot_weid (131) missing"))?
    {
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => anyhow::bail!("pivot_weid must be a 32-byte bstr"),
    };
    println!(
        "\nPivot antecedent: {} (ρ is inherited from this head)",
        pivot_weid.encode_hex::<String>()
    );

    println!("\nAll rollup metadata verified successfully.");
    Ok(())
}

fn parse_sorted_unique_bytes(value: &Value) -> anyhow::Result<Vec<[u8; 32]>> {
    let Value::Array(entries) = value else {
        anyhow::bail!("expected array");
    };
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Bytes(bytes) = entry else {
            anyhow::bail!("array element must be bytes");
        };
        if bytes.len() != 32 {
            anyhow::bail!("entries must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        result.push(arr);
    }
    // Ensure canonical ordering (lexicographic ascending, unique).
    let mut sorted = result.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != result {
        anyhow::bail!("entries must be sorted and unique");
    }
    Ok(result)
}

#[derive(Clone)]
struct EpochReplayEntry {
    weid: [u8; 32],
    xk_hash: [u8; 32],
    parent_root: [u8; 32],
    is_join: bool,
}

fn parse_epoch_replay(value: &Value) -> anyhow::Result<Vec<EpochReplayEntry>> {
    let Value::Array(entries) = value else {
        anyhow::bail!("epoch_replay must be an array");
    };
    let mut out = Vec::with_capacity(entries.len());
    let mut previous: Option<[u8; 32]> = None;
    for entry in entries {
        let Value::Array(fields) = entry else {
            anyhow::bail!("epoch entry must be array");
        };
        if fields.len() != 4 {
            anyhow::bail!("epoch entry must have 4 elements");
        }
        let weid = value_bytes32(&fields[0])?;
        if let Some(prev) = previous
            && prev >= weid
        {
            anyhow::bail!("epoch entries must be sorted by weid");
        }
        previous = Some(weid);
        let xk_hash = value_bytes32(&fields[1])?;
        let Value::Array(root_fields) = &fields[2] else {
            anyhow::bail!("epoch roots must be array");
        };
        if root_fields.len() != 4 {
            anyhow::bail!("epoch roots must have 4 elements");
        }
        let parent_root = value_bytes32(&root_fields[0])?;
        let is_join = match fields[3] {
            Value::Bool(flag) => flag,
            _ => anyhow::bail!("epoch entry 'is_join' must be bool"),
        };
        out.push(EpochReplayEntry {
            weid,
            xk_hash,
            parent_root,
            is_join,
        });
    }
    Ok(out)
}

fn parse_kbroad_replay(value: &Value) -> anyhow::Result<BTreeMap<[u8; 32], Vec<u8>>> {
    let Value::Array(entries) = value else {
        anyhow::bail!("kbroad_replay must be an array");
    };
    let mut map = BTreeMap::new();
    for entry in entries {
        let Value::Array(fields) = entry else {
            anyhow::bail!("kbroad entry must be array");
        };
        if fields.len() != 2 {
            anyhow::bail!("kbroad entry must have 2 elements");
        }
        let weid = value_bytes32(&fields[0])?;
        let envelope = match &fields[1] {
            Value::Bytes(bytes) => bytes.clone(),
            _ => anyhow::bail!("kbroad envelope must be bytes"),
        };
        // Basic shape check – real clients should re-run the full envelope validator.
        ensure_kbroad_shape(&envelope)?;
        map.insert(weid, envelope);
    }
    Ok(map)
}

fn ensure_kbroad_shape(bytes: &[u8]) -> anyhow::Result<()> {
    let value: Value =
        ciborium::de::from_reader(bytes).map_err(|_| anyhow::anyhow!("invalid CBOR envelope"))?;
    let Value::Array(items) = value else {
        anyhow::bail!("envelope must be array");
    };
    if items.len() != 3 {
        anyhow::bail!("envelope must have 3 elements");
    }
    if items[0] != Value::Text("barrier-sealed-v1".to_string()) {
        anyhow::bail!("unexpected barrier hp mode");
    }
    if let Value::Bytes(ciphertext) = &items[1] {
        if ciphertext.len() < 16 {
            anyhow::bail!("barrier hp ciphertext must be at least 16 bytes");
        }
    } else {
        anyhow::bail!("barrier hp ciphertext must be bytes");
    }
    if items[2] != Value::Text("chacha20-poly1305".to_string()) {
        anyhow::bail!("unexpected AEAD suite");
    }
    Ok(())
}

fn verify_commits(
    provenance_commit: &Value,
    vck_commit: &Value,
    entries: &[EpochReplayEntry],
) -> anyhow::Result<()> {
    let Value::Bytes(provenance_bytes) = provenance_commit else {
        anyhow::bail!("provenance commit must be bytes");
    };
    let Value::Bytes(vck_bytes) = vck_commit else {
        anyhow::bail!("vck commit must be bytes");
    };

    // In a real deployment each entry would pull vck/xk from the acceptance store.
    // Here we use the synthetic data baked into the sample header.
    let mut provenance_rows = Vec::with_capacity(entries.len());
    let mut vck_rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let vck = synthetic_vck_for(&entry.weid);
        provenance_rows.push(Value::Array(vec![
            Value::Bytes(entry.weid.to_vec()),
            Value::Bytes(vck.to_vec()),
            Value::Bytes(entry.xk_hash.to_vec()),
        ]));
        vck_rows.push(Value::Bytes(vck.to_vec()));
    }

    let mut prov_buf = Vec::new();
    into_writer(&Value::Array(provenance_rows), &mut prov_buf)
        .map_err(|_| anyhow::anyhow!("encode provenance"))?;
    let computed_prov = h_l("msphf/rollup/prov", &RollupCommit(&prov_buf))
        .map_err(|e| anyhow::anyhow!("hash provenance: {e:?}"))?;
    if provenance_bytes.as_slice() != computed_prov.as_slice() {
        anyhow::bail!("provenance commit mismatch");
    }

    let mut vck_buf = Vec::new();
    into_writer(&Value::Array(vck_rows), &mut vck_buf)
        .map_err(|_| anyhow::anyhow!("encode vck list"))?;
    let computed_vck = h_l("msphf/rollup/vck", &RollupCommit(&vck_buf))
        .map_err(|e| anyhow::anyhow!("hash vck: {e:?}"))?;
    if vck_bytes.as_slice() != computed_vck.as_slice() {
        anyhow::bail!("vck commit mismatch");
    }

    println!("\nCommit verification succeeded.");
    Ok(())
}

fn value_bytes32(value: &Value) -> anyhow::Result<[u8; 32]> {
    let Value::Bytes(bytes) = value else {
        anyhow::bail!("expected bytes");
    };
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn synthetic_vck_for(weid: &[u8; 32]) -> [u8; 32] {
    // Deterministic dummy data: H_L("synthetic/vck", weid)
    #[derive(Serialize)]
    struct Synthetic<'a>(#[serde(with = "serde_bytes")] &'a [u8; 32]);
    h_l("synthetic/vck", &Synthetic(weid)).unwrap_or([0u8; 32])
}

fn sample_rollup_header() -> anyhow::Result<BTreeMap<u64, Value>> {
    let mut map = BTreeMap::new();

    // Two heads: a join (0x11...) and a merge (0x22...).
    let weid_join = [0x11u8; 32];
    let weid_merge = [0x22u8; 32];
    map.insert(
        HDR_MH_HEADS,
        Value::Array(vec![
            Value::Bytes(weid_join.to_vec()),
            Value::Bytes(weid_merge.to_vec()),
        ]),
    );
    map.insert(HDR_ROLLUP_PIVOT_WEID, Value::Bytes(weid_merge.to_vec()));

    let xk_join = [0x33u8; 32];
    let xk_merge = [0x44u8; 32];
    let roots_join = vec![
        Value::Bytes([0xA0u8; 32].to_vec()),
        Value::Bytes([0xB0u8; 32].to_vec()),
        Value::Bytes([0xC0u8; 32].to_vec()),
        Value::Bytes([0xD0u8; 32].to_vec()),
    ];
    let roots_merge = vec![
        Value::Bytes([0xE0u8; 32].to_vec()),
        Value::Bytes([0xF0u8; 32].to_vec()),
        Value::Bytes([0x10u8; 32].to_vec()),
        Value::Bytes([0x20u8; 32].to_vec()),
    ];
    map.insert(
        HDR_ROLLUP_EPOCH_REPLAY,
        Value::Array(vec![
            Value::Array(vec![
                Value::Bytes(weid_join.to_vec()),
                Value::Bytes(xk_join.to_vec()),
                Value::Array(roots_join.clone()),
                Value::Bool(true),
            ]),
            Value::Array(vec![
                Value::Bytes(weid_merge.to_vec()),
                Value::Bytes(xk_merge.to_vec()),
                Value::Array(roots_merge.clone()),
                Value::Bool(false),
            ]),
        ]),
    );

    // One barrier-sealed envelope corresponding to the join epoch.
    let kbroad_envelope = Value::Array(vec![
        Value::Text("barrier-sealed-v1".to_string()),
        Value::Bytes(vec![0xCC; 80]),
        Value::Text("chacha20-poly1305".to_string()),
    ]);
    let mut envelope_buf = Vec::new();
    into_writer(&kbroad_envelope, &mut envelope_buf)
        .map_err(|_| anyhow::anyhow!("encode envelope"))?;
    map.insert(
        HDR_KBROAD_REPLAY,
        Value::Array(vec![Value::Array(vec![
            Value::Bytes(weid_join.to_vec()),
            Value::Bytes(envelope_buf),
        ])]),
    );

    // Compute synthetic provenance & VCK commits that match the replay data.
    let mut provenance_rows = Vec::new();
    let mut vck_rows = Vec::new();
    for (weid, xk) in [(&weid_join, &xk_join), (&weid_merge, &xk_merge)] {
        let vck = synthetic_vck_for(weid);
        provenance_rows.push(Value::Array(vec![
            Value::Bytes(weid.to_vec()),
            Value::Bytes(vck.to_vec()),
            Value::Bytes(xk.to_vec()),
        ]));
        vck_rows.push(Value::Bytes(vck.to_vec()));
    }
    let mut provenance_buf = Vec::new();
    into_writer(&Value::Array(provenance_rows), &mut provenance_buf)
        .map_err(|_| anyhow::anyhow!("encode provenance"))?;
    let provenance_commit = h_l("msphf/rollup/prov", &RollupCommit(&provenance_buf))
        .map_err(|e| anyhow::anyhow!("hash provenance: {e:?}"))?;
    map.insert(
        HDR_ROLLUP_PROVENANCE_COMMIT,
        Value::Bytes(provenance_commit.to_vec()),
    );

    let mut vck_buf = Vec::new();
    into_writer(&Value::Array(vck_rows), &mut vck_buf)
        .map_err(|_| anyhow::anyhow!("encode vck list"))?;
    let vck_commit = h_l("msphf/rollup/vck", &RollupCommit(&vck_buf))
        .map_err(|e| anyhow::anyhow!("hash vck: {e:?}"))?;
    map.insert(HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vck_commit.to_vec()));

    Ok(map)
}
