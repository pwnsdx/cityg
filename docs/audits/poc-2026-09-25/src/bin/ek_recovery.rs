//! Finding C-01: the server can recompute E_k from the bytes it receives on
//! `POST /v1/accept_epoch` (`ClientEpochBundle::to_cbor()`).
//!
//! Every input of the author's `seed_DRBG` is public: `rho_raw` is derived from
//! the PoP signature published in header[109], and the other inputs come from
//! the header / anchor instance. The server already derives `seed_DRBG` itself
//! in `msphf_rlwe::recompute_capss_witness` during JOIN acceptance.
use anchor_seed::{SeedCommitFields, build_anchor_seed_ctx, compute_seed_commit};
use ciborium::value::Value;
use cityg_client::{ClientEpochBundle, demo};
use msphf_core::{
    ds,
    hash::{h_l, xof32},
    instance::{AnchorInstance, epoch_key},
};
use serde::Serialize;
use std::collections::BTreeMap;

// Same preimage shapes as crates/msphf-orchestrator/src/lib.rs (derive_rho_from_pop, YStar).
#[derive(Serialize)]
struct RhoSig<'a> {
    #[serde(with = "serde_bytes")]
    pop_sig: &'a [u8],
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
}

#[derive(Serialize)]
struct YStar<'a> {
    #[serde(with = "serde_bytes")]
    r_y: &'a [u8],
    #[serde(with = "serde_bytes")]
    xk: &'a [u8],
    crs: &'a str,
    params: &'a str,
}

fn header_bytes(header: &BTreeMap<u64, Value>, key: u64) -> Result<Vec<u8>, String> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        other => Err(format!("header[{key}] is not a byte string: {other:?}")),
    }
}

fn header_text(header: &BTreeMap<u64, Value>, key: u64) -> Result<String, String> {
    match header.get(&key) {
        Some(Value::Text(text)) => Ok(text.clone()),
        other => Err(format!("header[{key}] is not a text string: {other:?}")),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for label in ["alice", "bob", "carol"] {
        // Honest author: E_k is computed locally and is never serialized.
        let authored = demo::demo_bundle(label)?;
        let author_ek = authored.epoch_key;
        let wire = authored.to_cbor()?; // exactly what accept_epoch_bundle() POSTs

        // Server side: only the received bytes.
        let rx = ClientEpochBundle::from_cbor(&wire)?;
        assert_eq!(rx.epoch_key, [0u8; 32], "E_k itself is not on the wire");
        let header = &rx.header_map;
        let pop_sig = header_bytes(header, 109)?;
        let seed_ctx_hash: [u8; 32] = header_bytes(header, 91)?
            .try_into()
            .map_err(|_| "header[91] length")?;
        let crs_id = header_text(header, 98)?;
        let params_id = header_text(header, 106)?;
        let anchor_seed_ctx = build_anchor_seed_ctx(header)?;
        assert_eq!(anchor_seed_ctx, rx.anchor.anchor_hdr_ctx);

        let instance = AnchorInstance {
            gid: &rx.anchor.gid,
            cat: &rx.anchor.cat,
            we_epoch_id: rx.we_epoch_id,
            anchor_hdr_ctx: &anchor_seed_ctx,
            tswe_salt_hash: &rx.anchor.tswe_salt_hash,
            parent_root: &rx.anchor.parent_root,
            join_delta_root: &rx.anchor.join_delta_root,
            revoked_since_prev_root: &rx.anchor.revoked_since_prev_root,
            revoked_root: &rx.anchor.revoked_root,
            pox_r_commit: rx.anchor.pox_r_commit.as_ref().map(|v| v.as_slice()),
            msphf_hp_commit: None,
        };
        let xk_hash = instance.xk_hash()?;
        let rho_raw = h_l(
            ds::MSPHF_RHO_DER,
            &RhoSig {
                pop_sig: &pop_sig,
                xk_hash: &xk_hash,
            },
        )?;
        let seed_commit = compute_seed_commit(
            &anchor_seed_ctx,
            &SeedCommitFields {
                gid: &rx.anchor.gid,
                cat: &rx.anchor.cat,
                we_epoch_id: rx.we_epoch_id,
            },
        )?;
        let seed_drbg =
            msphf_rlwe::derive_drbg_seed(&seed_commit, &rho_raw, &xk_hash, &seed_ctx_hash)?;
        let r_y = xof32("msphf/y*", &seed_drbg);
        let xk_bytes = instance.to_cbor_bytes()?;
        let y_star = h_l(
            ds::MSPHF_YSTAR,
            &YStar {
                r_y: &r_y,
                xk: &xk_bytes,
                crs: &crs_id,
                params: &params_id,
            },
        )?;
        let server_ek = epoch_key(&instance, &y_star)?;

        println!("{label:>5}: author E_k = {}", hex::encode(author_ek));
        println!(
            "{label:>5}: server E_k = {}  match={}",
            hex::encode(server_ek),
            server_ek == author_ek
        );
        println!(
            "{label:>5}: hp_a sent in clear inside capss_witness: {} bytes",
            rx.capss_witness.branch_a.branch_artifact.len()
        );
        assert_eq!(server_ek, author_ek);
    }
    println!("RESULT: E_k is computable from the accept_epoch request bytes alone.");
    Ok(())
}
