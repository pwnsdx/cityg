use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, anyhow};
use cityg_client::{
    ClientEpochBundle,
    demo::{
        DEMO_GID, bootstrap_public, demo_bundle, demo_bundle_with_parent_leaves, demo_member_leaf,
        kbroad_public,
    },
};
use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};
use msphf_orchestrator::{
    AcceptanceContext, AcceptanceOptions, AnchorAcceptanceResult, AnchorInstanceParts,
    BootstrapPolicy, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, FsJoinInputs,
    FsMergeInputs, LeafIdMode, OrchestrationParams, ReceiverCache, SrxMode,
    joiner_kgen_merge_from_acceptances, process_anchor_or,
};

fn main() -> Result<()> {
    let mut registry = BTreeMap::new();
    registry.insert(DEMO_GID.to_vec(), kbroad_public().to_vec());
    let options = AcceptanceOptions {
        bootstrap_policy: BootstrapPolicy::CaMlDsa {
            public_key: bootstrap_public().to_vec(),
        },
        kbroad_registry: Some(registry),
        ..AcceptanceOptions::default()
    };

    let mut ctx = AcceptanceContext::with_options(8, Duration::from_secs(30), options);
    let mut receiver = ReceiverCache::with_defaults();

    // Bootstrap Alice then Bob to establish baseline roster
    let alice = demo_bundle("alice")?;
    let bob = demo_bundle("bob")?;
    accept_bundle(&mut ctx, &mut receiver, &alice)?;
    accept_bundle(&mut ctx, &mut receiver, &bob)?;

    // Prepare two competing heads from the same parent set (Alice, Bob).
    let baseline: Vec<[u8; 32]> = vec![demo_member_leaf("alice"), demo_member_leaf("bob")];
    let branch0 = demo_bundle_with_parent_leaves(&baseline, demo_member_leaf("carol"))?;
    let branch1 = demo_bundle_with_parent_leaves(&baseline, demo_member_leaf("dave"))?;

    let acceptance0 = accept_bundle(&mut ctx, &mut receiver, &branch0)?;
    let acceptance1 = accept_bundle(&mut ctx, &mut receiver, &branch1)?;
    let branch_acceptances = [
        (&branch0, acceptance0.clone()),
        (&branch1, acceptance1.clone()),
    ];

    println!("Inserted two heads for the same parent root:");
    report_window(&ctx);

    // Build a merge bundle that retires both heads.
    let (pivot_bundle, _) = match branch_acceptances.iter().max_by(|(_, a), (_, b)| {
        a.outcome
            .accept_seq
            .cmp(&b.outcome.accept_seq)
            .then(a.outcome.xk_hash.cmp(&b.outcome.xk_hash))
    }) {
        Some(pb) => pb,
        None => unreachable!("pivot bundle should exist"),
    };
    let merge_header = pivot_bundle.header_map.clone();
    let anchor_parts = AnchorPartsOwned::from_bundle(pivot_bundle);
    let params = merge_params();
    let acceptances: Vec<_> = branch_acceptances
        .iter()
        .map(|(_, acc)| acc.clone())
        .collect();

    let merge_bundle = joiner_kgen_merge_from_acceptances(
        merge_header,
        &acceptances,
        Some("merge branches"),
        anchor_parts.as_parts(),
        params.clone(),
        None,
    )
    .map_err(|err| anyhow!("build merge bundle failed: {err:?}"))?;

    println!(
        "Merge retires heads: {:?}",
        merge_bundle
            .retired_heads()
            .unwrap_or_default()
            .iter()
            .map(|id| hex(id))
            .collect::<Vec<_>>()
    );

    println!(
        "After merge, retired heads would be removed once the merge is accepted by the orchestrator."
    );

    Ok(())
}

fn accept_bundle(
    ctx: &mut AcceptanceContext,
    receiver: &mut ReceiverCache,
    bundle: &ClientEpochBundle,
) -> Result<AnchorAcceptanceResult> {
    let anchor = bundle.anchor_instance();
    let binding_inputs = bundle.hp_binding_inputs();
    let witness = bundle.witness_bytes().unwrap_or(&[]);
    process_anchor_or(
        ctx,
        receiver,
        &anchor,
        &bundle.header_map,
        &bundle.hp_proof,
        &binding_inputs,
        witness,
    )
    .map_err(|err| anyhow!("accept bundle failed: {err:?}"))
}

fn merge_params() -> OrchestrationParams<'static> {
    let (vrf_secret_key, vrf_public_key) = deterministic_example_vrf_keys();
    OrchestrationParams {
        msphf_crs_id: RLWE_CRS_ID_DEFAULT,
        params_id: RLWE_PARAMS_ID_MOCK,
        srx: None,
        srx_mode: SrxMode::Complete,
        pop_keys: None,
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: DEFAULT_PROOF_MODE,
        vrf_id: DEFAULT_VRF_ID,
        policy_version: DEFAULT_POLICY_VERSION,
        vrf_secret_key: Some(vrf_secret_key),
        vrf_public_key: Some(vrf_public_key),
        fs_policy_version: "fs-merge-policy",
        fs_epoch_base_ts: 0,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs {
            fs_purge_times: Some((0, 0)),
        },
    }
}

fn deterministic_example_vrf_keys() -> (&'static [u8], &'static [u8]) {
    static VRF_KEYS: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    let pair = VRF_KEYS.get_or_init(|| {
        let params = match msphf_orchestrator::lb::generate_parameters([0u8; 32]) {
            Ok(params) => params,
            Err(_) => unreachable!("deterministic example VRF params must be derivable"),
        };
        match msphf_orchestrator::lb::generate_keypair(&params, [1u8; 32]) {
            Ok(pair) => pair,
            Err(_) => unreachable!("deterministic example VRF keypair must be derivable"),
        }
    });
    (&pair.0, &pair.1)
}

fn report_window(ctx: &AcceptanceContext) {
    for (wid, heads) in ctx.mh_window.snapshot() {
        println!("  wid {} -> {} heads", hex(&wid), heads.len());
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct AnchorPartsOwned {
    gid: Vec<u8>,
    cat: Vec<u8>,
    tswe_salt_hash: Vec<u8>,
    parent_root: [u8; 32],
    join_delta_root: [u8; 32],
    revoked_since_prev_root: [u8; 32],
    revoked_root: [u8; 32],
    pox_r_commit: Option<[u8; 32]>,
}

impl AnchorPartsOwned {
    fn from_bundle(bundle: &ClientEpochBundle) -> Self {
        Self {
            gid: bundle.anchor.gid.clone(),
            cat: bundle.anchor.cat.clone(),
            tswe_salt_hash: bundle.anchor.tswe_salt_hash.clone(),
            parent_root: bundle.anchor.parent_root,
            join_delta_root: bundle.anchor.join_delta_root,
            revoked_since_prev_root: bundle.anchor.revoked_since_prev_root,
            revoked_root: bundle.anchor.revoked_root,
            pox_r_commit: bundle.anchor.pox_r_commit,
        }
    }

    fn as_parts(&self) -> AnchorInstanceParts<'_> {
        AnchorInstanceParts {
            gid: &self.gid,
            cat: &self.cat,
            tswe_salt_hash: &self.tswe_salt_hash,
            parent_root: &self.parent_root,
            join_delta_root: &self.join_delta_root,
            revoked_since_prev_root: &self.revoked_since_prev_root,
            revoked_root: &self.revoked_root,
            pox_r_commit: self.pox_r_commit.as_ref().map(|arr| arr.as_slice()),
        }
    }
}
