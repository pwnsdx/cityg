use std::{collections::BTreeMap, fs, path::Path};

use crate::proofs::{
    capss,
    hp_binding::{HpBindingInputs, proof_to_cbor, prove_hp_k},
};
use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use msphf_core::{
    MsphfError, ds,
    hash::{eid_from_epoch, h_branch_bytes, h_l, hash_bytes_with_label, xof32},
    instance::{AnchorInstance, epoch_key},
    witness::{
        CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
        ValidatedWitness, WitnessVariants,
    },
};
use msphf_rlwe::{
    FullHashResult, derive_branch_material, hash_full as rlwe_hash_full,
    hash_proj as rlwe_hash_proj,
};
use rand::{SeedableRng, rngs::SysRng};
use serde::{Deserialize, Serialize};

use crate::{
    AnchorInstanceParts, CapssWitnessBundle, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE,
    DEFAULT_VRF_ID, FsJoinInputs, FsMergeInputs, HpArtifactOwned, OrchestrationParams,
    compute_proofs_commit_bytes, hdr,
};

pub fn generate_from_plan_file(plan_path: &Path) -> Result<KatOutput, MsphfError> {
    let data = fs::read(plan_path).map_err(MsphfError::serialization)?;
    let plan: KatPlan = serde_json::from_slice(&data).map_err(MsphfError::serialization)?;
    generate(plan)
}

pub fn generate(plan: KatPlan) -> Result<KatOutput, MsphfError> {
    let base = BaseContext::try_from_plan(&plan)?;
    let mut cases_out = Vec::new();
    for case in &plan.cases {
        cases_out.push(generate_case(&plan.params, &base, case)?);
    }
    Ok(KatOutput { cases: cases_out })
}

#[derive(Debug, Deserialize)]
pub struct KatPlan {
    pub params: PlanParams,
    #[serde(flatten)]
    pub base: PlanBase,
    pub cases: Vec<PlanCase>,
}

#[derive(Debug, Deserialize)]
pub struct PlanParams {
    pub msphf_crs_id: String,
    pub params_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PlanBase {
    pub anchor: PlanAnchor,
    #[serde(default)]
    pub header: BTreeMap<String, String>,
    pub rho: String,
    #[serde(default)]
    pub seed_drbg: Option<String>,
    #[serde(default)]
    pub witness: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PlanAnchor {
    pub gid: String,
    pub cat: String,
    pub tswe_salt_hash: String,
    pub parent_root: String,
    pub join_delta_root: String,
    pub revoked_since_prev_root: String,
    pub revoked_root: String,
    #[serde(default)]
    pub pox_r_commit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PlanCase {
    pub id: String,
    #[serde(default = "default_branch")]
    pub branch: CaseBranch,
    #[serde(default)]
    pub seed_drbg: Option<String>,
    #[serde(default)]
    pub witness_mod: Option<WitnessModification>,
    #[serde(default)]
    pub mask_mod: Option<MaskModification>,
    #[serde(default)]
    pub hp_commit_mismatch: bool,
    #[serde(default)]
    pub scenario: Option<ScenarioPlan>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ScenarioPlan {
    MhwClock {
        #[serde(default = "default_t_window_secs")]
        t_window_secs: u64,
        first_dp_ms: u64,
        second_accept_ms: u64,
        second_dp_ms: u64,
    },
    RhoReplay,
    AcceptTsLocality {
        #[serde(default = "default_t_window_secs")]
        t_window_secs: u64,
        dp_delay_ms: u64,
    },
    PathOversize,
    NonmemEmptyTree,
    NonmemBoundary {
        side: BoundarySide,
    },
    MergeDedupe,
    HeadMetaMismatch,
    AeadAadTamper,
    SrxValid,
    SrxConflictParent,
    SrxConflictRevoke,
    SrxConflictSubset,
    SrxCommitMismatch,
    MissingRevokedRoot,
    SrxNoncanonical,
    SrxNoncanonicalRightEq,
    SrxNoncanonicalIntervalOrder,
    MergeCarriesJoin,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum BoundarySide {
    Left,
    Right,
}

fn default_t_window_secs() -> u64 {
    10
}

fn default_branch() -> CaseBranch {
    CaseBranch::A
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum CaseBranch {
    A,
    B,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WitnessModification {
    RootXor { byte: usize, mask: String },
    Remove,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum MaskModification {
    Flip {
        target: MaskTarget,
        byte: usize,
        mask: String,
    },
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "UPPERCASE")]
pub enum MaskTarget {
    A,
    B,
}

#[derive(Debug)]
struct BaseContext {
    anchor: OwnedAnchor,
    header: BTreeMap<u64, Value>,
    rho: [u8; 32],
    seed_drbg: Option<[u8; 32]>,
    witness_bytes: Option<Vec<u8>>,
}

impl BaseContext {
    fn try_from_plan(plan: &KatPlan) -> Result<Self, MsphfError> {
        let rho = hex_to_array(&plan.base.rho)?;
        let header = parse_header_map(&plan.base.header)?;
        let anchor = OwnedAnchor::from_plan(&plan.base.anchor)?;
        let seed_drbg = match &plan.base.seed_drbg {
            Some(s) => Some(hex_to_array(s)?),
            None => None,
        };
        let witness_bytes = match &plan.base.witness {
            Some(hex) => Some(hex_to_vec(hex)?),
            None => None,
        };
        Ok(Self {
            anchor,
            header,
            rho,
            seed_drbg,
            witness_bytes,
        })
    }
}

#[derive(Debug)]
struct OwnedAnchor {
    gid: Vec<u8>,
    cat: Vec<u8>,
    tswe_salt_hash: Vec<u8>,
    parent_root: Vec<u8>,
    join_delta_root: Vec<u8>,
    revoked_since_prev_root: Vec<u8>,
    revoked_root: Vec<u8>,
    pox_r_commit: Option<Vec<u8>>,
}

impl OwnedAnchor {
    fn from_plan(plan: &PlanAnchor) -> Result<Self, MsphfError> {
        Ok(Self {
            gid: hex_to_vec(&plan.gid)?,
            cat: hex_to_vec(&plan.cat)?,
            tswe_salt_hash: hex_to_vec(&plan.tswe_salt_hash)?,
            parent_root: hex_to_vec(&plan.parent_root)?,
            join_delta_root: hex_to_vec(&plan.join_delta_root)?,
            revoked_since_prev_root: hex_to_vec(&plan.revoked_since_prev_root)?,
            revoked_root: hex_to_vec(&plan.revoked_root)?,
            pox_r_commit: match &plan.pox_r_commit {
                Some(hex) => Some(hex_to_vec(hex)?),
                None => None,
            },
        })
    }

    fn parts(&self) -> AnchorInstanceParts<'_> {
        AnchorInstanceParts {
            gid: &self.gid,
            cat: &self.cat,
            tswe_salt_hash: &self.tswe_salt_hash,
            parent_root: &self.parent_root,
            join_delta_root: &self.join_delta_root,
            revoked_since_prev_root: &self.revoked_since_prev_root,
            revoked_root: &self.revoked_root,
            pox_r_commit: self.pox_r_commit.as_deref(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KatOutput {
    pub cases: Vec<KatCaseOutput>,
}

#[derive(Serialize, Deserialize)]
pub struct KatCaseOutput {
    pub id: String,
    pub branch: CaseBranch,
    #[serde(flatten)]
    pub status: KatCaseStatus,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum KatCaseStatus {
    Ok(KatCaseSuccess),
    Error(KatCaseError),
    Scenario(KatCaseScenario),
}

#[derive(Serialize, Deserialize)]
pub struct KatCaseSuccess {
    pub header: BTreeMap<u64, String>,
    pub anchor_hdr_ctx: String,
    pub seed_ctx_hash: String,
    pub seed_commit: String,
    pub rho_commit: String,
    pub we_epoch_id: String,
    pub xk_hash: String,
    pub hp_commit: String,
    pub hp_k: String,
    pub hp_ciphertext: String,
    pub hp_proof: String,
    pub y_star: String,
    pub y_full: String,
    pub y_proj: String,
    pub mask: String,
    pub epoch_key: String,
    pub eid: String,
    pub witness: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KatCaseError {
    pub expected_error: String,
    pub header: BTreeMap<u64, String>,
    pub anchor_hdr_ctx: String,
    pub seed_ctx_hash: String,
    pub seed_commit: String,
    pub rho_commit: String,
    pub we_epoch_id: String,
    pub xk_hash: String,
    pub hp_commit: String,
    pub hp_k: String,
    pub hp_ciphertext_valid: String,
    pub hp_ciphertext_tampered: String,
    pub hp_proof: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KatCaseScenario {
    MhwClock {
        head: HeadSnapshot,
        t_window_ms: u64,
        receivers: Vec<MhwReceiverScenario>,
    },
    RhoReplay {
        head: HeadSnapshot,
        expected_freeze: String,
    },
    AcceptTsLocality {
        head: HeadSnapshot,
        t_window_ms: u64,
        dp_delay_ms: u64,
        expected: String,
    },
    PathOversize {
        head: HeadSnapshot,
        witness: String,
        expected_freeze: String,
    },
    NonmemEmptyTree {
        head: HeadSnapshot,
        witness: String,
        expected: String,
    },
    NonmemBoundary {
        head: HeadSnapshot,
        side: BoundarySide,
        valid_witness: String,
        invalid_witness: String,
        expected_invalid_freeze: String,
    },
    MergeDedupe {
        head: HeadSnapshot,
        header: BTreeMap<u64, String>,
        expected_freeze: String,
    },
    HeadMetaMismatch {
        head: HeadSnapshot,
        wrong_parent: String,
        expected_freeze: String,
    },
    AeadAadTamper {
        head: HeadSnapshot,
        hp_ciphertext: String,
        hp_commit: String,
        tampered_commit: String,
        expected_error: String,
    },
    Srx {
        head: HeadSnapshot,
        header: BTreeMap<u64, String>,
        payload: String,
        commit: String,
        expected: String,
    },
    HeaderMissing {
        head: HeadSnapshot,
        header: BTreeMap<u64, String>,
        expected_freeze: String,
    },
    MergeJoinKeys {
        head: HeadSnapshot,
        header: BTreeMap<u64, String>,
        expected_freeze: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct HeadSnapshot {
    pub anchor: AnchorSnapshot,
    pub header: BTreeMap<u64, String>,
    pub anchor_hdr_ctx: String,
    pub we_epoch_id: String,
    pub seed_ctx_hash: String,
    pub seed_commit: String,
    pub rho_commit: String,
    pub hp_commit: String,
    pub hp_ciphertext: String,
    pub epoch_key: String,
    pub eid: String,
}

#[derive(Serialize, Deserialize)]
pub struct AnchorSnapshot {
    pub gid: String,
    pub cat: String,
    pub tswe_salt_hash: String,
    pub parent_root: String,
    pub join_delta_root: String,
    pub revoked_since_prev_root: String,
    pub revoked_root: String,
    pub pox_r_commit: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct MhwReceiverScenario {
    pub label: String,
    pub accept_offset_ms: u64,
    pub dp_offset_ms: u64,
    pub expected: String,
}

#[allow(clippy::too_many_arguments)]
fn build_head_snapshot(
    parts: &AnchorInstanceParts<'_>,
    header_hex: BTreeMap<u64, String>,
    anchor_hdr_ctx: &[u8],
    we_epoch_id: [u8; 32],
    seed_ctx_hash: &[u8; 32],
    seed_commit: &[u8; 32],
    rho_commit: &[u8; 32],
    hp_commit: &[u8; 32],
    hp_ciphertext: &[u8],
    epoch_key: &[u8; 32],
    eid: &[u8; 32],
) -> HeadSnapshot {
    HeadSnapshot {
        anchor: anchor_to_snapshot(parts),
        header: header_hex,
        anchor_hdr_ctx: to_hex(anchor_hdr_ctx),
        we_epoch_id: to_hex(&we_epoch_id),
        seed_ctx_hash: to_hex(seed_ctx_hash),
        seed_commit: to_hex(seed_commit),
        rho_commit: to_hex(rho_commit),
        hp_commit: to_hex(hp_commit),
        hp_ciphertext: to_hex(hp_ciphertext),
        epoch_key: to_hex(epoch_key),
        eid: to_hex(eid),
    }
}

fn anchor_to_snapshot(parts: &AnchorInstanceParts<'_>) -> AnchorSnapshot {
    AnchorSnapshot {
        gid: to_hex(parts.gid),
        cat: to_hex(parts.cat),
        tswe_salt_hash: to_hex(parts.tswe_salt_hash),
        parent_root: to_hex(parts.parent_root),
        join_delta_root: to_hex(parts.join_delta_root),
        revoked_since_prev_root: to_hex(parts.revoked_since_prev_root),
        revoked_root: to_hex(parts.revoked_root),
        pox_r_commit: parts.pox_r_commit.map(to_hex),
    }
}

fn build_scenario_output(
    plan: &ScenarioPlan,
    head: HeadSnapshot,
    header_map: &BTreeMap<u64, Value>,
    anchor_instance: &AnchorInstance<'_>,
    we_epoch_id: [u8; 32],
    hp_commit: &[u8; 32],
    hp_ciphertext: &[u8],
) -> Result<KatCaseScenario, MsphfError> {
    match plan {
        ScenarioPlan::MhwClock {
            t_window_secs,
            first_dp_ms,
            second_accept_ms,
            second_dp_ms,
        } => {
            let t_window_ms = t_window_secs.saturating_mul(1000);
            let first_elapsed = *first_dp_ms;
            let second_elapsed = second_dp_ms.saturating_sub(*second_accept_ms);
            let mut receivers = Vec::new();
            receivers.push(MhwReceiverScenario {
                label: "alpha".to_string(),
                accept_offset_ms: 0,
                dp_offset_ms: *first_dp_ms,
                expected: if first_elapsed >= t_window_ms {
                    "dp_epoch_expired".to_string()
                } else {
                    "ok".to_string()
                },
            });
            receivers.push(MhwReceiverScenario {
                label: "beta".to_string(),
                accept_offset_ms: *second_accept_ms,
                dp_offset_ms: *second_dp_ms,
                expected: if second_elapsed >= t_window_ms {
                    "dp_epoch_expired".to_string()
                } else {
                    "ok".to_string()
                },
            });
            Ok(KatCaseScenario::MhwClock {
                head,
                t_window_ms,
                receivers,
            })
        }
        ScenarioPlan::RhoReplay => Ok(KatCaseScenario::RhoReplay {
            head,
            expected_freeze: "924".to_string(),
        }),
        ScenarioPlan::AcceptTsLocality {
            t_window_secs,
            dp_delay_ms,
        } => {
            let t_window_ms = t_window_secs.saturating_mul(1000);
            let expected = if *dp_delay_ms >= t_window_ms {
                "dp_epoch_expired".to_string()
            } else {
                "ok".to_string()
            };
            Ok(KatCaseScenario::AcceptTsLocality {
                head,
                t_window_ms,
                dp_delay_ms: *dp_delay_ms,
                expected,
            })
        }
        ScenarioPlan::PathOversize => {
            let witness = make_nonmem_witness(
                anchor_instance,
                [0x10; 32],
                Some([0x20; 32]),
                Some([0x30; 32]),
                65,
                0,
            )?;
            Ok(KatCaseScenario::PathOversize {
                head,
                witness: to_hex(&witness),
                expected_freeze: "907.5".to_string(),
            })
        }
        ScenarioPlan::NonmemEmptyTree => {
            let witness = make_nonmem_witness(anchor_instance, [0u8; 32], None, None, 0, 0)?;
            Ok(KatCaseScenario::NonmemEmptyTree {
                head,
                witness: to_hex(&witness),
                expected: "ok".to_string(),
            })
        }
        ScenarioPlan::NonmemBoundary { side } => {
            let (valid_witness, invalid_witness) = make_boundary_witnesses(anchor_instance, *side)?;
            Ok(KatCaseScenario::NonmemBoundary {
                head,
                side: *side,
                valid_witness: to_hex(&valid_witness),
                invalid_witness: to_hex(&invalid_witness),
                expected_invalid_freeze: "907.2".to_string(),
            })
        }
        ScenarioPlan::MergeDedupe => {
            let mut dup_header = header_map.clone();
            dup_header.insert(
                hdr::HDR_MH_HEADS,
                Value::Array(vec![
                    Value::Bytes(we_epoch_id.to_vec()),
                    Value::Bytes(we_epoch_id.to_vec()),
                ]),
            );
            let header = header_to_hex(&dup_header)?;
            Ok(KatCaseScenario::MergeDedupe {
                head,
                header,
                expected_freeze: "927".to_string(),
            })
        }
        ScenarioPlan::HeadMetaMismatch => Ok(KatCaseScenario::HeadMetaMismatch {
            head,
            wrong_parent: to_hex(&[0xFF; 32]),
            expected_freeze: "926".to_string(),
        }),
        ScenarioPlan::AeadAadTamper => {
            let mut tampered = hp_commit.to_vec();
            if let Some(first) = tampered.first_mut() {
                *first ^= 0x01;
            }
            Ok(KatCaseScenario::AeadAadTamper {
                head,
                hp_ciphertext: to_hex(hp_ciphertext),
                hp_commit: to_hex(hp_commit),
                tampered_commit: to_hex(&tampered),
                expected_error: "msphf_hp_ciphertext tag mismatch".to_string(),
            })
        }
        ScenarioPlan::SrxValid => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "ok".to_string(),
            })
        }
        ScenarioPlan::SrxConflictParent => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let mut payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            if let Some(byte) = payload
                .join_parent
                .first_mut()
                .and_then(|first| first.root.get_mut(0))
            {
                *byte ^= 0xFF;
            }
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "set_conflict_parent".to_string(),
            })
        }
        ScenarioPlan::SrxConflictRevoke => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let mut payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            if let Some(byte) = payload
                .join_revoked
                .first_mut()
                .and_then(|first| first.root.get_mut(1))
            {
                *byte ^= 0xEE;
            }
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "set_conflict_revoke".to_string(),
            })
        }
        ScenarioPlan::SrxConflictSubset => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let mut payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            if let Some(byte) = payload
                .revoked_subset
                .first_mut()
                .and_then(|first| first.root.get_mut(2))
            {
                *byte ^= 0x55;
            }
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "set_conflict_subset".to_string(),
            })
        }
        ScenarioPlan::SrxCommitMismatch => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            let (payload_bytes, mut commit) = attach_srx_to_header(&mut header, &payload)?;
            commit[0] ^= 0xAA;
            header.insert(121, Value::Bytes(commit.to_vec()));
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "srx_invalid".to_string(),
            })
        }
        ScenarioPlan::MissingRevokedRoot => {
            let mut header = header_map.clone();
            header.remove(&113);
            Ok(KatCaseScenario::HeaderMissing {
                head,
                header: header_to_hex(&header)?,
                expected_freeze: "srx_required".to_string(),
            })
        }
        ScenarioPlan::SrxNoncanonical => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let mut payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            if let Some(first) = payload.join_parent.first_mut() {
                first.left = None;
                first.right = None;
            }
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "nonmem_noncanonical".to_string(),
            })
        }
        ScenarioPlan::SrxNoncanonicalRightEq => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let mut payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            if let Some(first) = payload.join_parent.first_mut() {
                first.right = Some(first.query.clone());
            }
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "nonmem_noncanonical".to_string(),
            })
        }
        ScenarioPlan::SrxNoncanonicalIntervalOrder => {
            let parent_root = slice_to_array(anchor_instance.parent_root)?;
            let since_root = slice_to_array(anchor_instance.revoked_since_prev_root)?;
            let revoked_root = slice_to_array(anchor_instance.revoked_root)?;
            let mut header = header_map.clone();
            let mut payload = build_srx_payload(&parent_root, &since_root, &revoked_root);
            if let Some(first) = payload.join_parent.first_mut() {
                first.left = Some(vec![0xF0; 32]);
                first.right = Some(vec![0x10; 32]);
            }
            let (payload_bytes, commit) = attach_srx_to_header(&mut header, &payload)?;
            refresh_seed_ctx(&mut header)?;
            Ok(KatCaseScenario::Srx {
                head,
                header: header_to_hex(&header)?,
                payload: to_hex(&payload_bytes),
                commit: to_hex(&commit),
                expected: "nonmem_noncanonical".to_string(),
            })
        }
        ScenarioPlan::MergeCarriesJoin => {
            let mut header = header_map.clone();
            header.insert(
                hdr::HDR_MH_HEADS,
                Value::Array(vec![Value::Bytes(we_epoch_id.to_vec())]),
            );
            Ok(KatCaseScenario::MergeJoinKeys {
                head,
                header: header_to_hex(&header)?,
                expected_freeze: "921".to_string(),
            })
        }
    }
}

fn make_boundary_witnesses(
    anchor: &AnchorInstance<'_>,
    side: BoundarySide,
) -> Result<(Vec<u8>, Vec<u8>), MsphfError> {
    let (valid_left, valid_right, valid_query, invalid_query, invalid_left, invalid_right) =
        match side {
            BoundarySide::Left => (
                None,
                Some([0x11; 32]),
                [0x01; 32],
                [0x11; 32],
                None,
                Some([0x11; 32]),
            ),
            BoundarySide::Right => (
                Some([0xEE; 32]),
                None,
                [0xF0; 32],
                [0xEE; 32],
                Some([0xEE; 32]),
                None,
            ),
        };
    let valid = make_nonmem_witness(anchor, valid_query, valid_left, valid_right, 0, 0)?;
    let invalid = make_nonmem_witness(anchor, invalid_query, invalid_left, invalid_right, 0, 0)?;
    Ok((valid, invalid))
}

fn make_nonmem_witness(
    anchor: &AnchorInstance<'_>,
    query: [u8; 32],
    left: Option<[u8; 32]>,
    right: Option<[u8; 32]>,
    path_len: usize,
    dir: u8,
) -> Result<Vec<u8>, MsphfError> {
    let membership = RawMembershipWitness {
        leaf_id: anchor.join_delta_root.to_vec(),
        root: anchor.join_delta_root.to_vec(),
        path: Vec::new(),
    };
    let mut path = Vec::with_capacity(path_len);
    for i in 0..path_len {
        path.push(RawPathEntry {
            sibling: vec![(i & 0xFF) as u8; 32],
            dir,
        });
    }
    let nonmembership = RawNonMembershipWitness {
        query: query.to_vec(),
        root: anchor.revoked_root.to_vec(),
        left: left.map(|arr| arr.to_vec()),
        right: right.map(|arr| arr.to_vec()),
        path,
        left_below: Vec::new(),
        right_below: Vec::new(),
        above: Vec::new(),
        nmint: None,
        lca_left_height: None,
        lca_right_height: None,
    };
    let witness = CanonicalWitness {
        inner: WitnessVariants::B {
            witness: membership,
            nonmem: Some(nonmembership),
            pop: None,
        },
    };
    encode_witness(&witness)
}

fn encode_witness(witness: &CanonicalWitness) -> Result<Vec<u8>, MsphfError> {
    let mut buf = Vec::new();
    into_writer(witness, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}

struct SrxPayload {
    join_parent: Vec<RawNonMembershipWitness>,
    join_revoked: Vec<RawNonMembershipWitness>,
    revoked_subset: Vec<RawMembershipWitness>,
}

fn build_srx_payload(
    parent_root: &[u8; 32],
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
) -> SrxPayload {
    let join_left = [0x10; 32];
    let join_right = [0x30; 32];
    let join_query = [0x20; 32];
    let revoked_left = [0x40; 32];
    let revoked_right = [0x60; 32];
    let revoked_query = [0x50; 32];

    SrxPayload {
        join_parent: vec![RawNonMembershipWitness {
            query: join_query.to_vec(),
            root: parent_root.to_vec(),
            left: Some(join_left.to_vec()),
            right: Some(join_right.to_vec()),
            path: vec![],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        }],
        join_revoked: vec![RawNonMembershipWitness {
            query: revoked_query.to_vec(),
            root: revoked_since_root.to_vec(),
            left: Some(revoked_left.to_vec()),
            right: Some(revoked_right.to_vec()),
            path: vec![],
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        }],
        revoked_subset: vec![RawMembershipWitness {
            leaf_id: revoked_root.to_vec(),
            root: revoked_root.to_vec(),
            path: vec![],
        }],
    }
}

fn payload_to_bytes(payload: &SrxPayload) -> Result<Vec<u8>, MsphfError> {
    let mut payload_bytes = Vec::new();
    into_writer(
        &(
            &payload.join_parent,
            &payload.join_revoked,
            &payload.revoked_subset,
        ),
        &mut payload_bytes,
    )
    .map_err(MsphfError::serialization)?;
    Ok(payload_bytes)
}

#[derive(Serialize)]
struct Commit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

fn compute_srx_commit(bytes: &[u8]) -> Result<[u8; 32], MsphfError> {
    h_l(ds::MSPHF_SRX_COMMIT, &Commit(bytes))
}

fn attach_srx_to_header(
    header: &mut BTreeMap<u64, Value>,
    payload: &SrxPayload,
) -> Result<(Vec<u8>, [u8; 32]), MsphfError> {
    let bytes = payload_to_bytes(payload)?;
    let commit = compute_srx_commit(&bytes)?;
    header.insert(120, Value::Text("srx/v1".to_string()));
    header.insert(121, Value::Bytes(commit.to_vec()));
    header.insert(122, Value::Bytes(bytes.clone()));
    Ok((bytes, commit))
}

fn refresh_seed_ctx(header: &mut BTreeMap<u64, Value>) -> Result<(), MsphfError> {
    let ctx = build_anchor_seed_ctx(header)?;
    let hash = compute_seed_ctx_hash(&ctx)?;
    header.insert(91, Value::Bytes(hash.to_vec()));
    Ok(())
}

fn slice_to_array(slice: &[u8]) -> Result<[u8; 32], MsphfError> {
    <[u8; 32]>::try_from(slice).map_err(|_| MsphfError::invalid_input("root must be 32 bytes"))
}

fn generate_case(
    params: &PlanParams,
    base: &BaseContext,
    case: &PlanCase,
) -> Result<KatCaseOutput, MsphfError> {
    let mut header_map = base.header.clone();
    let rho_commit = hash_bytes_with_label(ds::MSPHF_KGEN_RHO, &base.rho)?;
    header_map.insert(93, Value::Bytes(rho_commit.to_vec()));

    let parts = base.anchor.parts();
    let anchor_seed_ctx = build_anchor_seed_ctx(&header_map)?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx)?;
    header_map.insert(91, Value::Bytes(seed_ctx_hash.to_vec()));
    let we_epoch_id = super::derive_we_epoch_id(parts.gid, parts.parent_root, &seed_ctx_hash)?;
    let seed_commit = compute_seed_commit(
        &anchor_seed_ctx,
        &SeedCommitFields {
            gid: parts.gid,
            cat: parts.cat,
            we_epoch_id,
        },
    )?;
    let parent_root_arr = slice_to_array(parts.parent_root)?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &anchor_seed_ctx,
        &rho_commit,
        parts.gid,
        parts.cat,
        &parent_root_arr,
    )?;
    let anchor_hdr_ctx = anchor_seed_ctx.clone();

    let mut anchor_instance = AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id,
        anchor_hdr_ctx: &anchor_hdr_ctx,
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: None,
    };

    let xk_hash = anchor_instance.xk_hash()?;

    let seed_drbg = match (case.seed_drbg.as_ref(), base.seed_drbg) {
        (Some(hex), _) => hex_to_array(hex)?,
        (None, Some(arr)) => arr,
        (None, None) => compute_seed_drbg(&seed_commit, &base.rho, &xk_hash, &seed_ctx_hash)?,
    };

    let seed_a = derive_branch_seed(&seed_drbg, ds::MSPHF_KGEN_A)?;
    let seed_b = derive_branch_seed(&seed_drbg, ds::MSPHF_KGEN_B)?;

    let (sk_a, _) = derive_branch_material(&seed_a, "branch-a")?;
    let (sk_b, _) = derive_branch_material(&seed_b, "branch-b")?;

    let params_obj = OrchestrationParams {
        msphf_crs_id: &params.msphf_crs_id,
        params_id: &params.params_id,
        srx: None,
        srx_mode: crate::SrxMode::Complete,
        pop_keys: None,
        leaf_id_mode: crate::LeafIdMode::PerGroup,
        proof_mode: DEFAULT_PROOF_MODE,
        vrf_id: DEFAULT_VRF_ID,
        policy_version: DEFAULT_POLICY_VERSION,
        vrf_secret_key: {
            #[cfg(feature = "zkvrf-pq")]
            {
                Some(crate::proofs::zk_vrf::lb::deterministic_key_material().0)
            }
            #[cfg(not(feature = "zkvrf-pq"))]
            {
                None
            }
        },
        vrf_public_key: {
            #[cfg(feature = "zkvrf-pq")]
            {
                Some(crate::proofs::zk_vrf::lb::deterministic_key_material().1)
            }
            #[cfg(not(feature = "zkvrf-pq"))]
            {
                None
            }
        },
        fs_policy_version: "7",
        fs_epoch_base_ts: 0,
        barrier_version: 0,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs::default(),
    };

    let full_a = rlwe_hash_full(
        &sk_a,
        "A",
        params_obj.msphf_crs_id,
        params_obj.params_id,
        &anchor_instance,
        &xk_hash,
    )?;
    let full_b = rlwe_hash_full(
        &sk_b,
        "B",
        params_obj.msphf_crs_id,
        params_obj.params_id,
        &anchor_instance,
        &xk_hash,
    )?;

    let hp_a_bytes = full_a.projective.hp_bytes().to_vec();
    let hp_b_bytes = full_b.projective.hp_bytes().to_vec();

    let r_y = xof32("msphf/y*", &seed_drbg);
    let xk_cbor = anchor_instance.to_cbor_bytes()?;
    let y_star = h_l(
        ds::MSPHF_YSTAR,
        &YStar {
            r_y: &r_y,
            xk: &xk_cbor,
            crs: params_obj.msphf_crs_id,
            params: params_obj.params_id,
        },
    )?;

    let mask_a_material = h_branch_bytes(
        ds::MSPHF_MASK,
        "A",
        params_obj.msphf_crs_id,
        params_obj.params_id,
        &[full_a.y_full.as_ref()],
    )?;
    let mask_b_material = h_branch_bytes(
        ds::MSPHF_MASK,
        "B",
        params_obj.msphf_crs_id,
        params_obj.params_id,
        &[full_b.y_full.as_ref()],
    )?;

    let mut m_a = xor_arrays(&y_star, &mask_a_material);
    let mut m_b = xor_arrays(&y_star, &mask_b_material);

    if let Some(mask_mod) = &case.mask_mod {
        apply_mask_mod(mask_mod, &mut m_a, &mut m_b)?;
    }

    let hp_artifact = HpArtifactOwned {
        hp_a: hp_a_bytes,
        hp_b: hp_b_bytes,
        m_a: m_a.to_vec(),
        m_b: m_b.to_vec(),
        params_id: params_obj.params_id.to_string(),
        hp_version: 1,
    };

    let mut hp_k = Vec::new();
    into_writer(&hp_artifact, &mut hp_k).map_err(MsphfError::serialization)?;

    let hp_commit = hash_bytes_with_label(ds::MSPHF_HP_COMMIT, &hp_k)?;
    anchor_instance.msphf_hp_commit = Some(&hp_commit);

    let super::BarrierHpEnvelopeWire {
        envelope: kbroad_envelope,
        c_hp: hp_ciphertext,
        k_hp: _hp_aead_key,
    } = super::build_local_barrier_hp_envelope(&hp_k, &xk_hash, &hp_commit)?;
    header_map.insert(97, kbroad_envelope);

    let proof_inputs = HpBindingInputs {
        msphf_crs_id: params_obj.msphf_crs_id,
        params_id: params_obj.params_id,
        seed_ctx_hash: &seed_ctx_hash,
        seed_commit: &seed_commit,
        rho_commit: &rho_commit,
        xk_hash: &xk_hash,
        hp_commit: &hp_commit,
    };

    let hp_proof = prove_hp_k(&proof_inputs)?;
    let hp_proof_bytes = proof_to_cbor(&hp_proof)?;

    header_map.insert(99, Value::Bytes(hp_commit.to_vec()));
    let fs_dev_commit = [0u8; 32];
    header_map.insert(
        hdr::HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(
            params_obj
                .fs_policy_version
                .parse::<u64>()
                .map_err(|_| MsphfError::invalid_input("fs_policy_version must be uint"))?,
        )),
    );
    header_map.insert(
        hdr::HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(params_obj.fs_epoch_base_ts)),
    );
    header_map.insert(
        hdr::HDR_FS_EC,
        Value::Integer(Integer::from(params_obj.fs_join.fs_ec)),
    );
    header_map.insert(
        hdr::HDR_FS_EPOCH_COMMIT,
        Value::Bytes(params_obj.fs_join.fs_epoch_commit.to_vec()),
    );
    header_map.insert(
        hdr::HDR_FS_DEV_PREV_COMMIT,
        Value::Bytes(params_obj.fs_join.fs_dev_prev_commit.to_vec()),
    );
    header_map.insert(hdr::HDR_FS_DEV_COMMIT, Value::Bytes(fs_dev_commit.to_vec()));

    let _capss_bundle = CapssWitnessBundle {
        branch_a: full_a.capss_witness.clone(),
        branch_b: full_b.capss_witness.clone(),
    };

    let mut vrf_pi_bytes = Vec::with_capacity(64);
    vrf_pi_bytes.extend_from_slice(&y_star);
    vrf_pi_bytes.extend_from_slice(&seed_drbg);
    let fs_capss_inputs = capss::Inputs {
        seed_commit: &seed_commit,
        seed_bundle_commit: &seed_bundle_commit,
        rho_commit: &rho_commit,
        hp_commit: &hp_commit,
        bind: capss::BindingInputs {
            xk_hash: &xk_hash,
            crs_id: params_obj.msphf_crs_id,
            params_id: params_obj.params_id,
            proof_mode: params_obj.proof_mode,
            fs_policy_version: params_obj
                .fs_policy_version
                .parse::<u64>()
                .map_err(|_| MsphfError::invalid_input("fs_policy_version must be uint"))?,
            vrf_id: params_obj.vrf_id,
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            fs_epoch_commit: &params_obj.fs_join.fs_epoch_commit,
            fs_ec: params_obj.fs_join.fs_ec,
            fs_dev_prev_commit: &params_obj.fs_join.fs_dev_prev_commit,
            fs_dev_commit: &fs_dev_commit,
        },
    };
    let mut fs_rng =
        rand::rngs::StdRng::try_from_rng(&mut SysRng).map_err(MsphfError::serialization)?;
    let fs_capss_proof = capss::prove(&mut fs_rng, &fs_capss_inputs)?;
    let fs_capss_bytes = fs_capss_proof.as_bytes().to_vec();
    let srx_root_sw_bytes = header_map
        .get(&hdr::HDR_SRX_ROOT_SW)
        .and_then(|value| match value {
            Value::Bytes(bytes) if bytes.len() == 32 => Some(bytes.clone()),
            _ => None,
        });
    let srx_smallwood_bytes =
        header_map
            .get(&hdr::HDR_SRX_SMALLWOOD)
            .and_then(|value| match value {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            });
    let proofs_commit = compute_proofs_commit_bytes(
        &vrf_pi_bytes,
        &fs_capss_bytes,
        srx_root_sw_bytes.as_deref(),
        srx_smallwood_bytes.as_deref(),
    )?;
    header_map.insert(hdr::HDR_FS_CAPSS, Value::Bytes(fs_capss_bytes.clone()));
    header_map.insert(95, Value::Bytes(vrf_pi_bytes.clone()));
    header_map.insert(119, Value::Text(DEFAULT_PROOF_MODE.to_string()));
    header_map.insert(116, Value::Text(DEFAULT_VRF_ID.to_string()));
    header_map.insert(125, Value::Bytes(proofs_commit.to_vec()));

    let witness_bytes = base.witness_bytes.clone();
    let (validated_witness, witness_hex) =
        prepare_witness(witness_bytes, &anchor_instance, case.witness_mod.as_ref())?;

    let projective_params = match case.branch {
        CaseBranch::A => &full_a.projective,
        CaseBranch::B => &full_b.projective,
    };
    let y_proj = rlwe_hash_proj(
        projective_params,
        match case.branch {
            CaseBranch::A => "A",
            CaseBranch::B => "B",
        },
        params_obj.msphf_crs_id,
        params_obj.params_id,
        &anchor_instance,
        validated_witness.as_ref(),
    )?;

    let mask = match case.branch {
        CaseBranch::A => m_a,
        CaseBranch::B => m_b,
    };

    let epoch_key = epoch_key(&anchor_instance, &y_star)?;
    let eid = eid_from_epoch(&epoch_key)?;

    let header_hex = header_to_hex(&header_map)?;
    let anchor_hdr_hex = to_hex(&anchor_hdr_ctx);
    let weid_hex = to_hex(&we_epoch_id);

    if let Some(scenario_plan) = &case.scenario {
        let head_snapshot = build_head_snapshot(
            &parts,
            header_hex.clone(),
            &anchor_hdr_ctx,
            we_epoch_id,
            &seed_ctx_hash,
            &seed_commit,
            &rho_commit,
            &hp_commit,
            &hp_ciphertext,
            &epoch_key,
            &eid,
        );
        let scenario_output = build_scenario_output(
            scenario_plan,
            head_snapshot,
            &header_map,
            &anchor_instance,
            we_epoch_id,
            &hp_commit,
            &hp_ciphertext,
        )?;
        return Ok(KatCaseOutput {
            id: case.id.clone(),
            branch: case.branch,
            status: KatCaseStatus::Scenario(scenario_output),
        });
    }

    if case.hp_commit_mismatch {
        let mut tampered = hp_ciphertext.clone();
        if let Some(first) = tampered.first_mut() {
            *first ^= 0x01;
        }
        return Ok(KatCaseOutput {
            id: case.id.clone(),
            branch: case.branch,
            status: KatCaseStatus::Error(KatCaseError {
                expected_error: "msphf_hp_commit mismatch".to_string(),
                header: header_hex,
                anchor_hdr_ctx: anchor_hdr_hex,
                seed_ctx_hash: to_hex(&seed_ctx_hash),
                seed_commit: to_hex(&seed_commit),
                rho_commit: to_hex(&rho_commit),
                we_epoch_id: weid_hex.clone(),
                xk_hash: to_hex(&xk_hash),
                hp_commit: to_hex(&hp_commit),
                hp_k: to_hex(&hp_k),
                hp_ciphertext_valid: to_hex(&hp_ciphertext),
                hp_ciphertext_tampered: to_hex(&tampered),
                hp_proof: to_hex(&hp_proof_bytes),
            }),
        });
    }

    Ok(KatCaseOutput {
        id: case.id.clone(),
        branch: case.branch,
        status: KatCaseStatus::Ok(KatCaseSuccess {
            header: header_hex,
            anchor_hdr_ctx: anchor_hdr_hex,
            seed_ctx_hash: to_hex(&seed_ctx_hash),
            seed_commit: to_hex(&seed_commit),
            rho_commit: to_hex(&rho_commit),
            we_epoch_id: weid_hex.clone(),
            xk_hash: to_hex(&xk_hash),
            hp_commit: to_hex(&hp_commit),
            hp_k: to_hex(&hp_k),
            hp_ciphertext: to_hex(&hp_ciphertext),
            hp_proof: to_hex(&hp_proof_bytes),
            y_star: to_hex(&y_star),
            y_full: to_hex(&full_y(case.branch, &full_a, &full_b)),
            y_proj: to_hex(&y_proj),
            mask: to_hex(&mask),
            epoch_key: to_hex(&epoch_key),
            eid: to_hex(&eid),
            witness: witness_hex,
        }),
    })
}

fn full_y(branch: CaseBranch, a: &FullHashResult, b: &FullHashResult) -> [u8; 32] {
    match branch {
        CaseBranch::A => a.y_full,
        CaseBranch::B => b.y_full,
    }
}

fn prepare_witness(
    bytes: Option<Vec<u8>>,
    anchor: &AnchorInstance<'_>,
    modification: Option<&WitnessModification>,
) -> Result<(Option<ValidatedWitness>, Option<String>), MsphfError> {
    let Some(raw) = bytes else {
        return Ok((None, None));
    };
    if matches!(modification, Some(WitnessModification::Remove)) {
        return Ok((None, Some(to_hex(&raw))));
    }
    let canonical: CanonicalWitness =
        from_reader(raw.as_slice()).map_err(MsphfError::serialization)?;
    let mut validated = canonical.validate_against(anchor)?;
    if let Some(WitnessModification::RootXor { byte, mask }) = modification {
        let mask_byte = parse_mask_byte(mask)?;
        if let Some(value) = validated.membership.root.get_mut(*byte) {
            *value ^= mask_byte;
        }
    }
    Ok((Some(validated), Some(to_hex(&raw))))
}

fn apply_mask_mod(
    modif: &MaskModification,
    m_a: &mut [u8; 32],
    m_b: &mut [u8; 32],
) -> Result<(), MsphfError> {
    match modif {
        MaskModification::Flip { target, byte, mask } => {
            let mask_byte = parse_mask_byte(mask)?;
            let target_slice = match target {
                MaskTarget::A => m_a,
                MaskTarget::B => m_b,
            };
            if let Some(value) = target_slice.get_mut(*byte) {
                *value ^= mask_byte;
            }
        }
    }
    Ok(())
}

fn parse_mask_byte(hex: &str) -> Result<u8, MsphfError> {
    let bytes = hex_to_vec(hex)?;
    if bytes.len() != 1 {
        return Err(MsphfError::invalid_input("mask must be single byte"));
    }
    Ok(bytes[0])
}

fn xor_arrays(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn derive_branch_seed(seed_drbg: &[u8; 32], label: &str) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct SeedRef<'a>(#[serde(with = "serde_bytes")] &'a [u8; 32]);
    h_l(label, &SeedRef(seed_drbg))
}

fn compute_seed_drbg(
    seed_commit: &[u8; 32],
    rho: &[u8; 32],
    xk_hash: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Drbg<'a> {
        #[serde(with = "serde_bytes")]
        seed_commit: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        rho: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        xk_hash: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        seed_ctx_hash: &'a [u8; 32],
    }

    h_l(
        ds::MSPHF_DRBG,
        &Drbg {
            seed_commit,
            rho,
            xk_hash,
            seed_ctx_hash,
        },
    )
}

#[derive(Serialize)]
struct YStar<'a> {
    #[serde(with = "serde_bytes")]
    r_y: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    xk: &'a [u8],
    crs: &'a str,
    params: &'a str,
}

fn parse_header_map(input: &BTreeMap<String, String>) -> Result<BTreeMap<u64, Value>, MsphfError> {
    let mut out = BTreeMap::new();
    for (k, v) in input {
        let key = k.parse::<u64>().map_err(MsphfError::serialization)?;
        out.insert(key, Value::Bytes(hex_to_vec(v)?));
    }
    Ok(out)
}

fn hex_to_vec(hex: &str) -> Result<Vec<u8>, MsphfError> {
    let clean = hex.trim();
    hex::decode(clean).map_err(|e| MsphfError::invalid_input(format!("invalid hex: {e}")))
}

fn hex_to_array<const N: usize>(hex: &str) -> Result<[u8; N], MsphfError> {
    let vec = hex_to_vec(hex)?;
    if vec.len() != N {
        return Err(MsphfError::invalid_input(format!("expected {N} bytes")));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&vec);
    Ok(arr)
}

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn header_to_hex(map: &BTreeMap<u64, Value>) -> Result<BTreeMap<u64, String>, MsphfError> {
    let mut out = BTreeMap::new();
    for (key, value) in map {
        let bytes = match value {
            Value::Bytes(data) => data.clone(),
            other => {
                let mut buf = Vec::new();
                into_writer(other, &mut buf).map_err(MsphfError::serialization)?;
                buf
            }
        };
        out.insert(*key, to_hex(&bytes));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kbroad_test_keys;
    use anyhow::{Context, Result, anyhow, ensure};
    use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_A1};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs};

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn basic_plan(seed_override: Option<String>) -> KatPlan {
        let (kbroad_pub, _) = kbroad_test_keys();
        let mut header = BTreeMap::new();
        header.insert("104".to_string(), hex::encode(b"ml-kem-768"));
        header.insert("105".to_string(), hex::encode(kbroad_pub));

        KatPlan {
            params: PlanParams {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT.to_string(),
                params_id: RLWE_PARAMS_ID_A1.to_string(),
            },
            base: PlanBase {
                anchor: PlanAnchor {
                    gid: hex32(0x01),
                    cat: hex32(0x02),
                    tswe_salt_hash: hex32(0x03),
                    parent_root: hex32(0x04),
                    join_delta_root: hex32(0x05),
                    revoked_since_prev_root: hex32(0x06),
                    revoked_root: hex32(0x07),
                    pox_r_commit: None,
                },
                header,
                rho: hex32(0x08),
                seed_drbg: seed_override,
                witness: None,
            },
            cases: vec![PlanCase {
                id: "case-ok".to_string(),
                branch: CaseBranch::A,
                seed_drbg: None,
                witness_mod: None,
                mask_mod: None,
                hp_commit_mismatch: false,
                scenario: None,
            }],
        }
    }

    #[test]
    fn generate_plan_produces_success_case() -> Result<()> {
        let plan = basic_plan(None);
        let output = generate(plan)?;
        assert_eq!(output.cases.len(), 1);
        let case = &output.cases[0];
        assert_eq!(case.id, "case-ok");
        ensure!(matches!(case.branch, CaseBranch::A), "expected branch A");

        let KatCaseStatus::Ok(success) = &case.status else {
            return Err(anyhow!("unexpected case status (expected Ok)"));
        };

        assert_eq!(success.we_epoch_id.len(), 64);
        assert!(!success.hp_commit.is_empty());
        assert!(success.witness.is_none());
        Ok(())
    }

    #[test]
    fn generate_from_plan_file_roundtrip() -> Result<()> {
        let plan = basic_plan(Some(hex32(0x09)));
        let seed_drbg = plan
            .base
            .seed_drbg
            .clone()
            .ok_or_else(|| anyhow!("basic_plan should supply seed_drbg"))?;
        let json_plan = json!({
            "params": {
                "msphf_crs_id": plan.params.msphf_crs_id,
                "params_id": plan.params.params_id,
            },
            "anchor": {
                "gid": plan.base.anchor.gid,
                "cat": plan.base.anchor.cat,
                "tswe_salt_hash": plan.base.anchor.tswe_salt_hash,
                "parent_root": plan.base.anchor.parent_root,
                "join_delta_root": plan.base.anchor.join_delta_root,
                "revoked_since_prev_root": plan.base.anchor.revoked_since_prev_root,
                "revoked_root": plan.base.anchor.revoked_root,
            },
            "header": plan.base.header,
            "rho": plan.base.rho,
            "seed_drbg": seed_drbg,
            "cases": [{
                "id": plan.cases[0].id,
                "branch": "A"
            }],
        });

        let temp_path = {
            let epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before the UNIX epoch")?
                .as_millis();
            env::temp_dir().join(format!("kat_plan_{epoch}.json"))
        };
        let json_bytes = serde_json::to_vec(&json_plan)?;
        fs::write(&temp_path, json_bytes)?;
        let output = generate_from_plan_file(&temp_path)?;
        fs::remove_file(&temp_path).context("remove temporary KAT plan")?;

        assert_eq!(output.cases.len(), 1);
        assert_eq!(output.cases[0].id, "case-ok");
        Ok(())
    }

    #[test]
    fn generate_plan_reports_hp_commit_mismatch() -> Result<()> {
        let mut plan = basic_plan(None);
        plan.cases[0].hp_commit_mismatch = true;
        let output = generate(plan)?;
        let status = &output.cases[0].status;
        let KatCaseStatus::Error(err) = status else {
            return Err(anyhow!("expected hp_commit mismatch error"));
        };
        ensure!(
            err.expected_error == "msphf_hp_commit mismatch",
            "unexpected error message: {}",
            err.expected_error
        );
        Ok(())
    }

    #[test]
    fn generate_plan_rho_replay_scenario() -> Result<()> {
        let mut plan = basic_plan(None);
        plan.cases[0].scenario = Some(ScenarioPlan::RhoReplay);
        let output = generate(plan)?;
        let status = &output.cases[0].status;
        let KatCaseStatus::Scenario(KatCaseScenario::RhoReplay {
            expected_freeze, ..
        }) = status
        else {
            return Err(anyhow!("expected rho replay scenario"));
        };
        assert_eq!(expected_freeze, "924");
        Ok(())
    }

    type ScenarioFixture = (
        OwnedAnchor,
        BTreeMap<u64, Value>,
        HeadSnapshot,
        [u8; 32],
        [u8; 32],
        Vec<u8>,
    );

    fn scenario_fixture() -> Result<ScenarioFixture> {
        let plan = basic_plan(None);
        let base = BaseContext::try_from_plan(&plan)?;
        let BaseContext {
            anchor,
            header,
            rho: _,
            seed_drbg: _,
            witness_bytes: _,
        } = base;
        let parts = anchor.parts();

        let we_epoch_id = [0x11; 32];
        let seed_ctx_hash = [0x22; 32];
        let seed_commit = [0x33; 32];
        let rho_commit = [0x44; 32];
        let hp_commit = [0x55; 32];
        let hp_ciphertext = vec![0x66; 48];
        let epoch_key = [0x77; 32];
        let eid = [0x88; 32];
        let anchor_hdr_ctx = [0xAB, 0xCD];

        let head = build_head_snapshot(
            &parts,
            header_to_hex(&header)?,
            &anchor_hdr_ctx,
            we_epoch_id,
            &seed_ctx_hash,
            &seed_commit,
            &rho_commit,
            &hp_commit,
            &hp_ciphertext,
            &epoch_key,
            &eid,
        );
        Ok((anchor, header, head, we_epoch_id, hp_commit, hp_ciphertext))
    }

    fn anchor_instance_from_owned<'a>(
        anchor: &'a OwnedAnchor,
        we_epoch_id: [u8; 32],
        hp_commit: Option<&'a [u8]>,
    ) -> AnchorInstance<'a> {
        let parts = anchor.parts();
        AnchorInstance {
            gid: parts.gid,
            cat: parts.cat,
            we_epoch_id,
            anchor_hdr_ctx: b"kat-test-ctx",
            tswe_salt_hash: parts.tswe_salt_hash,
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            pox_r_commit: parts.pox_r_commit,
            msphf_hp_commit: hp_commit,
        }
    }

    #[test]
    fn serde_defaults_apply_for_case_branch_and_window() -> Result<()> {
        let case: PlanCase = serde_json::from_value(json!({
            "id": "defaulted"
        }))?;
        ensure!(
            matches!(case.branch, CaseBranch::A),
            "default branch must be A"
        );

        let scenario: ScenarioPlan = serde_json::from_value(json!({
            "kind": "mhw-clock",
            "first_dp_ms": 1,
            "second_accept_ms": 2,
            "second_dp_ms": 3
        }))?;
        let ScenarioPlan::MhwClock { t_window_secs, .. } = scenario else {
            return Err(anyhow!("expected mhw-clock scenario"));
        };
        assert_eq!(t_window_secs, 10);
        Ok(())
    }

    #[test]
    fn base_context_rejects_invalid_hex_inputs() {
        let mut plan = basic_plan(None);
        plan.base.rho = "not-hex".to_string();
        assert!(BaseContext::try_from_plan(&plan).is_err());

        let mut plan = basic_plan(None);
        plan.base.anchor.parent_root = "not-hex".to_string();
        assert!(BaseContext::try_from_plan(&plan).is_err());
    }

    #[test]
    fn generate_from_plan_file_reports_io_and_parse_errors() {
        let missing = env::temp_dir().join("does-not-exist-kat-plan.json");
        assert!(generate_from_plan_file(&missing).is_err());

        let temp_path = env::temp_dir().join(format!(
            "kat_plan_invalid_{}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before UNIX epoch")
                .as_millis()
        ));
        fs::write(&temp_path, b"{invalid-json").expect("write invalid json");
        let result = generate_from_plan_file(&temp_path);
        let _ = fs::remove_file(&temp_path);
        assert!(result.is_err());
    }

    #[test]
    fn helper_parsers_cover_error_paths() {
        assert!(hex_to_vec("zz").is_err());
        assert!(hex_to_array::<32>("abcd").is_err());
        assert!(parse_mask_byte("0001").is_err());
        assert!(slice_to_array(&[0u8; 31]).is_err());

        let mut header = BTreeMap::new();
        header.insert("bad".to_string(), "aa".to_string());
        assert!(parse_header_map(&header).is_err());

        let mut header = BTreeMap::new();
        header.insert("91".to_string(), "zz".to_string());
        assert!(parse_header_map(&header).is_err());
    }

    #[test]
    fn header_to_hex_serializes_non_bytes_values() -> Result<()> {
        let mut header = BTreeMap::new();
        header.insert(1, Value::Bytes(vec![0xAA]));
        header.insert(2, Value::Text("hello".to_string()));
        let encoded = header_to_hex(&header)?;
        assert_eq!(encoded.get(&1), Some(&"aa".to_string()));
        let text_bytes = hex::decode(encoded.get(&2).context("missing key 2")?)?;
        assert!(!text_bytes.is_empty());
        Ok(())
    }

    #[test]
    fn scenario_output_covers_clock_and_locality_variants() -> Result<()> {
        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::MhwClock {
                    t_window_secs: 1,
                    first_dp_ms: 100,
                    second_accept_ms: 100,
                    second_dp_ms: 500,
                },
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::MhwClock { receivers, .. } = scenario else {
                return Err(anyhow!("expected mhw-clock scenario output"));
            };
            assert_eq!(receivers[0].expected, "ok");
            assert_eq!(receivers[1].expected, "ok");
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::MhwClock {
                    t_window_secs: 1,
                    first_dp_ms: 1000,
                    second_accept_ms: 100,
                    second_dp_ms: 1200,
                },
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::MhwClock { receivers, .. } = scenario else {
                return Err(anyhow!("expected mhw-clock scenario output"));
            };
            assert_eq!(receivers[0].expected, "dp_epoch_expired");
            assert_eq!(receivers[1].expected, "dp_epoch_expired");
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::AcceptTsLocality {
                    t_window_secs: 1,
                    dp_delay_ms: 999,
                },
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::AcceptTsLocality { expected, .. } = scenario else {
                return Err(anyhow!("expected accept-ts-locality scenario output"));
            };
            assert_eq!(expected, "ok");
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::AcceptTsLocality {
                    t_window_secs: 1,
                    dp_delay_ms: 1000,
                },
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::AcceptTsLocality { expected, .. } = scenario else {
                return Err(anyhow!("expected accept-ts-locality scenario output"));
            };
            assert_eq!(expected, "dp_epoch_expired");
        }

        Ok(())
    }

    #[test]
    fn scenario_output_covers_nonmembership_and_merge_variants() -> Result<()> {
        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::PathOversize,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::PathOversize {
                witness,
                expected_freeze,
                ..
            } = scenario
            else {
                return Err(anyhow!("expected path-oversize scenario output"));
            };
            assert!(!witness.is_empty());
            assert_eq!(expected_freeze, "907.5");
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::NonmemEmptyTree,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::NonmemEmptyTree {
                witness, expected, ..
            } = scenario
            else {
                return Err(anyhow!("expected nonmem-empty-tree scenario output"));
            };
            assert!(!witness.is_empty());
            assert_eq!(expected, "ok");
        }

        for side in [BoundarySide::Left, BoundarySide::Right] {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::NonmemBoundary { side },
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::NonmemBoundary {
                side: got_side,
                valid_witness,
                invalid_witness,
                expected_invalid_freeze,
                ..
            } = scenario
            else {
                return Err(anyhow!("expected nonmem-boundary scenario output"));
            };
            assert_eq!(got_side as u8, side as u8);
            assert!(!valid_witness.is_empty());
            assert!(!invalid_witness.is_empty());
            assert_eq!(expected_invalid_freeze, "907.2");
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::MergeDedupe,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::MergeDedupe {
                expected_freeze,
                header,
                ..
            } = scenario
            else {
                return Err(anyhow!("expected merge-dedupe scenario output"));
            };
            assert_eq!(expected_freeze, "927");
            assert!(header.contains_key(&hdr::HDR_MH_HEADS));
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::HeadMetaMismatch,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::HeadMetaMismatch {
                expected_freeze,
                wrong_parent,
                ..
            } = scenario
            else {
                return Err(anyhow!("expected head-meta-mismatch scenario output"));
            };
            assert_eq!(expected_freeze, "926");
            assert_eq!(wrong_parent, hex::encode([0xFF; 32]));
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::AeadAadTamper,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::AeadAadTamper {
                expected_error,
                hp_commit: commit,
                tampered_commit,
                ..
            } = scenario
            else {
                return Err(anyhow!("expected aead-aad-tamper scenario output"));
            };
            assert!(expected_error.contains("tag mismatch"));
            assert_ne!(commit, tampered_commit);
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::MissingRevokedRoot,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::HeaderMissing {
                expected_freeze, ..
            } = scenario
            else {
                return Err(anyhow!("expected header-missing scenario output"));
            };
            assert_eq!(expected_freeze, "srx_required");
        }

        {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &ScenarioPlan::MergeCarriesJoin,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::MergeJoinKeys {
                expected_freeze, ..
            } = scenario
            else {
                return Err(anyhow!("expected merge-carries-join scenario output"));
            };
            assert_eq!(expected_freeze, "921");
        }

        Ok(())
    }

    #[test]
    fn scenario_output_covers_srx_variants() -> Result<()> {
        let expectations = vec![
            (ScenarioPlan::SrxValid, "ok"),
            (ScenarioPlan::SrxConflictParent, "set_conflict_parent"),
            (ScenarioPlan::SrxConflictRevoke, "set_conflict_revoke"),
            (ScenarioPlan::SrxConflictSubset, "set_conflict_subset"),
            (ScenarioPlan::SrxCommitMismatch, "srx_invalid"),
            (ScenarioPlan::SrxNoncanonical, "nonmem_noncanonical"),
            (ScenarioPlan::SrxNoncanonicalRightEq, "nonmem_noncanonical"),
            (
                ScenarioPlan::SrxNoncanonicalIntervalOrder,
                "nonmem_noncanonical",
            ),
        ];

        for (plan, expected_status) in expectations {
            let (anchor, header_map, head, we_epoch_id, hp_commit, hp_ciphertext) =
                scenario_fixture()?;
            let anchor_instance =
                anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));
            let scenario = build_scenario_output(
                &plan,
                head,
                &header_map,
                &anchor_instance,
                we_epoch_id,
                &hp_commit,
                &hp_ciphertext,
            )?;
            let KatCaseScenario::Srx {
                expected,
                payload,
                commit,
                ..
            } = scenario
            else {
                return Err(anyhow!("expected srx scenario output"));
            };
            assert_eq!(expected, expected_status);
            assert!(!payload.is_empty());
            assert_eq!(commit.len(), 64);
        }
        Ok(())
    }

    #[test]
    fn witness_and_mask_helpers_cover_success_and_errors() -> Result<()> {
        let (anchor, _header_map, _head, we_epoch_id, hp_commit, _hp_ciphertext) =
            scenario_fixture()?;
        let anchor_instance =
            anchor_instance_from_owned(&anchor, we_epoch_id, Some(hp_commit.as_slice()));

        let (validated, witness_hex) = prepare_witness(None, &anchor_instance, None)?;
        assert!(validated.is_none());
        assert!(witness_hex.is_none());

        let witness = CanonicalWitness {
            inner: WitnessVariants::B {
                witness: RawMembershipWitness {
                    leaf_id: anchor_instance.join_delta_root.to_vec(),
                    root: anchor_instance.join_delta_root.to_vec(),
                    path: Vec::new(),
                },
                nonmem: None,
                pop: None,
            },
        };
        let witness_bytes = encode_witness(&witness)?;
        let (removed, removed_hex) = prepare_witness(
            Some(witness_bytes.clone()),
            &anchor_instance,
            Some(&WitnessModification::Remove),
        )?;
        assert!(removed.is_none());
        assert_eq!(removed_hex, Some(hex::encode(&witness_bytes)));

        let (mutated, _) = prepare_witness(
            Some(witness_bytes),
            &anchor_instance,
            Some(&WitnessModification::RootXor {
                byte: 0,
                mask: "01".to_string(),
            }),
        )?;
        let mutated = mutated.context("missing mutated witness")?;
        assert_eq!(
            mutated.membership.root[0],
            anchor_instance.join_delta_root[0] ^ 0x01
        );

        assert!(prepare_witness(Some(vec![0xFF, 0x00, 0xAA]), &anchor_instance, None).is_err());

        let mut m_a = [0u8; 32];
        let mut m_b = [0u8; 32];
        apply_mask_mod(
            &MaskModification::Flip {
                target: MaskTarget::A,
                byte: 0,
                mask: "ff".to_string(),
            },
            &mut m_a,
            &mut m_b,
        )?;
        assert_eq!(m_a[0], 0xFF);
        assert_eq!(m_b[0], 0x00);

        apply_mask_mod(
            &MaskModification::Flip {
                target: MaskTarget::B,
                byte: 1,
                mask: "01".to_string(),
            },
            &mut m_a,
            &mut m_b,
        )?;
        assert_eq!(m_b[1], 0x01);

        apply_mask_mod(
            &MaskModification::Flip {
                target: MaskTarget::B,
                byte: 99,
                mask: "01".to_string(),
            },
            &mut m_a,
            &mut m_b,
        )?;
        assert_eq!(m_b[1], 0x01);
        assert!(
            apply_mask_mod(
                &MaskModification::Flip {
                    target: MaskTarget::A,
                    byte: 0,
                    mask: "0011".to_string(),
                },
                &mut m_a,
                &mut m_b,
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn srx_helpers_and_seed_derivations_are_deterministic() -> Result<()> {
        let parent = [0x11; 32];
        let since = [0x22; 32];
        let revoked = [0x33; 32];
        let payload = build_srx_payload(&parent, &since, &revoked);
        let bytes = payload_to_bytes(&payload)?;
        let commit = compute_srx_commit(&bytes)?;
        assert_ne!(commit, [0u8; 32]);

        let mut header = BTreeMap::new();
        header.insert(104, Value::Bytes(b"ml-kem-768".to_vec()));
        header.insert(105, Value::Bytes(vec![0x44; 32]));
        let (_, attached_commit) = attach_srx_to_header(&mut header, &payload)?;
        assert_eq!(attached_commit, compute_srx_commit(&bytes)?);
        refresh_seed_ctx(&mut header)?;
        assert!(header.contains_key(&91));

        let seed_commit = [0xAA; 32];
        let rho = [0xBB; 32];
        let xk_hash = [0xCC; 32];
        let seed_ctx_hash = [0xDD; 32];
        let seed_drbg_1 = compute_seed_drbg(&seed_commit, &rho, &xk_hash, &seed_ctx_hash)?;
        let seed_drbg_2 = compute_seed_drbg(&seed_commit, &rho, &xk_hash, &seed_ctx_hash)?;
        assert_eq!(seed_drbg_1, seed_drbg_2);

        let branch_a_1 = derive_branch_seed(&seed_drbg_1, ds::MSPHF_KGEN_A)?;
        let branch_a_2 = derive_branch_seed(&seed_drbg_1, ds::MSPHF_KGEN_A)?;
        let branch_b = derive_branch_seed(&seed_drbg_1, ds::MSPHF_KGEN_B)?;
        assert_eq!(branch_a_1, branch_a_2);
        assert_ne!(branch_a_1, branch_b);

        let xored = xor_arrays(&parent, &revoked);
        assert_eq!(xored[0], parent[0] ^ revoked[0]);
        Ok(())
    }
}
