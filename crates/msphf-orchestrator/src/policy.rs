use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ciborium::ser::into_writer;
use hex::FromHexError;
use pqcrypto_dilithium::dilithium5::{
    DetachedSignature as MlDsaDetachedSignature, PublicKey as MlDsaPublicKey,
    public_key_bytes as ml_dsa_public_key_bytes, signature_bytes as ml_dsa_signature_bytes,
    verify_detached_signature as verify_ml_dsa,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    DEFAULT_POLICY_VERSION, LeafIdMode,
    accept::{AcceptanceContext, FsPolicyConfig},
    mhw::DEFAULT_H_MAX,
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy journal parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("policy journal is empty")]
    EmptyJournal,
    #[error("unsupported signature algorithm {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("unauthorized signer")]
    UnauthorizedSigner,
    #[error("invalid policy signature")]
    InvalidSignature,
    #[error("policy version {current} precedes or equals previous {previous}")]
    NonMonotonicVersion { previous: String, current: String },
    #[error("invalid leaf_id_mode {0}")]
    InvalidLeafIdMode(String),
    #[error("invalid base64 data")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid hex data")]
    InvalidHex(#[from] FromHexError),
    #[error("policy journal serialization error")]
    Serialization,
    #[error("H_max must be greater than zero")]
    InvalidHMax,
    #[error("policy_journal_root must be 32-byte hex")]
    InvalidPolicyJournalRoot,
    #[error("fs policy window incompatible")]
    FsPolicyWindowIncompatible,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyTrustAnchors {
    ml_dsa_public_keys: BTreeSet<Vec<u8>>,
}

impl PolicyTrustAnchors {
    pub fn from_ml_dsa_keys<I, B>(keys: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let set = keys
            .into_iter()
            .map(|k| k.as_ref().to_vec())
            .collect::<BTreeSet<_>>();
        Self {
            ml_dsa_public_keys: set,
        }
    }

    fn contains_ml_dsa(&self, key: &[u8]) -> bool {
        self.ml_dsa_public_keys.contains(key)
    }
}

#[derive(Debug, Clone)]
pub struct PolicyVersion {
    raw: String,
    timestamp: Option<OffsetDateTime>,
}

impl PolicyVersion {
    fn parse(raw: String) -> Result<Self, PolicyError> {
        if raw == DEFAULT_POLICY_VERSION {
            return Ok(Self {
                raw,
                timestamp: None,
            });
        }
        let ts = OffsetDateTime::parse(&raw, &Rfc3339).ok();
        Ok(Self { raw, timestamp: ts })
    }

    fn is_after(&self, previous: &PolicyVersion) -> bool {
        match (&self.timestamp, &previous.timestamp) {
            (Some(cur), Some(prev)) => cur > prev,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => self.raw > previous.raw,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyAllowList {
    pub msphf_crs_id: Option<BTreeSet<String>>,
    pub params_id: Option<BTreeSet<Vec<u8>>>,
    pub meor_vrf_id: Option<BTreeSet<String>>,
    pub proof_modes: Option<BTreeSet<String>>,
    pub srx_modes: Option<BTreeSet<String>>,
}

#[derive(Debug, Clone)]
pub struct PolicyDocument {
    pub version: PolicyVersion,
    pub allow: PolicyAllowList,
    pub kbroad_registry: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    pub leaf_id_mode: LeafIdMode,
    pub proof_mode: String,
    pub policy_journal_root: Option<[u8; 32]>,
    pub h_max: usize,
    pub fs_policy: FsPolicyConfig,
    pub fs_policy_version: String,
    pub fs_base_ts: u64,
}

impl PolicyDocument {
    pub fn apply_to_context(&self, ctx: &mut AcceptanceContext) -> Result<(), PolicyError> {
        match &self.allow.msphf_crs_id {
            Some(list) => ctx.set_allowed_crs_ids(Some(list.clone())),
            None => ctx.set_allowed_crs_ids(None),
        }
        match &self.allow.params_id {
            Some(list) => ctx.set_allowed_params_ids(Some(list.clone())),
            None => ctx.set_allowed_params_ids(None),
        }
        match &self.allow.meor_vrf_id {
            Some(list) => ctx.set_allowed_vrf_ids(Some(list.clone())),
            None => ctx.set_allowed_vrf_ids(None),
        }
        let proof_modes = match &self.allow.proof_modes {
            Some(list) => list.clone(),
            None => {
                let mut single = BTreeSet::new();
                single.insert(self.proof_mode.clone());
                single
            }
        };
        ctx.set_allowed_proof_modes(Some(proof_modes));
        match &self.allow.srx_modes {
            Some(list) => ctx.set_allowed_srx_modes(Some(list.clone())),
            None => ctx.set_allowed_srx_modes(None),
        }
        ctx.set_leaf_id_mode(self.leaf_id_mode);
        ctx.set_h_max(self.h_max);
        match &self.kbroad_registry {
            Some(map) => ctx.set_kbroad_registry(Some(map.clone())),
            None => ctx.set_kbroad_registry(None),
        }
        ctx.set_policy_state(self.version.raw.clone(), self.version.timestamp);
        ctx.invalidate_policy_caches();
        ctx.set_allowed_fs_policy_version(Some(self.fs_policy_version.clone()));
        ctx.set_fs_policy_version(Some(self.fs_policy_version.clone()));
        let fs_config = self.fs_policy.clone();
        ctx.apply_fs_policy_config(fs_config)
            .map_err(|_| PolicyError::FsPolicyWindowIncompatible)?;
        ctx.set_fs_base_ts(Some(self.fs_base_ts));
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PolicyJournalFile {
    entries: Vec<PolicyJournalEntrySer>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PolicyJournalEntrySer {
    policy: PolicyPayloadSer,
    signatures: Vec<PolicySignatureSer>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PolicyPayloadSer {
    policy_version: String,
    allow: Option<PolicyAllowSer>,
    kbroad_registry: Option<KbroadRegistrySer>,
    leaf_id_mode: Option<String>,
    proof_mode: Option<String>,
    policy_journal_root: Option<String>,
    #[serde(rename = "H_max")]
    h_max: Option<usize>,
    #[serde(rename = "H")]
    fs_h: Option<u64>,
    #[serde(rename = "checkpoint_interval")]
    fs_checkpoint_interval: Option<u64>,
    #[serde(rename = "checkpoint_head_threshold")]
    fs_checkpoint_head_threshold: Option<u64>,
    #[serde(rename = "S_anchor")]
    fs_slack_anchor: Option<u64>,
    #[serde(rename = "S_first")]
    fs_slack_first: Option<u64>,
    #[serde(rename = "S_device")]
    fs_slack_device: Option<u64>,
    #[serde(rename = "fs_policy_version")]
    fs_policy_version: Option<String>,
    #[serde(rename = "T_base")]
    fs_base_ts: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct PolicyAllowSer {
    #[serde(default)]
    msphf_crs_id: Vec<String>,
    #[serde(default)]
    params_id: Vec<String>,
    #[serde(default)]
    meor_vrf_id: Vec<String>,
    #[serde(default)]
    proof_mode: Vec<String>,
    #[serde(default)]
    srx_modes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KbroadRegistrySer {
    per_gid: bool,
    keys: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PolicySignatureSer {
    algorithm: String,
    public_key: String,
    signature: String,
}

pub fn load_policy_journal_from_reader<R: Read>(
    reader: R,
    anchors: &PolicyTrustAnchors,
) -> Result<PolicyDocument, PolicyError> {
    let file: PolicyJournalFile = serde_json::from_reader(reader)?;
    if file.entries.is_empty() {
        return Err(PolicyError::EmptyJournal);
    }

    let mut previous_version: Option<PolicyVersion> = None;
    let mut latest_document: Option<PolicyDocument> = None;

    for entry in file.entries {
        let payload = entry.policy;
        let message = serialize_payload(&payload)?;
        if !verify_signatures(&message, &entry.signatures, anchors)? {
            return Err(PolicyError::UnauthorizedSigner);
        }

        let version = PolicyVersion::parse(payload.policy_version.clone())?;
        if let Some(prev) = previous_version
            .as_ref()
            .filter(|prev| !version.is_after(prev))
        {
            return Err(PolicyError::NonMonotonicVersion {
                previous: prev.raw.clone(),
                current: version.raw.clone(),
            });
        }

        let document = payload.into_document(version)?;
        previous_version = Some(document.version.clone());
        latest_document = Some(document);
    }

    Ok(latest_document.expect("checked non-empty"))
}

fn serialize_payload(payload: &PolicyPayloadSer) -> Result<Vec<u8>, PolicyError> {
    let mut buffer = Vec::new();
    into_writer(payload, &mut buffer).map_err(|_| PolicyError::Serialization)?;
    Ok(buffer)
}

fn verify_signatures(
    message: &[u8],
    signatures: &[PolicySignatureSer],
    anchors: &PolicyTrustAnchors,
) -> Result<bool, PolicyError> {
    let mut recognized = false;
    for signature in signatures {
        if signature.verify(message, anchors)? {
            recognized = true;
        }
    }
    Ok(recognized)
}

impl PolicySignatureSer {
    fn verify(&self, message: &[u8], anchors: &PolicyTrustAnchors) -> Result<bool, PolicyError> {
        match self.algorithm.as_str() {
            "ml-dsa-65" | "ML-DSA-65" => self.verify_ml_dsa(message, anchors),
            other => Err(PolicyError::UnsupportedSignatureAlgorithm(
                other.to_string(),
            )),
        }
    }

    fn verify_ml_dsa(
        &self,
        message: &[u8],
        anchors: &PolicyTrustAnchors,
    ) -> Result<bool, PolicyError> {
        let public_key = BASE64.decode(self.public_key.as_bytes())?;
        let signature = BASE64.decode(self.signature.as_bytes())?;

        if public_key.len() != ml_dsa_public_key_bytes()
            || signature.len() != ml_dsa_signature_bytes()
        {
            return Err(PolicyError::InvalidSignature);
        }
        if !anchors.contains_ml_dsa(&public_key) {
            return Ok(false);
        }
        let pk =
            MlDsaPublicKey::from_bytes(&public_key).map_err(|_| PolicyError::InvalidSignature)?;
        let sig = MlDsaDetachedSignature::from_bytes(&signature)
            .map_err(|_| PolicyError::InvalidSignature)?;
        verify_ml_dsa(&sig, message, &pk).map_err(|_| PolicyError::InvalidSignature)?;
        Ok(true)
    }
}

impl PolicyPayloadSer {
    fn into_document(self, version: PolicyVersion) -> Result<PolicyDocument, PolicyError> {
        let allow_ser = self.allow.unwrap_or_default();
        let allow = PolicyAllowList {
            msphf_crs_id: if allow_ser.msphf_crs_id.is_empty() {
                None
            } else {
                Some(allow_ser.msphf_crs_id.into_iter().collect())
            },
            params_id: if allow_ser.params_id.is_empty() {
                None
            } else {
                let mut set = BTreeSet::new();
                for hex_value in allow_ser.params_id {
                    set.insert(hex::decode(hex_value)?);
                }
                Some(set)
            },
            meor_vrf_id: if allow_ser.meor_vrf_id.is_empty() {
                None
            } else {
                Some(allow_ser.meor_vrf_id.into_iter().collect())
            },
            proof_modes: if allow_ser.proof_mode.is_empty() {
                None
            } else {
                Some(allow_ser.proof_mode.into_iter().collect())
            },
            srx_modes: if allow_ser.srx_modes.is_empty() {
                None
            } else {
                Some(allow_ser.srx_modes.into_iter().collect())
            },
        };

        let kbroad_registry = match self.kbroad_registry {
            Some(registry) if registry.per_gid => {
                let mut map = BTreeMap::new();
                for (gid_hex, key_b64) in registry.keys {
                    let gid = hex::decode(gid_hex)?;
                    let value = BASE64.decode(key_b64.as_bytes())?;
                    map.insert(gid, value);
                }
                Some(map)
            }
            _ => None,
        };

        let leaf_id_mode = match self.leaf_id_mode.as_deref() {
            Some("per-group") | Some("per_group") | None => LeafIdMode::PerGroup,
            Some("global") => LeafIdMode::Global,
            Some(other) => return Err(PolicyError::InvalidLeafIdMode(other.to_string())),
        };

        let proof_mode = self.proof_mode.unwrap_or_else(|| "lin+zkvrf".to_string());

        let policy_journal_root = match self.policy_journal_root {
            Some(root_hex) => {
                let bytes = hex::decode(root_hex)?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    return Err(PolicyError::InvalidPolicyJournalRoot);
                }
            }
            None => None,
        };

        let h_max = self.h_max.unwrap_or(DEFAULT_H_MAX);
        if h_max == 0 {
            return Err(PolicyError::InvalidHMax);
        }

        let mut fs_policy = FsPolicyConfig::default();
        if let Some(h) = self.fs_h {
            fs_policy.h_seconds = h;
        }
        if let Some(interval) = self.fs_checkpoint_interval {
            fs_policy.checkpoint_interval_seconds = interval;
        }
        if let Some(threshold) = self.fs_checkpoint_head_threshold {
            fs_policy.checkpoint_head_threshold = threshold;
        }
        if let Some(slack) = self.fs_slack_anchor {
            fs_policy.slack_anchor = slack;
        }
        if let Some(slack) = self.fs_slack_first {
            fs_policy.slack_first_device = slack;
        }
        if let Some(slack) = self.fs_slack_device {
            fs_policy.slack_device = slack;
        }
        // Validate synthesized caps early so invalid policy is rejected during loading.
        fs_policy
            .synthesize_caps()
            .map_err(|_| PolicyError::FsPolicyWindowIncompatible)?;

        let fs_policy_version = self
            .fs_policy_version
            .clone()
            .unwrap_or_else(|| version.raw.clone());
        let fs_base_ts = self.fs_base_ts.unwrap_or(0);

        Ok(PolicyDocument {
            version,
            allow,
            kbroad_registry,
            leaf_id_mode,
            proof_mode,
            policy_journal_root,
            h_max,
            fs_policy,
            fs_policy_version,
            fs_base_ts,
        })
    }
}

pub fn load_policy_journal_from_bytes(
    bytes: &[u8],
    anchors: &PolicyTrustAnchors,
) -> Result<PolicyDocument, PolicyError> {
    load_policy_journal_from_reader(bytes, anchors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use pqcrypto_dilithium::dilithium5::{SecretKey as MlDsaSecretKey, keypair};
    use time::Month;

    fn make_payload(version: &str, params_hex: &str) -> PolicyPayloadSer {
        PolicyPayloadSer {
            policy_version: version.to_string(),
            allow: Some(PolicyAllowSer {
                msphf_crs_id: vec!["rlwe-merkle/v1".to_string()],
                params_id: vec![params_hex.to_string()],
                meor_vrf_id: vec!["lb-vrf/v1".to_string()],
                proof_mode: vec!["lin+zkvrf".to_string()],
                srx_modes: vec!["srx/v1-complete".to_string()],
            }),
            kbroad_registry: None,
            leaf_id_mode: Some("per-group".to_string()),
            proof_mode: Some("lin+zkvrf".to_string()),
            policy_journal_root: None,
            h_max: Some(32),
            fs_h: None,
            fs_checkpoint_interval: None,
            fs_checkpoint_head_threshold: None,
            fs_slack_anchor: None,
            fs_slack_first: None,
            fs_slack_device: None,
            fs_policy_version: None,
            fs_base_ts: None,
        }
    }

    fn policy_file(
        payloads: Vec<PolicyPayloadSer>,
        signatures: Vec<Vec<PolicySignatureSer>>,
    ) -> PolicyJournalFile {
        let entries = payloads
            .into_iter()
            .zip(signatures)
            .map(|(policy, signatures)| PolicyJournalEntrySer { policy, signatures })
            .collect();
        PolicyJournalFile { entries }
    }

    fn payload_with_registry(version: &str) -> PolicyPayloadSer {
        let mut payload = make_payload(version, "74657374");
        payload.kbroad_registry = Some(KbroadRegistrySer {
            per_gid: true,
            keys: BTreeMap::from([("aabbcc".to_string(), BASE64.encode(b"registry-key"))]),
        });
        payload.leaf_id_mode = Some("global".to_string());
        payload.h_max = Some(8);
        payload
    }

    fn sign_payload(
        payload: &PolicyPayloadSer,
        pk: &MlDsaPublicKey,
        sk: &MlDsaSecretKey,
    ) -> PolicySignatureSer {
        let message = serialize_payload(payload).expect("serialize");
        let signature = pqcrypto_dilithium::dilithium5::detached_sign(&message, sk);
        PolicySignatureSer {
            algorithm: "ml-dsa-65".to_string(),
            public_key: BASE64.encode(pk.as_bytes()),
            signature: BASE64.encode(signature.as_bytes()),
        }
    }

    #[test]
    fn journal_applies_latest_entry() -> Result<()> {
        let mut payload1 = make_payload("2025-09-01T00:00:00Z", "74657374");
        payload1.h_max = Some(16);
        let (pk, sk) = keypair();
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let sig1 = sign_payload(&payload1, &pk, &sk);

        let payload2 = make_payload("2025-10-01T00:00:00Z", "7465737432");
        let sig2 = sign_payload(&payload2, &pk, &sk);
        let message = PolicyJournalFile {
            entries: vec![
                PolicyJournalEntrySer {
                    policy: payload1,
                    signatures: vec![sig1.clone()],
                },
                PolicyJournalEntrySer {
                    policy: payload2.clone(),
                    signatures: vec![sig2],
                },
            ],
        };
        let json = serde_json::to_vec(&message)?;
        let document = load_policy_journal_from_bytes(&json, &anchors).context("load document")?;
        assert_eq!(document.version.raw, "2025-10-01T00:00:00Z");
        assert_eq!(document.h_max, 32);
        let params = document
            .allow
            .params_id
            .as_ref()
            .context("params_id missing")?;
        let first = params.first().context("params list empty")?;
        let expected = hex::decode("7465737432")?;
        assert_eq!(first, &expected);
        Ok(())
    }

    #[test]
    fn refuses_non_monotonic_version() -> Result<()> {
        let payload1 = make_payload("2025-09-01T00:00:00Z", "74657374");
        let payload2 = make_payload("2025-09-01T00:00:00Z", "74657375");
        let (pk, sk) = keypair();
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let sig1 = sign_payload(&payload1, &pk, &sk);
        let sig2 = sign_payload(&payload2, &pk, &sk);
        let file = PolicyJournalFile {
            entries: vec![
                PolicyJournalEntrySer {
                    policy: payload1,
                    signatures: vec![sig1],
                },
                PolicyJournalEntrySer {
                    policy: payload2,
                    signatures: vec![sig2],
                },
            ],
        };
        let json = serde_json::to_vec(&file)?;
        let err =
            load_policy_journal_from_bytes(&json, &anchors).expect_err("non monotonic version");
        assert!(matches!(err, PolicyError::NonMonotonicVersion { .. }));
        Ok(())
    }

    #[test]
    fn applying_policy_updates_context() -> Result<()> {
        let payload = make_payload("2025-11-01T00:00:00Z", "74657374");
        let (pk, sk) = keypair();
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let signature = sign_payload(&payload, &pk, &sk);
        let file = PolicyJournalFile {
            entries: vec![PolicyJournalEntrySer {
                policy: payload,
                signatures: vec![signature],
            }],
        };
        let json = serde_json::to_vec(&file)?;
        let document = load_policy_journal_from_bytes(&json, &anchors).context("load document")?;

        let mut ctx = AcceptanceContext::with_defaults();
        document
            .apply_to_context(&mut ctx)
            .context("policy apply failed")?;
        assert_eq!(ctx.policy_version(), "2025-11-01T00:00:00Z");
        let timestamp = ctx.policy_timestamp().context("timestamp missing")?;
        ensure!(timestamp.year() == 2025);
        ensure!(timestamp.month() == Month::November);
        Ok(())
    }

    #[test]
    fn journal_rejects_unauthorized_signer() -> Result<()> {
        let payload = make_payload("2025-12-01T00:00:00Z", "74657374");
        let (authorized_pk, _) = keypair();
        let (unauth_pk, unauth_sk) = keypair();
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([authorized_pk.as_bytes().to_vec()]);
        let unauthorized_sig = sign_payload(&payload, &unauth_pk, &unauth_sk);
        let file = PolicyJournalFile {
            entries: vec![PolicyJournalEntrySer {
                policy: payload,
                signatures: vec![unauthorized_sig],
            }],
        };
        let json = serde_json::to_vec(&file)?;
        let err = load_policy_journal_from_bytes(&json, &anchors).expect_err("unauthorized signer");
        assert!(matches!(err, PolicyError::UnauthorizedSigner));
        Ok(())
    }

    #[test]
    fn kbroad_registry_and_leaf_mode_applied() -> Result<()> {
        let payload = payload_with_registry("2025-12-15T00:00:00Z");
        let (pk, sk) = keypair();
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let signature = sign_payload(&payload, &pk, &sk);
        let file = PolicyJournalFile {
            entries: vec![PolicyJournalEntrySer {
                policy: payload,
                signatures: vec![signature],
            }],
        };
        let json = serde_json::to_vec(&file)?;
        let document = load_policy_journal_from_bytes(&json, &anchors).context("load document")?;

        let mut ctx = AcceptanceContext::with_defaults();
        document
            .apply_to_context(&mut ctx)
            .context("policy apply failed")?;

        assert_eq!(ctx.leaf_id_mode(), LeafIdMode::Global);
        assert_eq!(ctx.h_max(), 8);
        let registry = ctx.kbroad_registry().context("registry missing")?;
        assert_eq!(registry.len(), 1);
        let key = hex::decode("aabbcc")?;
        let stored = registry.get(&key).context("gid entry")?;
        assert_eq!(stored, b"registry-key");
        Ok(())
    }

    #[test]
    fn rejects_zero_h_max() -> Result<()> {
        let mut payload = make_payload("2025-08-01T00:00:00Z", "01");
        payload.h_max = Some(0);
        let (pk, sk) = keypair();
        let sig = sign_payload(&payload, &pk, &sk);
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let file = policy_file(vec![payload], vec![vec![sig]]);
        let json = serde_json::to_vec(&file)?;
        let err =
            load_policy_journal_from_bytes(&json, &anchors).expect_err("invalid h_max allowed");
        assert!(matches!(err, PolicyError::InvalidHMax));
        Ok(())
    }

    #[test]
    fn rejects_unknown_leaf_id_mode() -> Result<()> {
        let mut payload = make_payload("2025-08-15T00:00:00Z", "02");
        payload.leaf_id_mode = Some("invalid-mode".to_string());
        let (pk, sk) = keypair();
        let sig = sign_payload(&payload, &pk, &sk);
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let file = policy_file(vec![payload], vec![vec![sig]]);
        let json = serde_json::to_vec(&file)?;
        let err = load_policy_journal_from_bytes(&json, &anchors).expect_err("invalid leaf mode");
        assert!(matches!(err, PolicyError::InvalidLeafIdMode(_)));
        Ok(())
    }

    #[test]
    fn rejects_invalid_journal_root() -> Result<()> {
        let mut payload = make_payload("2025-08-20T00:00:00Z", "02");
        payload.policy_journal_root = Some("deadbeef".to_string());
        let (pk, sk) = keypair();
        let sig = sign_payload(&payload, &pk, &sk);
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let file = policy_file(vec![payload], vec![vec![sig]]);
        let json = serde_json::to_vec(&file)?;
        let err =
            load_policy_journal_from_bytes(&json, &anchors).expect_err("invalid journal root");
        assert!(matches!(err, PolicyError::InvalidPolicyJournalRoot));
        Ok(())
    }

    #[test]
    fn policy_rotation_updates_context() -> Result<()> {
        let payload1 = make_payload("2025-07-01T00:00:00Z", "0102");
        let mut payload2 = payload_with_registry("2025-09-01T00:00:00Z");
        payload2.allow = Some(PolicyAllowSer {
            msphf_crs_id: vec!["rlwe-merkle/v1".to_string()],
            params_id: vec!["0304".to_string()],
            meor_vrf_id: vec!["lb-vrf/v1".to_string()],
            proof_mode: vec!["lin+zkvrf".to_string()],
            srx_modes: vec!["srx/v1-complete".to_string()],
        });

        let (pk, sk) = keypair();
        let anchors = PolicyTrustAnchors::from_ml_dsa_keys([pk.as_bytes().to_vec()]);
        let sig1 = sign_payload(&payload1, &pk, &sk);
        let sig2 = sign_payload(&payload2, &pk, &sk);
        let file = policy_file(
            vec![payload1, payload2],
            vec![vec![sig1.clone()], vec![sig2]],
        );
        let json = serde_json::to_vec(&file)?;
        let document = load_policy_journal_from_bytes(&json, &anchors).context("load document")?;

        let mut ctx = AcceptanceContext::with_defaults();
        document
            .apply_to_context(&mut ctx)
            .context("policy apply failed")?;

        assert_eq!(ctx.policy_version(), "2025-09-01T00:00:00Z");
        assert_eq!(ctx.h_max(), 8);
        let params = ctx
            .allowed_params_ids()
            .context("params allow list missing")?;
        let expected = hex::decode("0304")?;
        assert!(params.contains(&expected));
        Ok(())
    }
}
