//! Audits of a window's entries and fraud proofs (E-12,
//! docs/specs.md section 15).
//!
//! The delivery service checks every request as it records it; each
//! committer checks the entries of its district; the sealer checks the
//! structure of every district commit. Members audit random entries: each
//! entry of a window is checked by `AUDIT_K` members on average, against the
//! header of the epoch before the window. An entry that fails, in a district
//! commit signed by its committer, is a [`FraudProof`] anyone can check.

use std::collections::BTreeSet;

use rand_core::CryptoRngCore;

use crate::card::Card;
use crate::commit::{Change, DistrictCommit};
use crate::crypto::kem_pk_hash;
use crate::error::{CoreError, CoreResult};
use crate::objects::{GroupPolicy, Request};
use crate::smm::SmmProof;
use crate::tree::{LeafProof, Occupancy, leaf_key_hash};
use crate::window::{EpochHeader, PublicState, Requests, WindowShape};

/// Mean number of audits per entry.
pub const AUDIT_K: u32 = 20;

/// What an auditor needs besides the request to check an entry against the
/// previous epoch's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryProofs {
    /// The changed leaf in the previous tree (not for joins).
    pub subject: Option<LeafProof>,
    /// For a join: the device's absence from the device map.
    pub device: Option<SmmProof>,
    /// For a join: the absence of its admission (or, without admission, of
    /// its request) from the admission map.
    pub admission: Option<SmmProof>,
    /// For an eviction: the policy in force.
    pub policy: Option<GroupPolicy>,
    /// For a join, an update or a re-entry: the leaf key's and the card's
    /// absence from the map of keys, in that order
    /// (docs/specs-v0.5-draft.md section 4.2).
    pub keys: Vec<SmmProof>,
    /// In an authorized group, for a join or a removal: the authorizer's
    /// key, which the registry's hash of it checks (section 4.9).
    pub authorizer_pk: Option<Vec<u8>>,
}

/// One entry of a window, with what it takes to audit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub epoch: u64,
    pub district: u32,
    pub committer: Occupancy,
    pub change: Change,
    pub request: Request,
    pub proofs: EntryProofs,
}

/// The outcome of an audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    Fraud(&'static str),
}

/// The records of a window's entries, with proofs against `state`, the
/// state before the window.
pub fn records(
    state: &PublicState,
    window: &WindowShape,
    commits: &[DistrictCommit],
    requests: &Requests,
) -> CoreResult<Vec<AuditRecord>> {
    let mut records = Vec::new();
    for commit in commits {
        for change in &commit.changes {
            let request = requests
                .get(&change.request)
                .ok_or(CoreError::Invalid("missing request"))?
                .clone();
            let mut proofs = EntryProofs {
                subject: None,
                device: None,
                admission: None,
                policy: None,
                keys: Vec::new(),
                authorizer_pk: None,
            };
            let key_proofs = |encryption_key: &[u8], card: &Card| -> CoreResult<Vec<SmmProof>> {
                [leaf_key_hash(encryption_key)?, card.hash()?]
                    .iter()
                    .map(|key| state.registry.key_proof(key))
                    .collect()
            };
            if matches!(request, Request::Join(_) | Request::Removal(_)) {
                proofs.authorizer_pk = state
                    .policy
                    .as_ref()
                    .and_then(GroupPolicy::authorizer_pk)
                    .map(<[u8]>::to_vec);
            }
            match &request {
                Request::Join(join) => {
                    proofs.device = Some(state.registry.device_proof(&join.device_id()?)?);
                    proofs.admission = Some(state.registry.admission_proof(&join.token())?);
                    proofs.keys = key_proofs(&join.encryption_key, &join.card)?;
                }
                Request::Eviction(_) => {
                    proofs.subject = Some(state.tree.leaf_proof(change.leaf)?);
                    proofs.policy.clone_from(&state.policy);
                }
                Request::Update(update) => {
                    proofs.subject = Some(state.tree.leaf_proof(change.leaf)?);
                    proofs.keys = key_proofs(&update.encryption_key, &update.card)?;
                }
                Request::ReEntry(re_entry) => {
                    proofs.subject = Some(state.tree.leaf_proof(change.leaf)?);
                    proofs.keys = key_proofs(&re_entry.encryption_key, &re_entry.card)?;
                }
                Request::Removal(_) => proofs.subject = Some(state.tree.leaf_proof(change.leaf)?),
            }
            records.push(AuditRecord {
                epoch: window.epoch,
                district: commit.district,
                committer: commit.committer,
                change: *change,
                request,
                proofs,
            });
        }
    }
    Ok(records)
}

fn fraud_if(check: CoreResult<()>, why: &'static str) -> Option<Verdict> {
    check.err().map(|_| Verdict::Fraud(why))
}

/// Whether the leaf key or the card that a record's change sets is in the
/// map of keys before its window, by the record's two proofs.
fn keys_in_use(
    previous: &EpochHeader,
    record: &AuditRecord,
    encryption_key: &[u8],
    card: &Card,
) -> CoreResult<bool> {
    let keys = [leaf_key_hash(encryption_key)?, card.hash()?];
    if record.proofs.keys.len() != keys.len() {
        return Err(CoreError::Invalid("audit record without the key proofs"));
    }
    let mut in_use = false;
    for (proof, key) in record.proofs.keys.iter().zip(&keys) {
        in_use |= proof.verify(&previous.registry.keys_root, key)?.is_some();
    }
    Ok(in_use)
}

const KEY_IN_USE: Verdict = Verdict::Fraud("a leaf key or card already in use");

/// Audit one entry against `previous`, the header of the epoch before its
/// window. `Err` means the record's proofs do not check (nothing can be
/// concluded); `Ok(Verdict::Fraud(_))` that the entry is invalid.
pub fn check_record(previous: &EpochHeader, record: &AuditRecord) -> CoreResult<Verdict> {
    let gid = &previous.gid;
    let admitters = previous
        .registry
        .admitters(record.proofs.authorizer_pk.as_deref())?;
    if record.epoch != previous.epoch + 1 || record.request.reference() != record.change.request {
        return Err(CoreError::Invalid("audit record"));
    }
    if record.request.gid() != gid {
        return Ok(Verdict::Fraud("request for another group"));
    }
    if record.request.kind() != record.change.kind {
        return Ok(Verdict::Fraud("request of another kind"));
    }
    let subject = || -> CoreResult<&LeafProof> {
        let proof = record
            .proofs
            .subject
            .as_ref()
            .ok_or(CoreError::Invalid("audit record without the leaf"))?;
        proof.verify(&previous.tree_hash)?;
        if proof.index != record.change.leaf {
            return Err(CoreError::Invalid("audit record for another leaf"));
        }
        Ok(proof)
    };
    let verdict = match &record.request {
        Request::Join(join) => {
            let device = record
                .proofs
                .device
                .as_ref()
                .ok_or(CoreError::Invalid("audit record without the device proof"))?
                .verify(&previous.registry.devices_root, &join.device_id()?)?;
            let admission = record
                .proofs
                .admission
                .as_ref()
                .ok_or(CoreError::Invalid(
                    "audit record without the admission proof",
                ))?
                .verify(&previous.registry.admissions_root, &join.token())?;
            let in_use = keys_in_use(previous, record, &join.encryption_key, &join.card)?;
            if device.is_some() {
                Some(Verdict::Fraud("device already a member"))
            } else if admission.is_some() {
                Some(Verdict::Fraud("admission already used"))
            } else if in_use {
                Some(KEY_IN_USE)
            } else {
                fraud_if(
                    join.verify(gid, record.epoch, &admitters),
                    "join request or admission",
                )
            }
        }
        Request::Removal(proposal) => {
            let leaf = subject()?;
            match &leaf.leaf {
                None => Some(Verdict::Fraud("removal of a blank leaf")),
                Some(_) if leaf.occupancy() != Some(proposal.target) => {
                    Some(Verdict::Fraud("removal of another member"))
                }
                Some(node) => fraud_if(
                    proposal.verify(gid, &admitters, &node.device_pk),
                    "removal proposal",
                ),
            }
        }
        Request::Eviction(eviction) => {
            let leaf = subject()?;
            let policy = record.proofs.policy.as_ref();
            match (&leaf.leaf, policy, previous.registry.policy) {
                (None, _, _) => Some(Verdict::Fraud("eviction of a blank leaf")),
                (_, _, None) => Some(Verdict::Fraud("eviction without a policy")),
                (_, None, Some(_)) => {
                    return Err(CoreError::Invalid("audit record without the policy"));
                }
                (Some(node), Some(policy), Some(hash)) => {
                    if policy.hash() != hash {
                        return Err(CoreError::Invalid("audit record with another policy"));
                    }
                    if leaf.occupancy() != Some(eviction.target) {
                        Some(Verdict::Fraud("eviction of another member"))
                    } else {
                        fraud_if(
                            eviction.verify(gid, policy, node.updated, record.epoch),
                            "eviction",
                        )
                    }
                }
            }
        }
        Request::Update(update) => {
            let leaf = subject()?;
            match &leaf.leaf {
                Some(node) if leaf.occupancy() == Some(update.member) => {
                    if update.replaces != kem_pk_hash(&node.encryption_key)? {
                        Some(Verdict::Fraud("update replaces another key"))
                    } else if keys_in_use(previous, record, &update.encryption_key, &update.card)? {
                        Some(KEY_IN_USE)
                    } else {
                        fraud_if(update.verify(gid, &node.device_pk), "update request")
                    }
                }
                _ => Some(Verdict::Fraud("update of another member")),
            }
        }
        Request::ReEntry(re_entry) => {
            let leaf = subject()?;
            match &leaf.leaf {
                Some(node) if leaf.occupancy() == Some(re_entry.member) => {
                    if re_entry.replaces != kem_pk_hash(&node.encryption_key)? {
                        Some(Verdict::Fraud("re-entry replaces another key"))
                    } else if keys_in_use(
                        previous,
                        record,
                        &re_entry.encryption_key,
                        &re_entry.card,
                    )? {
                        Some(KEY_IN_USE)
                    } else {
                        fraud_if(re_entry.verify(gid, &node.device_pk), "re-entry request")
                    }
                }
                _ => Some(Verdict::Fraud("re-entry of another member")),
            }
        }
    };
    Ok(verdict.unwrap_or(Verdict::Valid))
}

/// The entries one member audits among `entries`, when `members` members
/// share `k` audits per entry on average.
pub fn picks(entries: usize, members: usize, k: u32, rng: &mut impl CryptoRngCore) -> Vec<usize> {
    if entries == 0 || members == 0 {
        return Vec::new();
    }
    let wanted = (entries * k as usize).div_ceil(members).min(entries);
    let mut chosen = BTreeSet::new();
    while chosen.len() < wanted {
        let index = usize::try_from(rng.next_u64() % entries as u64).unwrap_or(0);
        chosen.insert(index);
    }
    chosen.into_iter().collect()
}

/// A signed district commit with an invalid entry: proof that its committer
/// placed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FraudProof {
    pub commit: DistrictCommit,
    pub record: AuditRecord,
    /// The committer's leaf in the tree after the window.
    pub committer_leaf: LeafProof,
}

impl FraudProof {
    /// Check the proof against the headers of the epochs before and after
    /// the window; returns the committer it proves guilty.
    pub fn verify(&self, previous: &EpochHeader, next: &EpochHeader) -> CoreResult<Occupancy> {
        let commit = &self.commit;
        if next.epoch != previous.epoch + 1
            || commit.epoch != next.epoch
            || commit.gid != previous.gid
            || commit.committer != self.record.committer
            || commit.district != self.record.district
            || !commit.changes.contains(&self.record.change)
        {
            return Err(CoreError::Invalid("fraud proof"));
        }
        self.committer_leaf.verify(&next.tree_hash)?;
        let leaf = self
            .committer_leaf
            .leaf
            .as_ref()
            .ok_or(CoreError::Invalid("fraud proof committer"))?;
        if self.committer_leaf.occupancy() != Some(commit.committer) {
            return Err(CoreError::Invalid("fraud proof committer"));
        }
        commit.verify_signature(&leaf.device_pk)?;
        match check_record(previous, &self.record)? {
            Verdict::Fraud(_) => Ok(commit.committer),
            Verdict::Valid => Err(CoreError::Invalid("the entry is valid")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn picks_spread_audits() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert!(picks(0, 10, 20, &mut rng).is_empty());
        assert_eq!(picks(10, 5, 20, &mut rng).len(), 10);
        let few = picks(1000, 400, 20, &mut rng);
        assert_eq!(few.len(), 50);
        assert!(few.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(few.iter().all(|index| *index < 1000));
    }
}
