//! Merkle tree hashes in the manner of RFC 6962 §2.1, framed by a label
//! (docs/specs-v0.5-draft.md sections 4.8 to 4.10):
//!
//! ```text
//! MTH(label, [])  := H_L(label, [])
//! MTH(label, [d]) := H_L(label, [d])
//! MTH(label, D)   := H_L(label, [MTH(label, D[0..k]), MTH(label, D[k..|D|])])
//!                    k: the largest power of 2 below |D|
//! ```
//!
//! A leaf and an inner node differ by the length of their arguments. The
//! message log (`msg-log`), authorization batches (`authorized`) and the
//! membership log (`membership-log`) are such trees.

use crate::cbor::bytes;
use crate::crypto::{Digest, h_l};
use crate::error::{CoreError, CoreResult};

fn leaf(label: &str, leaf: &Digest) -> CoreResult<Digest> {
    h_l(label, vec![bytes(leaf)])
}

fn node(label: &str, left: &Digest, right: &Digest) -> CoreResult<Digest> {
    h_l(label, vec![bytes(left), bytes(right)])
}

/// The largest power of 2 below `n` (for `n >= 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// `MTH(label, leaves)`.
pub fn root(label: &str, leaves: &[Digest]) -> CoreResult<Digest> {
    match leaves {
        [] => h_l(label, vec![]),
        [only] => leaf(label, only),
        _ => {
            let k = split(leaves.len());
            node(
                label,
                &root(label, &leaves[..k])?,
                &root(label, &leaves[k..])?,
            )
        }
    }
}

/// The proof that `leaves[index]` is in `MTH(label, leaves)`: the siblings
/// from the leaf up (RFC 6962 §2.1.1).
pub fn inclusion_proof(label: &str, leaves: &[Digest], index: usize) -> CoreResult<Vec<Digest>> {
    if index >= leaves.len() {
        return Err(CoreError::Invalid("Merkle tree index"));
    }
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let k = split(leaves.len());
    let (mut proof, sibling) = if index < k {
        (
            inclusion_proof(label, &leaves[..k], index)?,
            root(label, &leaves[k..])?,
        )
    } else {
        (
            inclusion_proof(label, &leaves[k..], index - k)?,
            root(label, &leaves[..k])?,
        )
    };
    proof.push(sibling);
    Ok(proof)
}

/// Check that `value` is the `index`-th of the `count` leaves under `root`
/// (RFC 9162 §2.1.3.2). `count` and `root` go together, as a signed tree
/// head does: a root alone does not fix the number of its leaves.
pub fn verify_inclusion(
    label: &str,
    root: &Digest,
    count: u64,
    index: u64,
    value: &Digest,
    proof: &[Digest],
) -> CoreResult<()> {
    const INVALID: CoreError = CoreError::Invalid("Merkle inclusion proof");
    if index >= count {
        return Err(INVALID);
    }
    let mut fn_ = index;
    let mut sn = count - 1;
    let mut hash = leaf(label, value)?;
    for sibling in proof {
        if sn == 0 {
            return Err(INVALID);
        }
        if fn_ & 1 == 1 || fn_ == sn {
            hash = node(label, sibling, &hash)?;
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            hash = node(label, &hash, sibling)?;
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn == 0 && hash == *root {
        Ok(())
    } else {
        Err(INVALID)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::h;

    #[test]
    fn every_leaf_has_a_proof_and_no_other_value_does() {
        let leaves: Vec<Digest> = (0..11u8).map(|i| h(&[i])).collect();
        for count in 1..=leaves.len() {
            let top = root("test", &leaves[..count]).unwrap();
            for index in 0..count {
                let proof = inclusion_proof("test", &leaves[..count], index).unwrap();
                let at = index as u64;
                verify_inclusion("test", &top, count as u64, at, &leaves[index], &proof).unwrap();
                let other = &leaves[(index + 1) % leaves.len()];
                assert!(verify_inclusion("test", &top, count as u64, at, other, &proof).is_err());
                assert!(
                    verify_inclusion("other", &top, count as u64, at, &leaves[index], &proof)
                        .is_err()
                );
            }
            assert!(inclusion_proof("test", &leaves[..count], count).is_err());
        }
        // A leaf is not a tree of two: the labels frame both.
        assert_ne!(
            root("test", &leaves[..1]).unwrap(),
            root("other", &leaves[..1]).unwrap()
        );
        assert_ne!(
            root("test", &[]).unwrap(),
            root("test", &leaves[..1]).unwrap()
        );
    }
}
