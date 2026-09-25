#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Genesis rules of the v0.2 profile (docs/specs.md, sections 5, 9.3 and
//! 12.1): a group starts from a commit whose `gid` binds its creator, which
//! starts the transcript at epoch 0, and whose GroupInfo describes exactly the
//! epoch the delivery service computed.

use cityg_core::CoreError;
use cityg_core::cbor::{array, bytes, encode, text};
use cityg_core::commit::{Commit, CommitContent, CommitKind};
use cityg_core::group_info::{GROUP_INFO_LABEL, GroupInfo};
use cityg_core::hash::ZERO32;
use cityg_core::identity::{DeviceIdentity, group_id, leaf_id};
use cityg_core::kem::KemSecret;
use cityg_core::key_schedule::{
    EpochSecrets, GroupContext, commit_secret, confirmed_transcript_hash,
};
use cityg_core::ledger::GroupLedger;
use cityg_core::state::{stage_genesis, verify_genesis};
use cityg_core::tree::{PathContext, generate_update_path_from_leaf_secret, leaf_key_from_secret};
use cityg_pqc::SignatureContext;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const N_MAX: u32 = 4;

struct Genesis {
    creator: DeviceIdentity,
    content: CommitContent,
    /// Root path secret of the creator's update path.
    root_secret: [u8; 32],
}

/// Honest genesis content, before any tampering.
fn genesis(rng: &mut ChaCha20Rng) -> Genesis {
    let creator = DeviceIdentity::from_seed(&[0x21; 32]);
    let nonce = [0x22; 32];
    let leaf_secret = [0x23; 32];
    let gid = group_id(creator.public_key(), &nonce).unwrap();
    let leaf_key = leaf_key_from_secret(&leaf_secret).unwrap();
    let staged = stage_genesis(&gid, N_MAX, creator.public_key(), &leaf_key.public_key()).unwrap();
    let context = PathContext {
        gid,
        epoch: 0,
        author_slot: 0,
    };
    let (update_path, secrets) =
        generate_update_path_from_leaf_secret(&staged.tree, &context, &leaf_secret, rng).unwrap();
    let mut tree = staged.tree.clone();
    tree.apply_update_path(0, &update_path).unwrap();
    let content = CommitContent {
        gid,
        epoch: 0,
        kind: CommitKind::Genesis,
        prev_interim_transcript_hash: ZERO32,
        author_leaf_id: leaf_id(&gid, creator.public_key()).unwrap(),
        author_device_pk: creator.public_key().to_vec(),
        roster_hash: staged.roster.roster_hash().unwrap(),
        tree_hash: tree.tree_hash().unwrap(),
        update_path,
        removals: Vec::new(),
        admin_changes: Vec::new(),
        join: None,
        external_init: None,
        group_nonce: Some(nonce),
        n_max: Some(N_MAX),
    };
    Genesis {
        creator,
        content,
        root_secret: *secrets.root_secret,
    }
}

/// Sign `content` as `signer`, derive the epoch-0 secrets and return the
/// encoded commit with the GroupInfo its author would publish.
fn publish(
    content: CommitContent,
    signer: &DeviceIdentity,
    root_secret: &[u8; 32],
    rng: &mut ChaCha20Rng,
) -> (Vec<u8>, GroupInfo, EpochSecrets) {
    let signature = content.sign(signer, rng).unwrap();
    let confirmed =
        confirmed_transcript_hash(&ZERO32, &content.tbs().unwrap(), &signature).unwrap();
    let group_context = GroupContext {
        gid: content.gid,
        epoch: content.epoch,
        tree_hash: content.tree_hash,
        roster_hash: content.roster_hash,
        confirmed_transcript_hash: confirmed,
    };
    let secrets = EpochSecrets::derive(
        &ZERO32,
        &commit_secret(root_secret).unwrap(),
        &group_context,
    )
    .unwrap();
    let confirmation_tag = secrets.confirmation_tag(&confirmed).unwrap();
    let info = GroupInfo {
        group_context,
        confirmation_tag,
        external_public_key: secrets.external_key().unwrap().public_key(),
        signer_leaf_id: content.author_leaf_id,
    };
    let commit = Commit {
        content,
        signature,
        confirmation_tag,
    }
    .encode()
    .unwrap();
    (commit, info, secrets)
}

#[test]
fn an_honest_genesis_starts_a_ledger() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let g = genesis(&mut rng);
    let (commit, info, _) = publish(g.content, &g.creator, &g.root_secret, &mut rng);
    let group_info = info.sign(&g.creator, &mut rng).unwrap();
    let (ledger, accepted) = GroupLedger::create(&commit, group_info.encoded(), 0).unwrap();
    assert_eq!(accepted.kind, CommitKind::Genesis);
    assert_eq!(ledger.epoch(), 0);
    assert_eq!(ledger.roster().len(), 1);
    assert!(ledger.roster().is_admin(g.creator.public_key()));
}

#[test]
fn the_gid_binds_the_creator_key_and_nonce() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let g = genesis(&mut rng);

    // Another nonce names another group: the commit's gid no longer binds it.
    let mut other_nonce = g.content.clone();
    other_nonce.group_nonce = Some([0x99; 32]);
    let (commit, _, _) = publish(other_nonce, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::Invalid("gid does not bind the creator"))
    );

    // Another device cannot claim the creator's group: the author leaf id
    // binds its key, and the gid binds the creator's key.
    let mallory = DeviceIdentity::from_seed(&[0x66; 32]);
    let mut stolen = g.content.clone();
    stolen.author_device_pk = mallory.public_key().to_vec();
    stolen.author_leaf_id = leaf_id(&stolen.gid, mallory.public_key()).unwrap();
    let (commit, _, _) = publish(stolen, &mallory, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::Invalid("gid does not bind the creator"))
    );
}

#[test]
fn a_genesis_starts_the_transcript_at_epoch_zero() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let g = genesis(&mut rng);

    let mut later = g.content.clone();
    later.epoch = 1;
    let (commit, _, _) = publish(later, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::EpochMismatch {
            expected: 0,
            got: 1
        })
    );

    let mut chained = g.content.clone();
    chained.prev_interim_transcript_hash = [1; 32];
    let (commit, _, _) = publish(chained, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::TranscriptMismatch)
    );

    let mut member = g.content.clone();
    member.kind = CommitKind::Member;
    member.group_nonce = None;
    member.n_max = None;
    let (commit, _, _) = publish(member, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::Invalid("first commit is not a genesis"))
    );

    let mut wrong_author = g.content.clone();
    wrong_author.author_leaf_id = [7; 32];
    let (commit, _, _) = publish(wrong_author, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::Invalid("commit author leaf id"))
    );
}

#[test]
fn the_announced_tree_and_roster_hashes_are_recomputed() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let g = genesis(&mut rng);

    let mut tree = g.content.clone();
    tree.tree_hash = [3; 32];
    let (commit, _, _) = publish(tree, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::Invalid("commit tree hash"))
    );

    let mut roster = g.content.clone();
    roster.roster_hash = [4; 32];
    let (commit, _, _) = publish(roster, &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        verify_genesis(&commit).err(),
        Some(CoreError::Invalid("commit roster hash"))
    );
}

#[test]
fn the_ledger_accepts_only_the_group_info_of_the_computed_epoch() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let g = genesis(&mut rng);
    let (commit, info, secrets) = publish(g.content.clone(), &g.creator, &g.root_secret, &mut rng);
    assert_eq!(
        info.external_public_key,
        secrets.external_key().unwrap().public_key()
    );

    // A GroupInfo naming another confirmation tag or another context does
    // not describe the epoch the ledger computed.
    let mut wrong_tag = info.clone();
    wrong_tag.confirmation_tag = [5; 32];
    let mut wrong_context = info.clone();
    wrong_context.group_context.tree_hash = [6; 32];
    for forged in [wrong_tag, wrong_context] {
        let signed = forged.sign(&g.creator, &mut rng).unwrap();
        assert_eq!(
            GroupLedger::create(&commit, signed.encoded(), 0).err(),
            Some(CoreError::Invalid("group info does not match the commit"))
        );
    }

    // Only the author of the commit signs its GroupInfo.
    let mallory = DeviceIdentity::from_seed(&[0x66; 32]);
    let mut other_signer = info.clone();
    other_signer.signer_leaf_id = mallory.leaf_id(&g.content.gid).unwrap();
    let signed = other_signer.sign(&mallory, &mut rng).unwrap();
    assert_eq!(
        GroupLedger::create(&commit, signed.encoded(), 0).err(),
        Some(CoreError::Invalid("group info does not match the commit"))
    );

    // Nor can the delivery service sign one in the author's name.
    let server = DeviceIdentity::from_seed(&[0x55; 32]);
    let mut fields = vec![
        text(GROUP_INFO_LABEL),
        bytes(&info.group_context.encode().unwrap()),
        bytes(&info.confirmation_tag),
        bytes(&info.external_public_key),
        bytes(&info.signer_leaf_id),
    ];
    let tbs = encode(&array(fields.clone())).unwrap();
    let signature = server
        .sign(SignatureContext::GROUP_INFO, &tbs, &mut rng)
        .unwrap();
    fields.push(bytes(&signature));
    let by_server = encode(&array(fields)).unwrap();
    assert!(matches!(
        GroupLedger::create(&commit, &by_server, 0),
        Err(CoreError::BadSignature(_))
    ));

    // A wrong external key is caught by members, which derive it themselves
    // (docs/specs.md, section 9.5); the ledger cannot check it.
    let mut wrong_key = info.clone();
    wrong_key.external_public_key = KemSecret::generate(&mut rng).public_key();
    let signed = wrong_key.sign(&g.creator, &mut rng).unwrap();
    assert!(
        GroupLedger::create(&commit, signed.encoded(), 0).is_ok(),
        "the ledger holds no secret to check the external key"
    );
}
