//! The message plane of the v0.5 draft (docs/specs-v0.5-draft.md sections
//! 4.3 to 4.8): messages through the delivery service, burst chains checked
//! against the cards of the messages' epoch, and the sealed message log.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use cityg_core::error::CoreError;
use cityg_core::message::{Delivered, MAX_MESSAGE_BYTES, Message, MessageLog, T_BURST_MS};
use cityg_core::objects::Urgency;
use cityg_core::tree::{Occupancy, PublicTree};
use common::Sim;

/// `from` sends `data` now, and the DS records it: the message and its
/// index in the epoch's log.
fn send(sim: &mut Sim, from: Occupancy, data: &[u8]) -> (Message, u64) {
    let message = sim
        .members
        .get_mut(&from)
        .unwrap()
        .send(data, sim.now, &mut sim.rng)
        .unwrap();
    let index = sim.ds.submit_message(message.clone()).unwrap();
    (message, index)
}

/// `reader` opens `messages`, but its own, and delivers what their senders'
/// cards sign, the cards taken from leaf proofs of `tree`, the tree of
/// `tree_epoch`.
fn read(
    sim: &mut Sim,
    reader: Occupancy,
    messages: &[Message],
    tree: &PublicTree,
    tree_epoch: u64,
) -> Vec<Delivered> {
    let member = sim.members.get_mut(&reader).unwrap();
    let mut ready = BTreeSet::new();
    for message in messages {
        match member.open_message(message, sim.now) {
            Err(CoreError::Invalid("a message of the member's own leaf")) => {}
            opened => {
                let received = opened.unwrap();
                if received.ready {
                    ready.insert((message.epoch, received.leaf));
                }
            }
        }
    }
    let mut delivered = Vec::new();
    for (epoch, leaf) in ready {
        let proof = tree.leaf_proof(leaf).unwrap();
        delivered.extend(
            member
                .authenticate(epoch, leaf, &proof, tree_epoch)
                .unwrap(),
        );
    }
    delivered
}

/// What each sender said, in order.
fn by_sender(delivered: &[Delivered]) -> BTreeMap<u32, Vec<&[u8]>> {
    let mut said: BTreeMap<u32, Vec<&[u8]>> = BTreeMap::new();
    for message in delivered {
        said.entry(message.leaf)
            .or_default()
            .push(&message.application_data);
    }
    said
}

#[test]
fn members_exchange_messages_that_the_ds_cannot_attribute() {
    let mut sim = Sim::new(2, 91);
    sim.request_joins(3);
    sim.run_window();
    sim.assert_agreement();
    let epoch = sim.ds.epoch();
    let members: Vec<Occupancy> = sim.members.keys().copied().collect();
    let (alice, bob, carol) = (members[0], members[1], members[2]);
    // Alice's first message is signed at once; her next two wait for the
    // signature that closes her burst.
    send(&mut sim, alice, b"hello");
    sim.now += 100;
    send(&mut sim, bob, b"hi alice");
    send(&mut sim, alice, b"how are you");
    send(&mut sim, alice, b"?");
    assert!(!sim.member(alice).sign_due(sim.now));
    sim.now += T_BURST_MS;
    assert!(sim.member(alice).sign_due(sim.now));
    let closing = sim
        .members
        .get_mut(&alice)
        .unwrap()
        .sign_burst(sim.now, &mut sim.rng)
        .unwrap()
        .unwrap();
    sim.ds.submit_message(closing).unwrap();
    // The DS keeps them in order; nothing in them names their sender.
    let messages = sim.ds.messages(epoch).unwrap().to_vec();
    assert_eq!(messages.len(), 5);
    let sizes: BTreeSet<usize> = messages
        .iter()
        .map(|message| message.encrypted_sender_data.len())
        .collect();
    assert_eq!(sizes.len(), 1);
    // Carol reads everything; Bob everything but his own.
    let tree = sim.ds.state().tree.clone();
    let delivered = read(&mut sim, carol, &messages, &tree, epoch);
    let said = by_sender(&delivered);
    assert_eq!(
        said[&alice.leaf],
        vec![&b"hello"[..], b"how are you", b"?", b""]
    );
    assert_eq!(said[&bob.leaf], vec![&b"hi alice"[..]]);
    let delivered = read(&mut sim, bob, &messages, &tree, epoch);
    assert_eq!(
        by_sender(&delivered).keys().collect::<Vec<_>>(),
        vec![&alice.leaf]
    );
    // Every member of the epoch shares its exports and its authenticator.
    let exports: BTreeSet<Vec<u8>> = sim
        .members
        .values()
        .map(|member| member.export("app", b"context", 32).unwrap().to_vec())
        .collect();
    assert_eq!(exports.len(), 1);
    let before = *sim.member(alice).epoch_authenticator();
    sim.request_joins(1);
    sim.run_window();
    sim.assert_agreement();
    assert_ne!(*sim.member(alice).epoch_authenticator(), before);
}

#[test]
fn a_seal_closes_the_log_of_the_epoch_it_ends() {
    let mut sim = Sim::new(2, 92);
    sim.request_joins(3);
    sim.run_window();
    let epoch = sim.ds.epoch();
    let members: Vec<Occupancy> = sim.members.keys().copied().collect();
    let (first, index) = send(&mut sim, members[0], b"before the window");
    let (second, _) = send(&mut sim, members[1], b"also before");
    // The window opens; messages go to the log until the DS gives the
    // sealer its work.
    sim.request_joins(1);
    let task = sim.open_window();
    send(&mut sim, members[2], b"during the tasks");
    sim.commit_open(&task);
    let log = sim.ds.close_message_log().unwrap();
    assert_eq!(log.count, 3);
    // From then on the DS refuses messages of the epoch: their senders send
    // them again in the next.
    let late = sim
        .members
        .get_mut(&members[0])
        .unwrap()
        .send(b"late", sim.now, &mut sim.rng)
        .unwrap();
    assert_eq!(
        sim.ds.submit_message(late).unwrap_err(),
        CoreError::Invalid("message log closed")
    );
    // A seal with another log is refused; the sealer signs the closed one.
    let other = MessageLog::of(&[first.hash().unwrap()]).unwrap();
    let wrong = sim.seal_open_with(&task, other);
    assert_eq!(
        sim.ds.submit_seal(wrong).unwrap_err(),
        CoreError::Invalid("seal message log")
    );
    let seal = sim.seal_open(&task);
    assert_eq!(seal.header.message_log, log);
    let next = sim.ds.submit_seal(seal).unwrap();
    sim.follow(next);
    sim.welcome_and_enter(next);
    // Every member of the epoch holds the log its seal closed.
    assert_eq!(sim.ds.message_log(epoch).unwrap(), log);
    for member in &members {
        assert_eq!(sim.member(*member).sealed_log(), Some(log));
    }
    // A reader of the whole epoch checks the log; a sender, its message's
    // place in it.
    let messages = sim.ds.messages(epoch).unwrap().to_vec();
    log.check(&messages).unwrap();
    assert!(log.check(&messages[..2]).is_err());
    let proof = sim.ds.message_proof(epoch, index).unwrap();
    log.verify_inclusion(index, &first, &proof).unwrap();
    assert!(log.verify_inclusion(index, &second, &proof).is_err());
    // Members read the epoch's messages after its seal, then forget it.
    let tree = sim.ds.state().tree.clone();
    let delivered = read(&mut sim, members[3], &messages, &tree, next);
    assert_eq!(delivered.len(), 3);
    let reader = sim.members.get_mut(&members[3]).unwrap();
    reader.forget_previous_messages();
    assert_eq!(
        reader.open_message(&first, sim.now).unwrap_err(),
        CoreError::Invalid("messages of an epoch the member does not read")
    );
    // The late message goes out again, in the new epoch.
    let (resent, index) = send(&mut sim, members[0], b"late");
    assert_eq!((resent.epoch, index), (next, 0));
    let delivered = read(&mut sim, members[3], &[resent], &tree, next);
    assert_eq!(delivered[0].application_data, b"late");
}

#[test]
fn a_card_is_checked_against_the_leaf_of_the_messages_epoch() {
    let mut sim = Sim::new(2, 93);
    sim.request_joins(3);
    sim.run_window();
    let epoch = sim.ds.epoch();
    let members: Vec<Occupancy> = sim.members.keys().copied().collect();
    let (admin, updater, leaving, reader) = (members[0], members[1], members[2], members[3]);
    // Two members send; the next window updates the first and removes the
    // other.
    let (from_updater, _) = send(&mut sim, updater, b"before my update");
    let (from_leaving, _) = send(&mut sim, leaving, b"before I go");
    let old_tree = sim.ds.state().tree.clone();
    let update = sim
        .members
        .get_mut(&updater)
        .unwrap()
        .update_request(&mut sim.rng)
        .unwrap();
    sim.ds.submit_update(update, sim.now).unwrap();
    let removal = sim.members[&admin]
        .remove_proposal(leaving, Urgency::Urgent, &mut sim.rng)
        .unwrap();
    sim.ds.submit_removal(removal, sim.now).unwrap();
    let mut removed = sim.take(leaving);
    sim.run_window();
    let next = sim.ds.epoch();
    let tree = sim.ds.state().tree.clone();
    let member = sim.members.get_mut(&reader).unwrap();
    assert!(member.open_message(&from_updater, sim.now).unwrap().ready);
    assert!(member.open_message(&from_leaving, sim.now).unwrap().ready);
    // The updated leaf shows another card: it does not vouch for a message
    // of the previous epoch, the leaf of that epoch does.
    let invalid = CoreError::Invalid("sender's leaf of another epoch");
    let new_leaf = tree.leaf_proof(updater.leaf).unwrap();
    assert_eq!(
        member
            .authenticate(epoch, updater.leaf, &new_leaf, next)
            .unwrap_err(),
        invalid
    );
    let old_leaf = old_tree.leaf_proof(updater.leaf).unwrap();
    let delivered = member
        .authenticate(epoch, updater.leaf, &old_leaf, epoch)
        .unwrap();
    assert_eq!(delivered[0].application_data, b"before my update");
    // The removed member's leaf is blank now; it was a member when it sent.
    let blank = tree.leaf_proof(leaving.leaf).unwrap();
    assert_eq!(
        member
            .authenticate(epoch, leaving.leaf, &blank, next)
            .unwrap_err(),
        CoreError::Invalid("sender's leaf is blank")
    );
    let old_leaving = old_tree.leaf_proof(leaving.leaf).unwrap();
    assert_eq!(
        member
            .authenticate(epoch, leaving.leaf, &old_leaving, epoch)
            .unwrap()
            .len(),
        1
    );
    // A message of the new epoch is not checked against a leaf of an
    // earlier one, which may no longer hold.
    let (fresh, _) = send(&mut sim, updater, b"with my new card");
    let member = sim.members.get_mut(&reader).unwrap();
    assert!(member.open_message(&fresh, sim.now).unwrap().ready);
    assert_eq!(
        member
            .authenticate(next, updater.leaf, &old_leaf, epoch)
            .unwrap_err(),
        invalid
    );
    assert_eq!(
        member
            .authenticate(next, updater.leaf, &new_leaf, next)
            .unwrap()
            .len(),
        1
    );
    // The removed member holds no secret of the new epoch, and the DS
    // refuses the epoch it knows.
    let stale = removed.send(b"still here?", sim.now, &mut sim.rng).unwrap();
    assert_eq!(stale.epoch, epoch);
    assert_eq!(
        sim.ds.submit_message(stale).unwrap_err(),
        CoreError::Invalid("message log closed")
    );
}

#[test]
fn a_joiner_reads_from_the_epoch_it_enters() {
    let mut sim = Sim::new(2, 94);
    sim.request_joins(2);
    sim.run_window();
    let sender = common::CREATOR;
    let (before, _) = send(&mut sim, sender, b"before you came");
    sim.request_joins(1);
    sim.run_window();
    let next = sim.ds.epoch();
    let joiner = *sim
        .members
        .keys()
        .find(|member| member.since == next)
        .unwrap();
    assert_eq!(
        sim.members
            .get_mut(&joiner)
            .unwrap()
            .open_message(&before, sim.now)
            .unwrap_err(),
        CoreError::Invalid("messages of an epoch the member does not read")
    );
    let (welcome, _) = send(&mut sim, sender, b"welcome");
    let tree = sim.ds.state().tree.clone();
    let delivered = read(&mut sim, joiner, &[welcome], &tree, next);
    assert_eq!(delivered[0].application_data, b"welcome");
    assert_eq!(delivered[0].leaf, sender.leaf);
}

#[test]
fn the_ds_checks_what_it_can_see_of_a_message() {
    let mut sim = Sim::new(2, 95);
    sim.request_joins(1);
    sim.run_window();
    let sender = common::CREATOR;
    let (message, _) = send(&mut sim, sender, b"hello");
    assert_eq!(
        sim.ds.submit_message(message.clone()).unwrap_err(),
        CoreError::Invalid("message already in the log")
    );
    let mut elsewhere = message.clone();
    elsewhere.gid[0] ^= 1;
    assert_eq!(
        sim.ds.submit_message(elsewhere).unwrap_err(),
        CoreError::Invalid("message for another group")
    );
    let mut later = message.clone();
    later.epoch += 1;
    assert_eq!(
        sim.ds.submit_message(later).unwrap_err(),
        CoreError::Invalid("message log closed")
    );
    let mut large = message.clone();
    large.ciphertext = vec![0; MAX_MESSAGE_BYTES];
    assert_eq!(
        sim.ds.submit_message(large).unwrap_err(),
        CoreError::TooLarge("message")
    );
    let mut short = message;
    short.encrypted_sender_data.pop();
    assert!(sim.ds.submit_message(short).is_err());
    // A sender cannot send more than a message holds.
    let member = sim.members.get_mut(&sender).unwrap();
    assert_eq!(
        member
            .send(&vec![1; MAX_MESSAGE_BYTES], sim.now, &mut sim.rng)
            .unwrap_err(),
        CoreError::TooLarge("message")
    );
    // Nothing closes a log outside a window.
    assert!(sim.ds.close_message_log().is_err());
}
