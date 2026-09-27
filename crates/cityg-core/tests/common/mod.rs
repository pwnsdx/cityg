//! A small simulation of a group: a delivery service, members that
//! follow every window (their whole path, or as island followers), and
//! joiners.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;

use cityg_core::ds::{DeliveryService, DsConfig, TopChoice};
use cityg_core::error::CoreError;
use cityg_core::identity::DeviceIdentity;
use cityg_core::member::{Joiner, Member, Returning};
use cityg_core::packet::SealLink;
use cityg_core::roles::WindowTask;
use cityg_core::tree::Occupancy;
use cityg_core::window::EpochHeader;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

pub const CREATOR: Occupancy = Occupancy { leaf: 0, since: 0 };

pub struct Sim {
    pub rng: ChaCha20Rng,
    pub ds: DeliveryService,
    /// Members that follow every window.
    pub members: BTreeMap<Occupancy, Member>,
    /// Joiners waiting for their window, by request reference.
    pub joiners: BTreeMap<[u8; 32], Joiner>,
    /// Members coming back, by request reference.
    pub returning: BTreeMap<[u8; 32], Returning>,
    /// Members that do not follow windows for now.
    pub absent: std::collections::BTreeSet<Occupancy>,
    pub now: u64,
    /// Members follow as island followers, and relays and flat elements
    /// are made after every seal (E-15).
    pub islands: bool,
}

impl Sim {
    /// A closed group created by one member, with districts of `2^bits`
    /// leaves.
    pub fn new(bits: u8, seed: u64) -> Self {
        Self::with_policy(bits, seed, false)
    }

    /// A group created by one member, open or closed.
    pub fn with_policy(bits: u8, seed: u64, open: bool) -> Self {
        Self::build(bits, bits, seed, open, false)
    }

    /// A closed group with districts of `2^bits` leaves and islands of
    /// `2^island_bits`, whose members follow as island followers.
    pub fn with_islands(bits: u8, island_bits: u8, seed: u64) -> Self {
        Self::build(bits, island_bits, seed, false, true)
    }

    fn build(bits: u8, island_bits: u8, seed: u64, open: bool, islands: bool) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let identity = DeviceIdentity::generate(&mut rng);
        let (creator, genesis) =
            Member::create(identity, [7; 32], bits, island_bits, open, 1_000, &mut rng).unwrap();
        let ds = DeliveryService::new(genesis, DsConfig::default()).unwrap();
        let mut members = BTreeMap::new();
        members.insert(creator.occupancy(), creator);
        let mut sim = Self {
            rng,
            ds,
            members,
            joiners: BTreeMap::new(),
            returning: BTreeMap::new(),
            absent: std::collections::BTreeSet::new(),
            now: 1_000,
            islands,
        };
        sim.set_all_online(true);
        sim
    }

    pub fn member(&self, occupancy: Occupancy) -> &Member {
        &self.members[&occupancy]
    }

    pub fn set_all_online(&mut self, online: bool) {
        let all: Vec<Occupancy> = self.members.keys().copied().collect();
        for member in all {
            self.ds.set_online(member, online);
        }
    }

    /// An admin checkpoints the current epoch; returns the anchor a joiner
    /// builds from it.
    pub fn anchor(&mut self) -> EpochHeader {
        let admin = self
            .members
            .values()
            .find(|member| member.is_admin() && member.epoch() == self.ds.epoch())
            .expect("an admin following the group");
        let admin_pk = admin.identity().public_key().to_vec();
        let checkpoint = admin.checkpoint(self.now, &mut self.rng).unwrap();
        self.ds.submit_checkpoint(checkpoint.clone()).unwrap();
        let (registry, external_pk) = self.ds.anchor_material(checkpoint.content.epoch).unwrap();
        EpochHeader::from_checkpoint(
            &checkpoint.gid,
            &checkpoint,
            &admin_pk,
            registry,
            external_pk,
        )
        .unwrap()
    }

    /// `count` devices admitted by an admin ask to join.
    pub fn request_joins(&mut self, count: usize) -> Vec<[u8; 32]> {
        let anchor = self.anchor();
        let admin = *self
            .members
            .iter()
            .find(|(_, member)| member.is_admin())
            .map(|(occupancy, _)| occupancy)
            .unwrap();
        let mut references = Vec::new();
        for _ in 0..count {
            let identity = DeviceIdentity::generate(&mut self.rng);
            let admission = self.members[&admin]
                .admit(identity.public_key(), self.ds.epoch() + 100, &mut self.rng)
                .unwrap();
            let not_after = admission.not_after_epoch;
            let joiner = Joiner::new(
                identity,
                Some(&admission),
                not_after,
                anchor.clone(),
                &mut self.rng,
            )
            .unwrap();
            let reference = self
                .ds
                .submit_join(joiner.request().clone(), self.now)
                .unwrap();
            self.joiners.insert(reference, joiner);
            references.push(reference);
        }
        references
    }

    /// `count` devices ask to join an open group, with no admission.
    pub fn request_open_joins(&mut self, count: usize) -> Vec<[u8; 32]> {
        let anchor = self.anchor();
        let mut references = Vec::new();
        for _ in 0..count {
            let identity = DeviceIdentity::generate(&mut self.rng);
            let not_after = self.ds.epoch() + 100;
            let joiner =
                Joiner::new(identity, None, not_after, anchor.clone(), &mut self.rng).unwrap();
            let reference = self
                .ds
                .submit_join(joiner.request().clone(), self.now)
                .unwrap();
            self.joiners.insert(reference, joiner);
            references.push(reference);
        }
        references
    }

    /// Run one window with the online members in their roles; every member
    /// follows it and every welcomed joiner enters. Returns the task.
    pub fn run_window(&mut self) -> WindowTask {
        let task = self.open_window();
        let epoch = self.complete_window(&task);
        self.welcome_and_enter(epoch);
        task
    }

    /// Open the next window, with members online in its roles.
    pub fn open_window(&mut self) -> WindowTask {
        self.now += 60_000;
        let task = self.ds.open_window(self.now).unwrap().expect("a window");
        assert!(task.entrant.is_none(), "use run_entrant_window");
        task
    }

    /// The committers of the open window `task` commit, its sealer seals,
    /// and every member follows it. Returns the new epoch.
    pub fn complete_window(&mut self, task: &WindowTask) -> u64 {
        let epoch = self.seal_window(task);
        self.follow(epoch);
        epoch
    }

    /// The committers of the open window `task` commit and its sealer
    /// seals; nobody follows yet. Returns the new epoch.
    pub fn seal_window(&mut self, task: &WindowTask) -> u64 {
        let (_, requests, _) = self.ds.open_window_data().unwrap();
        let requests = requests.clone();
        for (district, committer) in &task.committers {
            let commit = self.members[committer]
                .commit_district(self.ds.state(), task, *district, &requests, &mut self.rng)
                .unwrap();
            self.ds.submit_district_commit(commit).unwrap();
        }
        let commits = self.ds.open_commits();
        // Without a city, the sealer follows the district commit along its
        // own path: an island follower refreshes its path first.
        let city = self
            .ds
            .state()
            .tree
            .shape()
            .grown(task.height)
            .unwrap()
            .has_city();
        if !city && !self.members[&task.sealer].knows_path() {
            let steps = self.ds.refresh_steps(task.sealer).unwrap();
            self.members
                .get_mut(&task.sealer)
                .unwrap()
                .refresh(&steps)
                .unwrap();
        }
        let seal = self.members[&task.sealer]
            .seal(self.ds.state(), task, &commits, &requests, &mut self.rng)
            .unwrap();
        self.ds.submit_seal(seal).unwrap()
    }

    /// Every member follows the window of `epoch`; members it removed leave.
    /// With islands, the window's relays and flat elements come first.
    pub fn follow(&mut self, epoch: u64) {
        if self.islands {
            self.make_tops(epoch);
        }
        let occupancies: Vec<Occupancy> = self.members.keys().copied().collect();
        for occupancy in occupancies {
            if self.members[&occupancy].epoch() + 1 != epoch || self.absent.contains(&occupancy) {
                continue;
            }
            let followed = if self.islands {
                self.follow_island(occupancy, epoch)
            } else {
                self.ds.packet(epoch, occupancy).map(|packet| {
                    self.members
                        .get_mut(&occupancy)
                        .unwrap()
                        .process(&packet)
                        .unwrap();
                })
            };
            if followed.is_err() {
                self.members.remove(&occupancy);
            }
        }
    }

    /// The relays of window `epoch` follow it by refresh and send their
    /// relay elements; then the members asked for flat elements send them.
    pub fn make_tops(&mut self, epoch: u64) {
        let task = self.ds.window(epoch).unwrap().top_task().clone();
        for relay in task.relays.values() {
            let ready = self
                .members
                .get(relay)
                .is_some_and(|member| member.epoch() + 1 == epoch);
            if !ready || self.absent.contains(relay) {
                continue;
            }
            let packet = self
                .ds
                .island_packet(epoch, *relay, TopChoice::Refresh)
                .unwrap();
            let member = self.members.get_mut(relay).unwrap();
            member.process(&packet).unwrap();
            let element = member.relay_element().unwrap();
            self.ds.submit_relay(*relay, element).unwrap();
        }
        for (maker, islands) in &task.flats {
            let Some(member) = self.members.get(maker) else {
                continue;
            };
            if member.epoch() != epoch {
                continue;
            }
            let flats = member
                .flat_elements(self.ds.state(), islands, &mut self.rng)
                .unwrap();
            self.ds.submit_flats(*maker, epoch, flats).unwrap();
        }
    }

    /// An island follower follows window `epoch`: from its relay element,
    /// else its flat element, else a refresh. A packet the service refuses
    /// (the member was removed) is the error.
    pub fn follow_island(&mut self, occupancy: Occupancy, epoch: u64) -> Result<(), CoreError> {
        for choice in [TopChoice::Best, TopChoice::AvoidRelay] {
            let packet = self.ds.island_packet(epoch, occupancy, choice)?;
            let member = self.members.get_mut(&occupancy).unwrap();
            if member.process(&packet).is_ok() {
                return Ok(());
            }
        }
        let packet = self
            .ds
            .island_packet(epoch, occupancy, TopChoice::Refresh)?;
        self.members
            .get_mut(&occupancy)
            .unwrap()
            .process(&packet)
            .expect("a refresh leads to the epoch");
        Ok(())
    }

    /// Welcomers seal their welcomes; joiners of the window enter.
    pub fn welcome_and_enter(&mut self, epoch: u64) {
        let stored = self.ds.window(epoch).unwrap().clone();
        let welcomers: Vec<Occupancy> = stored
            .task
            .welcomes
            .iter()
            .map(|welcome| welcome.welcomer)
            .collect();
        let mut done = std::collections::BTreeSet::new();
        for welcomer in welcomers {
            if !done.insert(welcomer) {
                continue;
            }
            let Some(member) = self.members.get(&welcomer) else {
                continue;
            };
            let welcomes = member
                .welcomes(
                    self.ds.state(),
                    &stored.seal,
                    &stored.commits,
                    &stored.task,
                    &stored.requests,
                    &stored.catch_ups,
                    &mut self.rng,
                )
                .unwrap();
            for welcome in welcomes {
                self.ds.submit_welcome(welcomer, welcome).unwrap();
            }
        }
        self.enter_joiners();
        self.enter_returning();
    }

    /// Run a window that an entrant seals (nobody online).
    pub fn run_entrant_window(&mut self) -> WindowTask {
        self.now += 60_000;
        let task = self.ds.open_window(self.now).unwrap().expect("a window");
        let entrant = task.entrant.expect("an entrant window");
        let (_, requests, catch_ups) = self.ds.open_window_data().unwrap();
        let (requests, catch_ups) = (requests.clone(), catch_ups.clone());
        let sealed = if let Some(mut joiner) = self.joiners.remove(&entrant) {
            let links = self.links(joiner.anchor().epoch);
            joiner.follow(&links).unwrap();
            joiner
                .seal_window(self.ds.state(), &task, &requests, &catch_ups, &mut self.rng)
                .unwrap()
        } else {
            let mut returning = self.returning.remove(&entrant).expect("the entrant");
            let links = self.links(returning.anchor().epoch);
            returning.follow(&links).unwrap();
            returning
                .seal_window(self.ds.state(), &task, &requests, &catch_ups, &mut self.rng)
                .unwrap()
        };
        for commit in sealed.commits {
            self.ds.submit_district_commit(commit).unwrap();
        }
        let epoch = self.ds.submit_seal(sealed.seal).unwrap();
        let welcomer = sealed.member.occupancy();
        for welcome in sealed.welcomes {
            self.ds.submit_welcome(welcomer, welcome).unwrap();
        }
        self.absent.remove(&sealed.member.occupancy());
        self.members
            .insert(sealed.member.occupancy(), sealed.member);
        self.follow(epoch);
        self.enter_joiners();
        self.enter_returning();
        task
    }

    /// Returning members whose welcome is ready enter.
    pub fn enter_returning(&mut self) {
        let references: Vec<[u8; 32]> = self.returning.keys().copied().collect();
        for reference in references {
            let anchor = self.returning[&reference].anchor().epoch;
            if let Ok(entry) = self.ds.entry(&reference, anchor) {
                let returning = self.returning.remove(&reference).unwrap();
                let member = returning.enter(&entry).unwrap();
                self.absent.remove(&member.occupancy());
                self.members.insert(member.occupancy(), member);
            }
        }
    }

    /// An absent member processes every window it missed.
    pub fn replay(&mut self, occupancy: Occupancy) {
        self.absent.remove(&occupancy);
        while self.members[&occupancy].epoch() < self.ds.epoch() {
            let epoch = self.members[&occupancy].epoch() + 1;
            if self.islands {
                self.follow_island(occupancy, epoch).unwrap();
                continue;
            }
            let packet = self.ds.packet(epoch, occupancy).unwrap();
            self.members
                .get_mut(&occupancy)
                .unwrap()
                .process(&packet)
                .unwrap();
        }
    }

    /// Take a member out of the simulation to come back as a returning
    /// member (the caller makes the request).
    pub fn take(&mut self, occupancy: Occupancy) -> Member {
        self.ds.set_online(occupancy, false);
        self.absent.remove(&occupancy);
        self.members.remove(&occupancy).unwrap()
    }

    /// Joiners whose welcome is ready enter.
    pub fn enter_joiners(&mut self) {
        let references: Vec<[u8; 32]> = self.joiners.keys().copied().collect();
        for reference in references {
            let anchor = self.joiners[&reference].anchor().epoch;
            if let Ok(entry) = self.ds.entry(&reference, anchor) {
                let joiner = self.joiners.remove(&reference).unwrap();
                let member = joiner.enter(&entry).unwrap();
                self.ds.set_online(member.occupancy(), true);
                self.members.insert(member.occupancy(), member);
            }
        }
    }

    /// Links from `after` to the current epoch.
    pub fn links(&self, after: u64) -> Vec<SealLink> {
        self.ds.links(after, self.ds.epoch()).unwrap()
    }

    /// Every member that follows the group agrees on the epoch.
    pub fn assert_agreement(&self) {
        let epoch = self.ds.epoch();
        let mut secrets = self
            .members
            .values()
            .filter(|member| member.epoch() == epoch)
            .map(|member| *member.msg_secret());
        let first = secrets.next().expect("a member at the current epoch");
        assert!(secrets.all(|secret| secret == first), "members disagree");
        for member in self.members.values().filter(|m| m.epoch() == epoch) {
            assert_eq!(member.header(), &self.ds.state().header().unwrap());
        }
    }

    pub fn random_seed(&mut self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        self.rng.fill_bytes(&mut seed);
        seed
    }
}
