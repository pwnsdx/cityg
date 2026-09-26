# Changelog

All notable changes to the City-G project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — initial version

Profile `city-g/v0.4`, for end-to-end encrypted groups of millions of
members.

### Protocol

- Specification ([`docs/specs.md`](docs/specs.md)) and design note
  ([`docs/design.md`](docs/design.md), decisions E-1 to E-14).
- One epoch per window of requests: district commits built in parallel,
  then a seal that re-keys the city and creates the epoch, then welcomes.
- A sparse tree of up to `2^24` leaves split into districts under a city;
  a parent node is blank exactly when its subtree is empty; taints record
  who drew each node's secret, and removing or updating a member re-keys
  every node it drew.
- Multi-path re-key plans that anyone can recompute from public data.
- The key schedule of MLS with the window's root secret: init chain,
  joiner secret, confirmation tag, transcript hashes, external init.
- Registry of admins and two sparse Merkle maps (devices, used admissions);
  an admission admits once.
- Admissions by admins or invites, anchored joins on admin checkpoints,
  replay, jump and re-entry for returning members.
- A group with no member online: an entrant seals the window with an
  external init; recorded removals are enforced at delivery until the first
  participant applies them; eviction only under an admin-signed policy.
- Open groups: an admin-signed policy lets any device join with its own
  signed request; every join stays visible.
- Sampled audits of the entries of a window, with transferable fraud
  proofs.
- One packet per member and window; seal links and entries for joiners and
  returning members.

### Implementation

- `cityg-core`: the protocol core without I/O and an in-memory delivery
  service; 22 scenario tests on whole groups and a scale test that matches
  the cost model's count of wraps and keys.
- `cityg-pqc`: ML-DSA-65 (FIPS 204) with one context per signed object.
- Symbolic model ([`docs/formal/`](docs/formal/)): 16 ProVerif scenarios.
- Research note, cost model and primitive benchmarks
  ([`docs/research/`](docs/research/)).

### Not yet

The message plane, the networked delivery service and the clients, test
vectors, and the other open items of the specification (section 19).
