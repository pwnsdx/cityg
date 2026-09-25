# Room-Scoped Administration Redesign

Status: Accepted design direction

Date: 2026-03-24

## Purpose

This document captures the agreed redesign for room administration in CityG.

It exists to replace the current "global admin token for room operations" model
with a room-scoped governance model that is safer for public rooms, easier to
operate, and aligned with the protocol's trust boundaries.

This note is intended to be a stable reference for:

- future spec updates
- API and server changes
- GUI and client implementation
- security reviews
- migration planning

## Executive Summary

CityG public rooms should remain open to participation without giving ordinary
members the ability to damage room governance or provisioning state.

The new model is:

- the creator is the initial room admin
- room admin authority is tied to a persistent room-scoped cryptographic
  identity, not to an alias and not to a global server token
- ordinary members can perform only member actions
- room governance actions are room-admin only
- server/operator admin tokens remain only for server/operator endpoints
- protocol maintenance that is required for liveness should not depend on a
  discretionary admin action when that can be avoided

The key design rule is:

> Public admission does not imply public control.

## Problems with the Current Model

The current room control model relies on a global header token:

- `x-cityg-admin-token`

That token is currently used for room-scoped control-plane endpoints such as:

- `/v1/rooms/bootstrap`
- `/v1/rooms/rotate_kbroad`

This creates several problems:

1. It is not room-scoped.
   One secret can control every room on a server.

2. It is operationally awkward for public rooms.
   The GUI/client needs special environment configuration to perform room
   operations that should conceptually belong to the room creator.

3. It is not aligned with user expectations.
   Users expect "the creator/admin of this room" rather than "whoever has the
   server secret".

4. It conflates server operator authority with room governance authority.
   These are different trust domains.

5. It does not compose well with public-room security.
   For public rooms, ordinary members must not be able to break the room, but
   that does not imply that room control should be delegated to a server-global
   token.

## Security Goals

The redesign must satisfy these goals:

1. Ordinary members must not be able to damage room governance or room control
   state.

2. Aliases must never be a source of authority.

3. Room administration must be room-scoped, not server-global.

4. Rejoining with the same alias but a different identity must not silently
   inherit admin rights.

5. A creator who leaves and later rejoins from the same persisted room identity
   should retain admin rights.

6. Protocol liveness should not depend on discretionary manual actions by
   ordinary members.

7. Over time, the system should become more resistant not only to malicious
   members, but also to malicious admins.

## Non-Goals

This redesign does not attempt to solve all governance problems in one step.

It does not, by itself:

- provide social recovery
- guarantee resistance to a malicious sole admin
- introduce quorum or multisig governance in the first version
- reserve a public room before the first creator claims it

Those can be layered later.

## Core Design Decision

### 1. Separate Operator Admin from Room Admin

Keep the global server admin token only for operator/server endpoints, such as:

- server config
- debug endpoints
- deployment/maintenance operations

Room-scoped governance must no longer depend on that token.

### 2. Creator Becomes Initial Room Admin

The first successful creator/provisioner of a room becomes its initial room
admin.

For an unclaimed room, the first successful room bootstrap/provisioning action
is equivalent to room creation.

### 3. Room Admin Is Bound to a Persistent Room Identity

Room admin authority is bound to a persistent room-scoped cryptographic
identity.

In practical terms for the current codebase, this should be the persisted
room identity public key currently represented by the membership PoP key
material, but reused across rejoins for the same room.

Important consequences:

- admin is not tied to alias text
- admin is not tied to a temporary session
- admin is not tied to a server-global secret
- admin is scoped to one room

### 4. Alias Is UX Only

Aliases remain a usability feature and a TOFU/account-labeling mechanism.

They are not an authorization principal.

The system must never grant or infer admin privileges from:

- alias equality
- alias history
- alias re-registration

## Identity Model

### Chosen Model

Use a persistent room-scoped identity per client per room.

This means:

- joining room A and room B may use different persisted identities
- rejoining room A from the same client should reuse the same persisted room-A
  identity

This is preferred over a single device-global identity because it reduces
cross-room linkability and keeps governance local to the room.

### Why Not Alias-Based Admin

Alias-based authority is not acceptable because aliases are:

- human-readable and easy to imitate
- intentionally reusable
- not a proof of device continuity

### Why Not Global Server Token for Room Control

A server-global token is an operator primitive, not a room-governance
primitive.

Using it for room administration couples all rooms together and creates a poor
fit for public-room UX and trust.

## Role Model

### Roles

There are four distinct authority classes:

1. Server operator
2. Room admin
3. Ordinary room member
4. Automatic protocol/server maintenance

### Permission Matrix

| Operation | Server operator | Room admin | Member | Automatic/server-managed |
| --- | --- | --- | --- | --- |
| Server debug/config endpoints | Yes | No | No | No |
| Create/claim unprovisioned room | No | Initial creator only | No | No |
| Join public room | No | Yes | Yes | No |
| Leave room | No | Yes | Yes | No |
| Send/fetch messages | No | Yes | Yes | No |
| Epoch sync / recovery | No | Yes | Yes | No |
| PCS refresh / join finalize | No | Yes | Yes, protocol-constrained | No |
| Grant room admin | No | Yes | No | No |
| Revoke room admin | No | Yes | No | No |
| List room admins | No | Yes | Optional read-only | No |
| Room policy/governance changes | No | Yes | No | No |
| KBROAD rotation | No | No in target state | No | Yes |
| Window/config debug APIs | Yes | No | No | No |

## Important Boundary: Governance vs Protocol Maintenance

Not every action that influences room state should become "admin only".

This distinction is critical:

- Governance actions should be admin-only.
- Protocol actions required for normal operation must remain available to
  members, but must be protocol-safe under malicious-member assumptions.

Examples of governance actions:

- grant/revoke room admin
- room policy changes
- room ownership and moderation actions

Examples of protocol actions:

- join finalize
- PCS refresh
- epoch sync
- normal message flows

These protocol actions should be hardened against malicious members rather than
being gated behind admin privileges. Otherwise a single admin becomes a
liveness bottleneck.

## KBROAD Decision

### Final Direction

`rotate_kbroad` should move out of the public/admin UI path and become
automatic or server-managed.

Reason:

- it is maintenance required for protocol liveness
- making it a member action lets members interfere with room maintenance
- making it an admin-only manual action makes liveness depend on discretionary
  admin intervention

Target state:

- no ordinary member can manually trigger room-critical provisioning changes
- no room admin needs to manually babysit KBROAD rotation during normal use

### Transitional Reality

During migration, the endpoint may remain temporarily, but the target model is:

- remove manual dependence from normal GUI flows
- internalize the operation into server/protocol logic where feasible

## Room Admin Lifecycle

### Room Creation

When a room is first claimed/provisioned:

- the creator signs the creation/claim request with the room-scoped identity
- the server stores that identity as the initial room admin

### Rejoin

When the creator rejoins the same room from the same persisted room identity:

- the room admin role is retained

When the same alias rejoins using a different identity:

- the room admin role is not inherited

### Delegation

A room admin can delegate admin rights to another room identity.

The delegation target should be:

- a room-scoped public identity key
- preferably an identity already observed in the room membership records

### Revocation

A room admin can revoke another room admin.

A room admin can also expel another current member from the room. That action
is distinct from admin-role revocation: it authorizes a revocation-style MERGE
against a target member leaf.

Leaving a room should not implicitly revoke room admin rights by default.
Governance rights and current membership are separate concepts.

However, some future policy may choose to require current membership for certain
admin actions. That is an implementation policy question, not the core identity
model.

### Device Loss

If the creator loses the device before delegating admin:

- there is no automatic recovery in v1

This is an acceptable first-version tradeoff, but it should be documented.

## API Direction

### Remove Global Token Dependence from Room Endpoints

Room endpoints should stop depending on `x-cityg-admin-token`.

In particular:

- `/v1/rooms/bootstrap`
- `/v1/rooms/rotate_kbroad` (target: internalized or removed from public API)

### Add Room-Scoped Auth for Governance

Introduce signed room-admin requests using a room-scoped identity.

This likely means a new signed payload type, for example:

- action kind
- room id / gid
- target identity (if applicable)
- timestamp / nonce
- signature by the room admin identity

The existing `IdentityBinding` concept is useful background, but it is not
sufficient by itself for arbitrary signed admin actions.

### New Endpoints

Expected room-governance endpoints:

- `POST /v1/rooms/grant_admin`
- `POST /v1/rooms/revoke_admin`
- `POST /v1/rooms/list_admins`
- `POST /v1/rooms/expel_member_ticket`

Optional later endpoints:

- `POST /v1/rooms/update_policy`
- `POST /v1/rooms/transfer_owner`

## Server State Model

The server should store room governance metadata per room:

- creator identity
- set of room admin identities
- creation timestamp
- governance metadata version
- optional audit trail of admin changes

This state should be journaled/persisted with the room so that it survives
restart and remains room-scoped.

## Client and GUI Changes

### Persist Room Identity

The GUI/client must stop generating a fresh room identity on every join.

Instead it should:

- generate a room-scoped identity for a room on first join/create
- persist it locally
- reuse it on rejoin for that same room

### Remove Normal Need for `CITYG_CLIENT_ADMIN_TOKEN`

Normal room creation and room management in the GUI should not require
`CITYG_CLIENT_ADMIN_TOKEN`.

That environment variable should become an operator/testing mechanism only, not
a normal product requirement.

### Expose Room Admin State in the GUI

The GUI should eventually show:

- whether the local user is a room admin
- the list of room admins
- delegation/revocation controls
- clear errors when a governance action is unauthorized

## Migration Plan

### Phase 1: Persist Room-Scoped Identity

- persist the room identity keypair locally
- reuse it on rejoin
- keep current behavior otherwise

### Phase 2: Add Room Admin ACL

- server stores `room_admins`
- first creator becomes initial admin
- room admin actions use room-scoped signatures

### Phase 3: Decouple Room Endpoints from Global Token

- remove global token requirement from room-governance endpoints
- keep operator token only for operator/debug endpoints

### Phase 4: Internalize KBROAD Maintenance

- stop requiring manual room control for KBROAD maintenance
- move rotation and related liveness operations toward server-managed behavior

### Phase 5: Optional Hardening Against Malicious Admins

Possible future additions:

- 2-of-N admin approval for destructive actions
- delayed admin actions with cancellation window
- recovery/guardian model
- admin action audit log surfaced to clients

## Open Questions

These are not blockers for the core decision, but they should be resolved
during implementation:

1. Should room admin actions require current membership, or only possession of
   the room-admin identity?

2. Should `list_room_admins` be visible to all members or only admins?

3. What is the minimum viable signed admin-action envelope format?

4. Do we want a distinguished "owner" role in addition to a generic
   `room_admins` set, or is "creator as first admin" sufficient?

5. What recovery story is acceptable if the sole admin loses the device before
   delegation?

## Implementation Guidance

If implementation starts immediately, the recommended order is:

1. persist room-scoped identity in the GUI/client
2. create server-side room admin metadata
3. make the creator the initial room admin on first room claim
4. add grant/revoke/list admin endpoints
5. remove global-token dependence from room control
6. move KBROAD maintenance toward automatic/server-managed behavior

## Current Code References

The current system pieces relevant to this redesign are:

- `crates/cityg-api/src/lib.rs`
  - room admin token enforcement
  - `/v1/rooms/bootstrap`
  - `/v1/rooms/rotate_kbroad`
  - `/v1/config/window`
- `crates/cityg-api-client/src/lib.rs`
  - `x-cityg-admin-token` client behavior
  - room endpoint classification in `requires_admin_token`
- `crates/cityg-gui/src/native.rs`
  - auto-bootstrap join flow
  - current `CITYG_CLIENT_ADMIN_TOKEN` handling
  - current room-join identity generation
- `docs/specs.md`
  - protocol rules around barrier updates, pending recovery, and bootstrap

## Final Decision Statement

CityG public rooms will use room-scoped cryptographic administration.

The creator will be the initial room admin.

Room admin authority will be tied to a persistent room-scoped identity, never
to alias text and never to a server-global room token.

Ordinary members must not be able to damage room governance or provisioning
state.

Protocol maintenance required for liveness should be hardened and automated
where possible, rather than turned into a discretionary manual admin workflow.
