# Archive: profile v0.1.4 documentation

This directory keeps the documentation of City-G profile v0.1.4
(`tswe/msphf-we/fs-hybrid + prs-barrier`) and of its implementation, as it
was when profile v0.2 replaced it. It describes a protocol and code that no
longer exist in this repository:

* the anchors with several partial signatures, the SPHF / ME-OR layer,
  `E_k`, `K_fs`, KBROAD, the CAPSS and ZK-VRF transcripts, SRX witnesses and
  the multi-head window;
* the `/v1` HTTP API, the room admin and message tokens, join tickets and
  slot leases;
* the crates `msphf-*`, `capss`, `anchor-seed`, `cityg-client` and
  `cityg-api-schema`.

The [2026-09-25 audit](../../audits/audit-crypto-conformite-2026-09-25.md)
explains why the profile was replaced; the
[v0.2 specification](../../specs.md) (section 18) lists the changes. Nothing
here is normative, and v0.1.4 groups do not interoperate with v0.2.

| Content | Files |
| --- | --- |
| Specifications | [`specs.md`](specs.md) (v0.1.4), [`legacy-specs.md`](legacy-specs.md) (earlier drafts), [`spec-conformance-changelog-v0.1.2.md`](spec-conformance-changelog-v0.1.2.md), [`-v0.1.3`](spec-conformance-changelog-v0.1.3.md), [`-v0.1.4`](spec-conformance-changelog-v0.1.4.md) |
| Protocol companion | [`protocol/`](protocol/00-README.md), [`whitepaper/`](whitepaper/) |
| Guides | [`api-reference.md`](api-reference.md), [`configuration.md`](configuration.md), [`gui-user-guide.md`](gui-user-guide.md), [`workflows.md`](workflows.md), [`fingerprints.md`](fingerprints.md), [`GLOSSARY.md`](GLOSSARY.md), [`OBSERVABILITY.md`](OBSERVABILITY.md), [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) |
| Plans and status notes | [`constraints.md`](constraints.md), [`todo-migration-0.1.2.md`](todo-migration-0.1.2.md), [`todo-slot-leases-v0.2.md`](todo-slot-leases-v0.2.md) (slot leases of the v0.1.4 server, not profile v0.2), [`room-admin-governance-redesign.md`](room-admin-governance-redesign.md), [`WORKER_MIGRATION_TODO.md`](WORKER_MIGRATION_TODO.md), [`repo-cleanup-plan-2026-03-29.md`](repo-cleanup-plan-2026-03-29.md), [`legacy-surface-inventory-2026-03-30.md`](legacy-surface-inventory-2026-03-30.md), [`security-audit-status-2026-03-23.md`](security-audit-status-2026-03-23.md) |
| Validation | [`preproduction-validation.md`](preproduction-validation.md), [`client-state-hardening-audit-pack.md`](client-state-hardening-audit-pack.md), [`timing-verification.md`](timing-verification.md), [`evidence/`](evidence/), [`security-review-checklist.md`](security-review-checklist.md), [`release-qa-checklist.md`](release-qa-checklist.md) |

The known-answer files of that profile are in
[`kat/legacy/v0.1.4/`](../../../kat/legacy/v0.1.4/). Links inside these
documents point to paths of the v0.1.4 tree; the tree itself is in the git
history (for instance commit `71ee261`, the audited revision).
