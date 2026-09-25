# City-G documentation

City-G's current protocol is profile **`city-g/v0.3`**. The normative
reference is the [specification](specs.md); everything else here explains,
operates or checks it. The specification of the former profile v0.2 is
archived in [`legacy/v0.2/`](legacy/v0.2/specs.md), and the documentation of
profile v0.1.4 in [`legacy/v0.1.4/`](legacy/v0.1.4/README.md).

## Protocol

| Document | Content |
| --- | --- |
| [specs.md](specs.md) | Normative specification: threat model and security properties, cryptographic suite, encodings, ratchet tree and leaf proofs, registry, key schedule, commits, admission, joins and welcomes, message plane, delivery-service rules, light members, parameters, registries. |
| [design-v0.3.md](design-v0.3.md) | Why profile v0.3 changed what it changed (decisions D-1 to D-9), their costs, and what was left out. |
| [formal/](formal/) | Symbolic model of the key schedule, joins and welcomes, removal, admission, key rotation and messages, with the security lemmas of specs.md section 2. |
| [../kat/](../kat/README.md) | Conformance vectors, their independent verifier, and the requirement-to-test manifest. |
| [workflows.md](workflows.md) | Sequence diagrams: create, invite and batched join, send, leave, remove, concurrent commits, resync, key rotation, light members. |
| [fingerprints.md](fingerprints.md) | The security code and the tree and registry hashes, and what comparing them proves. |
| [GLOSSARY.md](GLOSSARY.md) | Terms of the specification. |

## Using and integrating

| Document | Content |
| --- | --- |
| [gui-user-guide.md](gui-user-guide.md) | The desktop client: create, invite, join, chat, administer, leave. |
| [api-reference.md](api-reference.md) | The `/v3` delivery-service API, its errors, and the Rust member drivers (full and light). |
| [configuration.md](configuration.md) | Configuration files and environment variables. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Symptoms, causes, fixes. |

## Operating

| Document | Content |
| --- | --- |
| [deployment.md](deployment.md) | Native server and Cloudflare Worker, one writer per room, storage, capacity. |
| [examples/](examples/README.md) | Docker Compose, systemd, Kubernetes, Prometheus and Grafana samples. |
| [OBSERVABILITY.md](OBSERVABILITY.md) | Logs, metrics, health probes, load testing. |
| [release-qa-checklist.md](release-qa-checklist.md) | Release gate. |
| [security-review-checklist.md](security-review-checklist.md) | Security review of a change or a release. |

## Audits

| Document | Content |
| --- | --- |
| [audits/audit-crypto-conformite-2026-09-25.md](audits/audit-crypto-conformite-2026-09-25.md) | Cryptographic and conformance audit of profile v0.1.4 (in French), its proposals P-1 to P-8, and the status of each finding after the move to v0.2; profile v0.3 keeps those fixes. |
| [audits/](audits/README.md) | Earlier audits, kept as written. |

## Design notes

| Document | Content |
| --- | --- |
| [gui-material-system-roadmap.md](gui-material-system-roadmap.md) | Visual design direction of the GUI. |
