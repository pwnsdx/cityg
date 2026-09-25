# City-G documentation

City-G's current protocol is profile **`city-g/v0.2`**. The normative
reference is the [specification](specs.md); everything else here explains,
operates or checks it. Documentation of the former profile v0.1.4 is
archived in [`legacy/v0.1.4/`](legacy/v0.1.4/README.md).

## Protocol

| Document | Content |
| --- | --- |
| [specs.md](specs.md) | Normative specification: threat model and security properties, cryptographic suite, encodings, barrier tree, key schedule, commits, admission, message plane, delivery-service rules, parameters, registries. |
| [formal/](formal/) | Symbolic model of the key schedule, tree, removal and admission, with the security lemmas of specs.md section 2. |
| [../kat/](../kat/README.md) | Conformance vectors, their independent verifier, and the requirement-to-test manifest. |
| [workflows.md](workflows.md) | Sequence diagrams: create, invite and join, send, leave, remove, concurrent commits, resync. |
| [fingerprints.md](fingerprints.md) | The security code and roster hash, and what comparing them proves. |
| [GLOSSARY.md](GLOSSARY.md) | Terms of the specification. |

## Using and integrating

| Document | Content |
| --- | --- |
| [gui-user-guide.md](gui-user-guide.md) | The desktop client: create, invite, join, chat, administer, leave. |
| [api-reference.md](api-reference.md) | The `/v2` delivery-service API, its errors, and the Rust member driver. |
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
| [audits/audit-crypto-conformite-2026-09-25.md](audits/audit-crypto-conformite-2026-09-25.md) | Cryptographic and conformance audit of profile v0.1.4 (in French), its proposals P-1 to P-8, and the status of each finding after the move to v0.2. |
| [audits/](audits/README.md) | Earlier audits, kept as written. |

## Design notes

| Document | Content |
| --- | --- |
| [gui-material-system-roadmap.md](gui-material-system-roadmap.md) | Visual design direction of the GUI. |
