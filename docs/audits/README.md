# Historical Audit Archive

These files preserve the language and assumptions that were current when each
audit was written.

Several audits predate the reusable-slot `v0.2` rollout and therefore still use
historical terms such as `cover_leaf_index` or `leaf_index`.

The audits before 2026-09-25 describe profile v0.1.4 and its implementation,
both replaced by profile v0.2; their "v0.2" is the slot-lease revision of the
v0.1.4 server, not the current profile. The current protocol is specified in
[`docs/specs.md`](../specs.md); the v0.1.4 documents they cite are archived in
[`docs/legacy/v0.1.4/`](../legacy/v0.1.4/README.md).

Do not treat archived audit wording as the canonical description of the current
protocol.

## Later audits

- [`audit-crypto-conformite-2026-09-25.md`](audit-crypto-conformite-2026-09-25.md)
  (French): cryptographic and code-versus-spec conformance audit of `71ee261`,
  with reproducible PoCs in [`poc-2026-09-25/`](poc-2026-09-25/) and proposals
  for a `v0.2` profile. It revisits several conclusions of
  `final-verification-report-2026-03-26.md`. Its last section records how each
  finding and proposal was addressed by profile v0.2.
