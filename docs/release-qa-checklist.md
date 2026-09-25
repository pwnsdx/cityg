# Release QA checklist

## Build and tests

- [ ] `./scripts/ci/local-ci.sh` passes (format, strict clippy, workspace
      tests, server-blindness guardrail, independent vectors when Python and
      `blake3` are available, Worker `wasm32` check, GUI tests, release
      builds, Docker image).
- [ ] The CI workflow is green on the release commit, including the nightly
      chaos campaign and the symbolic model of the last days.
- [ ] Coverage did not drop (`cargo llvm-cov nextest --workspace --features
      cityg-gui/native-app --profile ci --summary-only`).
- [ ] [security-review-checklist.md](security-review-checklist.md) is done.

## End to end

With a fresh `cityg-api` (and, for Worker releases, a staging Worker):

- [ ] Two GUI instances (`CITYG_GUI_CONFIG_DIR` apart): create a room, copy
      the invite link, join, exchange messages both ways, compare the
      security codes.
- [ ] A third member joins with the same link while the others are offline,
      then everyone syncs and agrees.
- [ ] An admin expels a member: the member is told, can no longer send,
      and the others keep talking.
- [ ] A member leaves: another member's maintenance commits the removal.
- [ ] **PCS refresh** moves to a new epoch; messages of the previous epoch
      still decrypt during the grace window.
- [ ] Restart the server with a `state_path`: rooms, logs and sessions
      recover (sessions may need to be reopened; the clients do it).
- [ ] Restart a GUI: the session restores and does not resend with a spent
      generation.
- [ ] `cargo run -p cityg-stress -- --final-capacity-check` completes with no
      failed round.

## Release

- [ ] Versions and `CHANGELOG.md` updated; the profile identifier matches
      [`specs.md`](specs.md).
- [ ] Docker image built from the release commit; health probes answer.
- [ ] Release notes restate the security claims and limits of
      [SECURITY.md](../SECURITY.md).
