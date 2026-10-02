# Phase 4B stateful naming primitives task

## Status

Completed against keynet v0.7 at documentation commit
`4ae04faa06ca1f5d64e40aca58aa8e55a50c1e6e`, SHA-256
`ceeca74ab6dad33f34df36ef789c1d32014679c9592655439210c169b0bebce6`.

## Approved boundary

- Construct token-import default nicknames while preserving the H96 suffix,
  identity fallback, and reportable same-network collision outcome.
- Evaluate one pure NameRecord version high-water and conflict latch per full
  `(network_id, I)` owner stream.
- Keep transport, directory, resolver, alias allocation, persistence, and I/O
  deferred.

## RED and GREEN evidence

The first compiling focused test command failed with `E0432` for the new public
nickname and NameRecord state types/functions and `E0599` for the checked
record installation method. After implementation, the focused naming suite
passed 16 tests.

- Exact lowercase H96 suffix and 58-byte prefix preservation map to
  `default_nickname_preserves_exact_h96_suffix_and_prefix_boundary`.
- Empty/reserved fallback and collision without assignment map to
  `default_nickname_falls_back_and_reports_collision_without_assignment`.
- Cross-label owner-stream conflict scoping maps to
  `name_record_state_is_one_owner_stream_across_labels`.
- Lower-version rejection, canonical replay, conflict latch, latched rejection,
  and strictly higher recovery map to
  `name_record_versions_reject_replay_latch_and_recover_strictly`.
- Scope independence, `u64` boundaries, canonical decode, signatures,
  currentness, and unchanged rejected state map to
  `name_record_state_scopes_and_prevalidation_leave_state_unchanged`.

## Fixture evidence

No fixture bytes or manifest entries changed. Existing inventory integrity tests
passed. Relevant fixed hashes remain:

- `aliases.vec`: `0406dd0e60de7133e92323cdb3c391a17235b747cdd95a5167fb3d02ed6f3916`
- `labels.vec`: `2b0328e0c3fc700929d58dee51a1a3fbda48518f9304200a2ce3773fa86f5330`
- `name_records.vec`: `74584e2e68f2eaf382a63d4829b4ea9e92346bd37239208bba6a6e063d3a03e2`
- `manifest.txt`: `eeb36de13b752580ca634d027516deccfbf1dd77e488da874da969b9a407d716`

## Verification evidence

- `cargo test -p keynet-proto --locked`: passed (60 tests including one
  doctest).
- `cargo nextest run -p keynet-proto --locked`: 59 passed, 0 skipped.
- `cargo test -p keynet-proto --doc --locked`: 1 passed.
- `cargo clippy -p keynet-proto --all-targets --locked -- -D warnings`:
  passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- Repository `just qa`: 768 passed, 0 skipped; formatting, workspace Clippy,
  dependency policy, unused-dependency, and typo gates passed.
- Incremental Rust review: PASS with no high-confidence findings.
- No acceptance check was skipped. One pre-RED invocation could not locate
  Cargo through the non-login shell PATH; the installed Cargo executable was
  then used with the required build environment for the observable RED and all
  GREEN checks.

Before final acceptance the build volume had 106,485,168 KiB available; after
the repository gate it had 106,365,912 KiB. The cgroup memory limit was
25,769,803,776 bytes, anonymous memory changed from 2,963,304,448 to
2,738,196,480 bytes, and `oom_kill` remained 15.
