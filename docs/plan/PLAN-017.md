# PLAN-017 Keynet-proto wire and derivation primitives for keynet v0.7

- **status**: completed
- **createdAt**: 2026-09-13 03:55 UTC
- **approvedAt**: 2026-09-13 04:09 UTC
- **delivery**: keynet-v1-20260913
- **designRevision**: `docs/ns/keynet.md` in the documentation repository at commit `7f6090d340bb22d2c61f992e5e7b72666e21ae3e` (v0.7 clarification), SHA-256 `82818d8345c81736a7c8d65c82d07e3c785ac9d542ef0b1ef2acca3a51378e76`
- **builtAgainst**: phase 1 was built against v0.4; completed phases retained their reviewed vectors across later compatible revisions; see Design revisions below
- **deliveryState**: implementation resumed on 2026-09-13; the v0.7 clarification at docs commit `7f6090d340bb22d2c61f992e5e7b72666e21ae3e`, SHA-256 `82818d8345c81736a7c8d65c82d07e3c785ac9d542ef0b1ef2acca3a51378e76`, is the active pin for remaining work
- **integrationBranch**: `feat/keynet` in the canonical `ns-shared` checkout (the dedicated clone's `main` was restored to `d02a29c`)
- **updatedAt**: 2026-09-13 13:03 UTC

## Context

The repository needs an independent `keynet-proto` workspace crate containing
the pure wire, cryptographic derivation, validation and fixture primitives for
keynet v0.7. It must not depend on existing internal crates, an async runtime,
networking or production filesystem access.

The authoritative design is the English keynet document named above. Its
normative section 13, Wire Profile, controls every byte-level question where
it differs from earlier prose. The external design checkout remains read-only
during implementation. Each implementation phase and the final fixture manifest pin the
same revision digest until an explicitly approved later revision replaces it.

## Approved decisions

1. Add the smallest root workspace lint table: `warnings` is denied and
   `unsafe_code` is forbidden. Only `keynet-proto` opts into it; existing
   member manifests and root quality-gate configuration remain unchanged.
   The new crate enforces missing documentation and runtime
   panic/unwrap/expect restrictions locally.
2. Keep implementation-facing plan and task tracking in
   `crates/keynet-proto/docs/plan/` and `crates/keynet-proto/docs/task/`.
   The root plan index links to this project plan only.
3. KeyBinding uses ordinary Ed25519 over `keynet/key-binding/v1` immediately
   followed by the canonical unsigned seven-field CBOR array. Validity is
   `not_before <= now < not_after`; generation state is scoped by
   `(network_id, I)` and uses committed generation plus optional
   revoked-through state. Equal generation with a distinct key latches a
   conflict.
4. PairingToken uses the normative twelve-field profile, including optional
   `issuer_name` directly after the binding. Its signature is ordinary
   Ed25519 over `keynet/pairing-token/v1` followed by the canonical unsigned
   eleven-field array. HKDF has absent salt; token text is capped at 1024
   bytes and each text field at 255 bytes.
5. INTRO is the six-field array of v0.7 section 13.5, naming the token by
   `token_id` (SHA-256 of the canonical signed PairingToken) and carrying a
   caller-supplied 32-byte nonce; its MAC covers the five-field section 13.2
   transcript including `token_id`. INTRO_ACK is the normative five-field
   array with its separate `keynet/intro-ack/v1` MAC context. Token lookup by
   `token_id`, nonce generation and replay storage remain caller
   responsibilities.
6. H22, alias candidates and label normalization follow section 13.4. The
   PairingToken `issuer_name` supplies the device name used by the default
   nickname behavior.
7. NameRecord uses the section 13.2 owner and network signature contexts,
   fixed operation tags, and its specified equal-version behavior.
8. Relay datagrams use sections 13.5 and 13.6 of v0.5, which replaced the
   v0.4 length-framed stream profile: a fixed 37-byte header (magic `KNR1`,
   type, 16-byte `src` and `dst` slot ids), a 2048-byte datagram cap and a
   1200-byte cap for control types, canonical CBOR bodies for every type
   except DATA, the direction rules per type, the REGISTER signature context
   `keynet/relay-register/v1`, the session key `sk` (HKDF-SHA256 over the
   ephemeral X25519 shared secret with `reg_hash`), the control and reply MAC
   contexts `keynet/relay-ctl/v1` and `keynet/relay-reply/v1` over
   `[magic, type, src, dst, unsigned_body]`, the slot id (keyed BLAKE2s-16,
   `keynet-relay-slot-v1`, zero reserved), STATUS codes 1-6, `observed_addr`
   encoding and all width, range, timestamp-window and counter rules. X25519,
   HKDF and MAC computations are pure helpers over supplied keys and
   caller-supplied state; sockets, timers, tentative-session storage,
   forwarding and the WebSocket carrier remain outside this crate.
9. This document and the fixture suite use the pinned authoritative revision;
   a later revision requires a recorded approval and a replacement digest.
10. The CLI interaction revision (design sections 1.1, 7.5, 7.6, 8, 11 and
    14; approved review `keynet-cli v1`) adds no crate scope. It is a
    metadata-only deviation, `affects=[1,2,3,4,5,6]`: only design-digest pins
    and fixture manifest metadata change.
11. The UDP relay revision (design sections 5, 6.6, 8, 9, 11, 12, 13.2,
    13.4, 13.5, 13.6 and 7.5 step 2; approved review `keynet-relay-udp v1`)
    is a substantive deviation, `affects=[5,6]`: phase 5 is re-specified
    against the datagram profile in decision 8 and phase 6 seals vectors
    against the current revision. Phases 2-4 keep their contracts and
    vector payloads; their pins change as metadata only.
12. The v0.6 consistency revision (docs commit `0f56552`) is a further
    approved substantive deviation, `affects=[3,5,6]`: phase 3 gains the
    `token_id` field in INTRO
    (decision 5); phase 5 additionally covers the Revocation record
    (context `keynet/revocation/v1`) and the section 13.7 in-band control
    record codecs (ACK, ENDPOINTS, BINDING, REVOCATION, NAME) as pure
    codecs with fixtures; phase 6 seals against v0.6. Phases 1, 2 and 4
    change as metadata only. The recovery root and statement records stay
    open in the design and are outside this plan.
13. The v0.7 revision (docs commit `7f6090d340bb22d2c61f992e5e7b72666e21ae3e`)
    resolves the recorded design gaps. Phase 4 adds the approved default-nickname
    and per-owner NameRecord version-stream behavior. Phase 5 is split: the
    unchanged relay datagram, cryptographic and Revocation portion may land
    first, followed by the v0.7 relay-identifier grammar, section 13.7 records
    and new section 13.6 limits. Phase 6 seals the complete v0.7 fixture set.

## Roadmap

| Phase | Name | Depends | Status |
|---|---|---|---|
| 1 | Independent crate and address/name derivation foundation | None | Merged: head `bf61531b19821e728702d359e18bec03bcdfdcab`; merge base `49c257d71ed7e0387febeefbf1ab1fb15524bbd0`; merged-tree QA passed |
| 2 | Canonical KeyBinding and generation decisions | 1 | Accepted against v0.6; focused, adversarial, crate, doctest, and repository quality gates passed |
| 3 | PairingToken, PSK and INTRO | 1, 2 | Completed against v0.6 with the six-field INTRO and `token_id` |
| 4 | Labels, alias candidates and NameRecord | 1, 2, 3 | Completed through the stateless 4A and stateful 4B parts |
| 5A | Stable relay datagram and Revocation primitives | 1, 2, 3, 4 | Completed; byte profile pinned to v0.6 and unchanged in v0.7 |
| 5B | Relay identifiers and in-band control records | 5A | Completed against v0.7; focused and crate gates passed, final repository gate recorded below |
| 6 | Interoperability fixture release and final acceptance | 1, 2, 3, 4, 5A, 5B | Completed against v0.7; sealed manifest and final repository acceptance passed |

Each phase receives adversarial testing and an acceptance review. Only one
phase runs at a time because build capacity is constrained. A phase is merged
only after a passing review, completed adversarial checks, no unresolved major
finding, no still-failing finding and a successful merged-tree quality gate.

## Scope and acceptance

The crate provides only pure functions, strict bounded codecs and tests that
read committed fixture data. It covers address derivation and group conflict
checks, KeyBinding, PairingToken, PSK, INTRO/INTRO_ACK, names, labels, alias
candidates, NameRecord, relay frames and byte-exact interoperability vectors.

The crate does not add networking, I/O beyond test fixtures, persistence,
async runtimes, existing internal-crate dependencies, runtime key generation,
connection handling, DNS services, relay services or changes to existing
crates. `just qa`, crate-focused nextest and crate doctests are required at
the applicable phase boundaries. All public functions document their keynet
design section; all code forbids unsafe code.

## Verification settings

- Merge gate: enabled when the documented adversarial checks and review
  conditions are met.
- Parallel phase limit: one.
- Debug escalation threshold: two unresolved normal attempts.
- Quality gate: `just qa`; its output must include the actual
  `keynet-proto` tests before a phase is credited.

## Phase status

Merge bases, branch heads, adversarial outcomes and final quality-gate evidence
are recorded here as phases begin and are merged.

### Phase 1: merged

- Adversarial finding R1 (major): the fixture inventory accepted empty, duplicate and
  unlisted cases. Fixed by explicit required case lists and pre-execution
  inventory validation; the original regression source is retained under
  `crates/keynet-proto/tests/refutation_inventory.rs`.
- Acceptance review passed at head `bf61531b19821e728702d359e18bec03bcdfdcab`.
- Merge base `49c257d71ed7e0387febeefbf1ab1fb15524bbd0`; merged-tree QA
  passed (719 tests, zero skipped, `KEYNET_QA_EXIT=0`).
- Delivered: address and identity-name derivation, owner-aware collision
  checks, committed fixture files and the manifest loader, pinned to v0.4.

### Phase 2: accepted

- Rework rounds R1-R3 were consolidated at `6091f10` and began on
  2026-09-13 05:26 UTC against the v0.4 pin. The work was paused before
  acceptance review of that head; no merged-tree QA record exists for it. The
  migration QA on `feat/keynet` (732 tests, `KEYNET_QA_EXIT=0`) verified
  preservation only and does not accept the phase.
- The tree is preserved on `feat/keynet` by merge `26711e6`. Task and plan
  records: `crates/keynet-proto/docs/task/phase-2-key-binding.md` and
  `crates/keynet-proto/docs/plan/phase-2-key-binding.md`.
- The `keynet-v1-20260913` resume revalidates the preserved bytes and behavior
  against v0.6, repairs only demonstrated phase-2 defects, re-pins phase-2
  metadata, and reruns focused and repository quality gates.
- Acceptance repaired the conflict transition so it retains the committed
  generation and key while the equal-generation disagreement is latched.
  Focused tests, literal vectors, authentication and codec refutations, crate
  nextest, crate doctests, and `just qa` passed; the repository gate ran 732
  tests with zero skipped and included the actual `keynet-proto` suites.

### Phases 3-4: completed

Phase 3 delivered PairingToken, PSK, and the six-field INTRO/INTRO_ACK profile.
Phase 4 delivered both the stateless naming primitives and the v0.7 stateful
default-nickname and per-owner NameRecord version-stream behavior.

### Phase 5B: completed

Phase 5B delivered strict canonical relay identifiers and endpoint hints, all
eight section 13.7 in-band control records, v0.7 constants and deterministic
ordered-snapshot selection. Fixed literal vectors, adversarial checks, the
80-test crate gate and the 789-test repository gate passed with zero skipped.
Acceptance repair added explicit `fec0::/10` rejection and greedy relay fitting
across the complete canonical input; focused and package gates passed.
The completed task record is
`crates/keynet-proto/docs/task/phase-5b-control-wire.md`.

### Phases 5-6

Phase 5 is split at the revision boundary. The completed 5A relay-wire and
Revocation portion is pinned to v0.6 and is unchanged in v0.7. Phase 5B
completed the v0.7 identifier grammar and canonicalization, section 13.7
in-band control codecs, and relevant section 13.6 constants. Phase 6 depends
on both parts and seals the final vectors against the active revision.

### Phase 6: completed

Phase 6 adds an implementation-independent release seal over the complete
twelve-file fixture set. The initial positive release test failed against the
pre-release manifest while its drift-rejection case passed. The completed
manifest carries the full design pin and exact file, case, and field inventory;
all normative vector files remain byte-identical to the accepted phase inputs.
The implementation-independent release test pins manifest SHA-256
`09c5184dfdd114151c6650c02eaca9d0710c6d321b1b5c72847d7fea506d13ea`
and rejects missing, duplicate, unlisted, non-regular, symlinked, corrupted,
and locally rehashed inputs. The full package passed 84 tests with zero skipped,
and the repository gate passed 793 tests with zero skipped. Formatting,
warning-denied lint, dependency policy, unused-dependency, typo, documentation,
and whitespace checks passed. No protocol, production, or dependency input
changed.

## Design revisions

| Date (UTC) | Revision | SHA-256 | Docs commit | Plan effect |
| --- | --- | --- | --- | --- |
| 2026-09-13 04:09 | v0.4 with section 13 Wire Profile | `7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f` | `b1c0db4` | Gate 1 approval; phases 1 and 2 pinned here |
| 2026-09-13 06:00 | CLI revision: sections 1.1, 7.5, 7.6, 8, 11, new 14 | `ff3337f1f9fa0d825fce505fde44d5a2b66bf60aeff02fca279f4343761df173` | `a4b98bc` | Metadata-only deviation, `affects=[1..6]`; not re-pinned before the pause |
| 2026-09-13 07:20 | v0.5: UDP relay carrier; sections 5, 6.6, 8, 9, 11, 12, 13.2, 13.4, 13.5, 13.6, 7.5 step 2; decision records merged into the design | `173d4bf3ed25125822210e17c56ae31e172168098af7209d1d3486a5629b624e` | `c5f8309` | Substantive deviation `affects=[5,6]` |
| 2026-09-13 08:25 | v0.6: consistency revision after a full review; section 13.7 in-band control records; `token_id` in INTRO; Revocation record; STATUS, budget, cutover and recovery rules; corrected PSK, recovery, directory, nickname, size and placement statements | `494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1` | `0f56552` | Approved substantive deviation `affects=[3,5,6]`; active pin for phases P2-P6 |
| 2026-09-13 11:08 | v0.7: resolved rotation, ordered endpoint, probe, DNS, relay, CLI and naming contracts; alias portability remains deferred | `ceeca74ab6dad33f34df36ef789c1d32014679c9592655439210c169b0bebce6` | `4ae04faa` | Approved substantive deviation `affects=[4,5,6]`; active pin for remaining phases |
| 2026-09-13 14:00 | v0.7 clarification: stage-specific relay budgets, greedy relay selection and empty display metadata | `82818d8345c81736a7c8d65c82d07e3c785ac9d542ef0b1ef2acca3a51378e76` | `7f6090d` | Active pin for remaining work; sealed fixture bytes and manifest remain unchanged at the prior v0.7 release pin |

The approved review records that produced the two revisions are archived
under `docs/decisions/keynet/`.
