# 20261110-0525-relay-epoch-request-contract Relay attribution epoch request contract

- **status**: completed
- **createdAt**: 2026-11-10 05:25
- **approvedAt**: 2026-11-10 06:30
- **relatedTask**: 20261110-0628-relay-epoch-contract

## Context

A shared contract change is necessary for **two** reasons: participant sessions have no fresh-epoch operation, and the Attribution specification currently requires unchanged identity/class membership to reuse its epoch. The proposed same-custody recovery exception must be explicit. It does not require a new roster, DATA, usage-report or retention-seal schema.

Reviewed checkout main `f8589f9cc9508115cf7858352cfdc5d9cd2b9d4f`; NSD `e89764c332ecde608aa375b0c1ad2cd8754134cd` and nsgw `cc9a284868e53dda4e4292b6794fbb8e000a5c41` both lock nsshared-control v0.9.0 to `9c0ee7305eff4a5566f169d6e26b710a5709944c`. The inspected roster/retention implementations and specifications match at both shared revisions. Sources: both consumers' `Cargo.lock`; `/workspace/warehouse/nsiod2/loc-rr1-epoch/source-evidence.txt` (Shared contract pin).

- `session.rs` defines frame kinds 1 through 10; unknown kinds are rejected. Pair/correlation handling, exact lengths, header bounds and authenticated metadata version 2 are closed contracts. `FrameKind` is exhaustive, so adding variants can break downstream Rust matches. Sources: `crates/nsshared-control/src/account/families/relay/session.rs` (`FrameKind`, `Frame`, `PendingResponse`, `validate_header`); `docs/spec/account/relay.md` (Frames, Bounds, Authorization).
- Signed roster schema 2 already separates positive publication and attribution counters, with no general numerical ordering between them. Verification uses independent persisted floors and forbids epoch decrease. Source: `relay/roster.rs` (`Roster::validate`), `relay/participant_roster.rs` (`SignedRoster::verify_generation`), `docs/spec/account/relay.md` (Attribution, Verification); `docs/plan/20261028-2141-roster-attribution-epoch.md`.
- Capture interruption has no shared incomplete manifest. Absence of a seal already represents incomplete coverage, not zero usage. A complete seal cannot be extended after shutdown or synthesized for lost bytes. Source: `docs/spec/account/usage.md` (Retention seals and acknowledgements); `crates/nsshared-control/src/account/families/usage/retention.rs` (`RetentionSeal`, `RetentionSealAck`).
- Saved lab epoch 173 stayed incomplete while a global 174 restored forwarding; healthy relays closed 173 independently. The workaround changed custody generation and is not the proposed contract. Sources: `/workspace/warehouse/nsiod2/lab-l2-l3/l5-run-r7/report.md`, `/workspace/warehouse/nsiod2/lab-l2-l3/rr1-epoch-replace/report.md`, `/workspace/warehouse/nsiod2/loc-rr1-epoch/report.md` (Attribution epoch allocation and lifetime).

`account` is now unconditional and semver-covered, unlike the older opt-in state described in the attribution-epoch plan. Sources: `crates/nsshared-control/src/lib.rs`, `docs/architecture.md` (account boundary), `justfile` (`semver`). Versioning below therefore does not rely on the former unstable-account exception. No repository-level CLAUDE.md or AGENTS.md exists in this checkout; workspace instructions and the current PMA format apply.

## Proposal

### 1. Explicit same-custody recovery exception

Revise Attribution: ordinary unchanged-model refreshes reuse the epoch; a validated, audited, bounded fresh-epoch command may advance it without membership/class/provenance or custody changes. The current NSD implementation uses a global epoch and republishes all recipient projections; recipient-only allocation is not introduced. Publication and attribution floors remain independent, positive and monotonic according to the existing contract, without imposing NSD's counter relationship on every producer.

A recovery result never grants DATA authority, extends credential/roster validity, acknowledges usage, closes an epoch, resets a floor, or changes custody. The relay adopts an epoch only from a separately verified signed roster under authenticated custody, after durable observation. Historical reports keep their original epoch, classes, bytes, generation and digest. Interrupted epochs remain incomplete by permanent absence of a seal; no incomplete-seal sentinel or new report outcome is added. A normal stop persists the final cut and leaves the current epoch reusable.

### 2. Two new, strictly versioned participant frame kinds

Reserve proposed wire bytes 11 (`EpochRequest`) and 12 (`EpochResult`), subject to confirming they remain unused when implementation begins. Keep the existing `length_u32_be || kind_u8 || body` carrier and all ten existing kind encodings, signatures/domains and authentication-answer version 2 byte-identical. New bodies use fixed-order concatenation with big-endian u64 fields:

| Kind | Exact body layout | Body length |
| --- | --- | --- |
| 11 EpochRequest | issuer32, recipient32, correlation16, format_version1 (=1), owner_generation8, fenced_epoch8 | 97 bytes |
| 12 EpochResult | issuer32, recipient32, correlation16, format_version1 (=1), owner_generation8, fenced_epoch8, outcome1, result_epoch8, publication_version8, retry_not_before_unix_ms8 | 122 bytes |

The sole request meaning in version 1 is `interrupted_capture`; there is no free-form reason, custody override, requested new counter or alternate recipient. Keys must pass existing strict validation; correlation must be nonzero; generation and fenced epoch must be positive. Reject wrong versions, zero mandatory fields, wrong lengths, unknown outcomes, trailing bytes and invalid field combinations both on construction and decode. Header validation checks kind-specific lengths before body allocation; existing MAX_FRAME_BODY stays unchanged.

Proposed outcome bytes are 0 `Allocated`, 1 `AlreadyFresh`, 2 `RateLimited`, 3 `StaleCustody`, 4 `InvalidEpoch`, 5 `Unavailable`. For 0/1, result epoch must exceed the request's fenced epoch and publication version must be positive; retry time is zero. For 2, result epoch/publication are zero and retry time is positive (not-before time for the next allocation attempt, rechecked against the supplied clock). For 3/4/5, all result/retry fields are zero. Unknown outcome bytes are invalid. Do not impose an epoch-versus-publication ordering absent from schema 2. A successful result may describe an older committed decision on idempotent replay; it does not assert that its publication is currently live or latest.

Expose dedicated pure request/result and pending-response types through `account::relay`, with constructors, canonical encode/decode and `validate_for` checks for exact kind, pair, correlation, generation and fenced epoch. Keep epoch pending state distinct from renewal `PendingResponse` to prevent cross-operation correlation. The result's pair/generation echo the pending command even on `StaleCustody`; they are not newly authenticated metadata. Its validation consumes no credential deadline and cannot authorize a generation update. Pure codec validation never establishes an authenticated session or decides allocation/quota/audit.

### 3. Authenticated order and semantic idempotency

A runtime may send kind 11 only after successful Enroll/Authenticate on verified TLS for the exact pair. The existing exporter proof establishes session identity; an extra per-request signature or proof domain is unnecessary. NSD binds the session's accepted owner generation, checks the body against it and current enrolled/valid/enabled custody in the allocation transaction, and allows only the participant's own recipient. Operator platform authorization is a separate NSD HTTP contract, not a shared bearer credential.

The semantic idempotency key is `(issuer, participant custody id, recipient, owner_generation, fenced_epoch)` in authority storage. Correlation matches one pending transport exchange and may change on retry/reconnect; it never permits a second allocation. The wire need not expose custody id because NSD resolves it from the authenticated participant. A naturally newer or concurrently allocated current epoch satisfies the same request. Authentication is checked again on replay, so an old successful command does not grant a revoked session access.

A valid success is sent only after epoch/history/signing/audit and the command receipt commit. RateLimited and Unavailable grant no authority and may be retried with the same semantic intent; they are not successful allocation receipts. StaleCustody and InvalidEpoch require reauthentication/diagnosis rather than changing counters. An unauthorized pair or operation before authentication retains the existing generic Refused/close behavior, without a data-leaking typed result. No result claims proof that the relay truly crashed; dishonest self-reports are bounded by the authority's policy.

The sole session driver may interleave Roster, existing report/seal Answer, Renewed and EpochResult. Keep at most one outstanding epoch request, bounded queues, exact correlation, single consumption and no second stream reader. Roster may arrive before or after EpochResult. Duplicated/unsolicited/wrong-scope results are refused; a lost response permits an idempotent retry, never local epoch adoption. Stopping cancels the exchange without undoing an authority commit.

### 4. Versioning and compatibility

Plan a new nsshared **0.10.0 minor release** (or the next available 0.x minor chosen by its maintainer), not an in-place v0.9.0 tag rewrite or patch masquerading as source compatible. Adding variants to the exhaustive public `FrameKind` may require downstream match updates; account is now semver-covered by default. Update the migration/API inventory with concrete consumer call sites and decoder support. Run the existing semver gate with the deliberate minor transition and record its actual result; never suppress it as an unstable-account change.

Old peers reject kinds 11/12. Use producer-first rollout: NSD accepts kind 11 only when requested and never sends unsolicited kind 12, so old relays continue existing traffic. Upgrade authority before enabling new requesting consumers. No protocol guessing, negotiation, downgrade frame, overloaded Renew/Report body, or fallback custody mutation is added. A new relay encountering an old authority stays fenced with an explicit incompatibility diagnostic; deployment rollback must not place such relays behind an unsupported authority. Publish the approved shared release to `git.pvv.cc/nsiod/nsshared`; consumers pin that remote immutable release/full resolved commit in their manifests and locks, including standalone e2e workspaces. No sibling path dependency or local patch is permitted.

## Risks

- These are new closed wire kinds and potentially source-breaking exhaustive enum additions. Existing decoders cannot accept them; an additive specification does not make mixed-version requesting deployments safe. Preserve all old bytes and upgrade the authority first.
- A correlated EpochResult can be mistaken for roster authority or custody metadata. Keep dedicated types and validate exact pending context; success cannot update a floor or deadline and must not be accepted as a usage/seal ACK.
- Global recovery permits bounded unrelated publication/history churn. The pure contract can describe policy obligations, but cannot enforce rate limits, prove local interruption, store audit or make a database transaction. Those remain NSD runtime responsibilities.
- A request arriving on an old-but-open session after generation replacement must not act under current custody simply because the pair matches. Bind accepted session generation and recheck it transactionally; the body supplies an expectation, never new authorization.
- A delayed successful result can outlive its roster validity or be overtaken by newer publication. Consumers use independently verified latest rosters and retain monotonic floors. Never recreate or re-sign historical billing under the result epoch.
- An incomplete E remains incomplete indefinitely. This contract adds no external loss amount, empty-coverage proof or permission to discard retained history. Scope must not expand into a partial-seal scheme without another owner decision.

## Scope

After approval, expected changes are:

- `crates/nsshared-control/src/account/families/relay/session.rs`, or a narrowly split sibling for epoch operation types, plus re-exports in `relay.rs`: kinds 11/12, strict shape/header checks and pure constructors/parsers/validators. Preserve current authentication/renewal/report/seal paths.
- Existing account session/participant-roster tests and independent Python vector producers under `tools/vectors/nsvec/producers/control/account/`, their generated `crates/nsshared-control/tests/vectors/account/` fixtures and compatibility/migration inventory. Add downstream exhaustive-match compile probes or corresponding consumer checks where the current gate supports them.
- `docs/spec/account/relay.md`: Attribution exception, frame table, authorization/order/correlation and versioning. `docs/spec/account/usage.md`: clarify that recovery only restores future capture and clean shutdown leaves a reusable epoch open; change no report/seal encoding or completeness rule.
- Workspace release metadata/manifests and lock/inventory artifacts required by the approved minor release; PMA task/plan/index/changelog in the actual authorized implementation checkout. Re-align affected baseline shared/consumer interfaces and unified architecture at delivered pins, following workspace conventions.

No database, network client/server, automatic retry scheduler, clocks, quotas, signing service, billing acceptance implementation or host operation belongs in this pure library. No ns/nsplane implementation is required. NSD's platform API DTOs live in NSD, not as a new account wire family here. No new DATA flag, signed roster schema, signature domain, retention outcome or incomplete manifest is introduced.

There is no shared persisted-state migration. Consumers retain existing authority floors, enrollment custody, reporter incarnations, immutable reports and ledgers. Upgrade through the new released remote revision; do not rewrite old tags or change sibling consumer pins in this proposal-only task.

## Alternatives

| Alternative | Assessment |
| --- | --- |
| Reuse Renew and infer recovery | Ordinary renewal must not force epoch changes or lose exact semantics; no stopped-epoch expectation/correlation result exists there. Reject overloading. |
| Reuse Report/Answer with another payload | Those bytes are immutable usage and retention contracts. A control-plane epoch command is distinct and must not be mistaken for billable custody or settlement. |
| HTTP request authenticated by a new relay token/signature | Adds a second participant authentication surface and duplicate custody enforcement. Existing exporter-authenticated session is the narrower design. Operator HTTP remains independently platform-authenticated. |
| Operator-only command, no new frames | Avoids new kinds but cannot meet automatic recovery after unattended interruption. A specification-only Attribution amendment is insufficient. |
| New roster schema or retention incomplete sentinel | Existing schema 2 already expresses fresh epochs and permanent absence of seal already preserves incompleteness. Additional encodings are unnecessary. |
| Implicit periodic rollover/no request | Creates idle churn and delayed recovery while leaving explicit recovery intent unaudited. |
| Capability negotiation or fallback to old custody mutation | Adds a second recovery behavior and hides incompatible rollout. Use explicit producer-first version ordering and fail closed on unsupported authority. |

## Test plan

All tests below are proposals, not results from this task. Follow RED before codec behavior changes.

1. **Exact bytes:** independently generated request/result positive vectors for both success outcomes and each refusal, boundary u64 values, nonzero correlations, independent valid identities and fixed body/header lengths. Verify construction, encode, decode, canonical re-encode, `validate_header`, kind byte/from-byte and public re-exports. Existing kind 1..10, schema-1/2 roster, usage and retention vectors remain byte-identical.
2. **Malformed/refusal matrix:** unknown format/outcome/kind; zero generation/fenced epoch/correlation; invalid identity; truncated/extra fields or trailing bytes; length mismatch; success with F less than/equal to E or zero publication; success with retry time; refused result with authority counters; RateLimited without positive retry bound; and overflow/range behavior. Reject before granting any authority or oversized allocation.
3. **Pending context:** wrong issuer, recipient, generation, E, correlation or operation; interchanged renewal/result types; unsolicited/duplicate results; reply after cancellation; a delayed replayed result with an old publication. Pure validators grant no admission, do not renew deadlines and never replace authenticated generation. Runtime tests own pre-auth order, single consumption and current-authorization checks.
4. **Epoch invariants:** same classified membership may receive an explicit F greater than E, while ordinary publication-only renewal repeats E. Signed roster verification still rejects epoch decrease and publication replay and preserves independent counter magnitudes. No code hard-codes NSD's epoch-equals-first-publication allocation policy as a general wire constraint. Historical report/seal bytes at E remain exact after F; stopped E remains unsealed in consumer acceptance.
5. **Compatibility and release:** demonstrate v0.9.0 rejects new kinds while its ten kinds interoperate unchanged with new decoders. Compile representative NSD/nsgw matches against the new FrameKind and migration inventory; do not treat account as unstable/opt-in. Record actual semver results for the minor transition, documentation/API surface inventory, and independent vector regeneration/checks. No silently skipped gate is acceptance.
6. **Consumer acceptance:** new NSD with an old relay accepts existing authentication/roster/report/seal traffic and sends no unsolicited EpochResult. Paired new NSD/relayd proves operator and automatic rollover without generation/membership changes. New relay with an old authority fails closed and identifies incompatibility. Lost reply/restart/coalesced requests allocate at most once; only a verified fresh signed roster restores forwarding. Include healthy-peer seal continuity and offline-recipient hold.

Run the repository's `just qa` (which includes formatting, lint, dependency, vector and semver checks plus tests), the focused account/session targets registered by the actual manifest, and relevant release/inventory checks. Run `just vectors-check` explicitly if needed to document unchanged old bytes and new independent vectors. Use `$HOME/.cargo/bin` on PATH and the pinned toolchain. Full consumer integration/lab evidence is mandatory before deployment but is not a claim that a pure library gate itself launches real NSD.

## Rollout and dev-lab acceptance

1. Owner approves exact semantics/versioning and NSD's global-epoch policy. Agree producer/consumer acceptance before writing code. Adopt this draft into a claimed repository PMA task/plan in an isolated implementation checkout.
2. Publish the approved nsshared minor release from `git.pvv.cc/nsiod/nsshared`, with immutable tag/full resolved commit and contract/vector/migration evidence. This shared prerequisite precedes runtime adoption; **NSD is implemented and deployed first among runtime repositories**.
3. NSD pins that remote revision, delivers both audited command paths and preserves old-client behavior. Verify the operator action and real producer transaction before shipping a requesting relay.
4. nsgw pins the same remote release in main and standalone acceptance graphs, delivers all recovery/readiness/drain changes and validates supervisor grace through its deployment owner. No sibling checkout paths or temporary local patches substitute for a published shared contract.
5. Under a separate authorized dev-lab run, execute clean unchanged-epoch restart, interrupted unchanged-membership automatic recovery and operator/race controls described in the companion plans. Record exact candidate images, shared lock revisions, authenticated public request/result fields, committed signed roster bytes/floors, unchanged custody and model hashes, destination DATA and immutable billing/seal evidence. Do not capture secrets/exporter material.

Lab success means a clean stop can reuse E, an interrupted stop can adopt F only from signed authority, no billed DATA crosses an ineligible boundary, old incomplete E never receives a complete/empty seal, healthy recipients settle honest older epochs, and offline/unobserved coverage remains held. Rerun the failed C12 regional ingress and both historical-gateway directions using real NSD. Fixture-driven epoch publication or a readiness-only readback is insufficient.

Binary rollback preserves all advanced floors and custody, and authority compatibility remains available while any new requester is deployed. The original proposal performed no code, release, remote pin change, deployment, lab or host operation.

## Annotations

Owner decisions approved on 2026-11-10 06:30 UTC:

1. Approve the Attribution recovery exception and fixed kinds 11/12, version-1 layouts and six outcomes; confirm no concurrent upstream allocation of those kind bytes before implementation.
2. Approve a new 0.x minor release because FrameKind is exhaustive and account is semver-covered; maintainer selects the exact next available tag. No existing byte format is rewritten and no compatibility negotiation is proposed.
3. Confirm pure-library scope: NSD owns authentication recheck/audit/idempotency/quotas; nsgw owns command retries, capture eligibility and finalization. No complete-seal or billing-format change is needed.

The owner approved all three decisions. This copy adopts the shared-library scope
in the related repository task; the NSD and gateway deliveries remain separate.
The original warehouse proposal made no repository changes. Implementation and
verification results are recorded below; merge, tag and release publication remain
separate authorized work.


## Implementation results

- Selected 0.10.0: v0.9.0 was the newest tag and kinds 11/12 were unused at main f8589f9c. The owner approved the exact layouts; no layout change was necessary.
- Added dedicated immutable `EpochRequest`, `EpochResult`, `EpochOutcome` and `PendingEpochResponse` types, strict complete-frame conversion and exact pending validation. Constructors and decoders reject the same field combinations. Epoch results expose no credential deadline or custody-update API.
- Kept request/result bodies at 97/122 bytes, header length values at 98/123 and complete frames at 102/127 bytes. Version is 1 and u64 fields are big-endian.
- Added 54 independent vectors (12 accepted, 42 refused), focused codec/context/outcome/dispatch tests, a public usage doctest and a compile-fail probe for renewal pending state. All 52 pre-existing fixture files remain byte-identical.
- Updated relay and usage specifications, architecture, README and the consumer API/migration inventory. The historical account import-map regeneration remains unchanged and its check passes.
- Prepared the workspace, eight internal requirements and twelve lock packages for 0.10.0 without changing external dependencies. The normal semver gate identifies the 0.x minor transition as a major API change and skips its incompatible-change lints by version policy (260 skipped per library); both facade API inventories remain unchanged. An additional forced-patch diagnostic runs 229 checks (228 pass, one expected enum-variant-added failure, 31 unrelated skips), detecting exactly the two new FrameKind variants.
- RED failed on the valid independent request before implementation; GREEN passed the relay suite. Complete QA passed with the cached Cargo registry after two online registry-update attempts hit TLS EOF. No gate recipe or assertion was disabled. Runtime/transaction/lab acceptance remains the consumer deliveries' scope, not claimed by these pure library tests.
- Baseline documentation alignment at delivered main pins is tracked as tk nsdoc #1155; no feature-branch baseline pin is published.
- Final validation: `CARGO_NET_OFFLINE=true just qa` exit 0, 71 script tests, 626/626 nextest tests (0 skipped), three passing doctests and one pre-existing ignored testkit example, rustdoc with warnings denied; focused relay tests 19/19. Migration check and independent old-decoder compatibility probe exit 0. Full QA retains every static check; semver policy skips and the forced-patch expected failure are recorded above.
- Local code review covered all changed source, tests, generators, release metadata and documentation against f8589f9c. No blocking findings; consumer runtime/real-lab acceptance is explicitly outside this delivery.
