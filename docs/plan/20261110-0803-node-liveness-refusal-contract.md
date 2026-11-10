# 20261110-0803-node-liveness-refusal-contract Define typed Node liveness refusal receipts

- **status**: implementing
- **createdAt**: 2026-11-10 08:03 UTC
- **updatedAt**: 2026-11-10 08:15 UTC
- **approvedAt**: 2026-11-10 08:30 UTC
- **relatedTask**: 20261110-0821-node-liveness-refusal

## Context

The planning addendum makes ns the primary fix: e89764c3 already supports same-runtime bind after lease expiry. This shared change is the minimal refusal contract enabling the client to distinguish that recovery from real revocation. Stream snapshot expiry is not a permanent fence write.

This Full-tier proposal was originally external. Repository tracking was created and claimed in the authorized isolated checkout after approval; see Repository adoption below.

Both ns `bb2d61483bdef8d71fb89253834f60c68b1d45ee` and nsd `e89764c332ecde608aa375b0c1ad2cd8754134cd` pin nsshared `v0.9.0`, commit `9c0ee7305eff4a5566f169d6e26b710a5709944c`. Local nsshared HEAD is `f8589f9cc9508115cf7858352cfdc5d9cd2b9d4f`; the relevant Node report/M6 contract files are unchanged from that tag (the original revision audit is retained with the external approval evidence). Paths below are relative to `/workspace/nsiod2/nsshared/`.

`crates/nsshared-control/src/account/control/reports/node.rs`, `NodeRuntimeFence`, `NodeHeartbeatRequest`/`NodeHeartbeatResponse`, and `reports/node_posture.rs`, `NodePostureRequest`/`NodePostureResponse`, define successful, scoped, correlated version-1 receipts, but no shared typed refusal receipt. NSD's runtime predicate failures escape as plain HTTP 403; ns raw carriage drops 401/403 bodies before envelope verification. The shared contract therefore needs an additive change for authenticated refusal semantics.

The M6 contract is owned by `nsshared_control::service`, not the deprecated facade `nsshared-service-control` (`crates/nsshared-service-control/src/lib.rs`). `service/contract.rs` has schema 1 and capability `service_control.v1`; `service/contract/body.rs`, `ERROR_CODES`, already includes `stale-runtime`, `stale-epoch`, `unauthorized`, `runtime-recovery-required` and `recovery-required`. These error strings concern M6 operations. They neither define a heartbeat/posture refusal nor distinguish credential revocation from runtime lapse. Reusing a free-form string as a new recovery authorization would be unsafe.

## Proposal

### Contract boundary

Add a bounded `NodeLivenessRefusal` and pure codec/correlation methods alongside the Node control report contracts, behind their existing account feature. Re-export through the established public control facade. Proposed logical shape (the implementation will follow existing deterministic CBOR conventions):

```text
[version=1, operation, membership_scope, requested_runtime_fence,
 logical_request_id, refusal_code, reason]
```

Use an explicit discriminator/arity that cannot decode as a success receipt. `operation` is the heartbeat or posture operation and must match the outer signed envelope kind. Scope and fence echo the rejected request; they do not claim fresh custody or disclose a replacement process's identity. `logical_request_id` is heartbeat's nested heartbeat request ID or posture's snapshot request ID. Outer nonce remains the transmission nonce. Enum variants, not diagnostic strings, determine behavior:

| Code | Meaning | Required carrier status |
|---|---|---|
| `runtime_rebind_required` | Valid current business/enrollment authority, but presence elapsed or NSD authority epoch changed | 409 |
| `runtime_conflict` | Committed stop or superseded runtime; no automatic takeover permission | 409 |
| `authority_revoked` | Current credential/enrollment or scoped business authority actually refused | 403 |

Reasons are a bounded closed enum, e.g. `lease_elapsed`, `authority_epoch_changed`, `runtime_stopped`, `runtime_superseded`, `authority_changed`. They are diagnostic refinements of the typed code and cannot independently grant recovery. Specify exact legal code/reason combinations. Minimize externally visible revocation detail; no user identity, credential bytes, server replacement runtime ID, lease-owner token or bearer is needed. Scope of permanent Account sign-out remains a consumer lifecycle decision based on actual authority, not this type alone.

Require the existing `BootstrapEnvelope` signing, pinned NSD trust, direction/recipient/kind/timestamp/replay checks, outer nonce and complete inner request correlation. The shared decoder itself grants no authority: NSD must classify under its locked current authority; ns must verify before triggering recovery. Missing/malformed/unknown-version replies produce a protocol failure, never a guessed recoverable or permanent-Account verdict. Authority unavailable remains 503 with no invented revocation claim; invalid/untrusted requests retain existing HTTP security behavior.

### Versioning and deployment

This is an additive *new response type*, not a change to existing successful arrays or the envelope/M6 schema numbers. Keep existing `NodeHeartbeatResponse`, `NodePostureResponse`, `NodeRuntimeFence`, envelope v1 and `service_control.v1` bytes unchanged. Give the new refusal payload its own version 1. Do not add a new M6 error code merely to represent report refusal; audit M6 consumers in ns to preserve the existing typed distinctions at the adapter boundary.

Publish one agreed, unused compatible nsshared release tag after vector/semver validation; both consumers must pin that exact tag/commit and update lockfiles. Do not assume a particular next tag is free: current remote tags are not verified in this environment. No dependency bump or publication is authorized here.

The HTTP status and signed result form one contract. NSD emits correct 409 semantics for runtime conflicts even to old clients; no negotiation is needed to preserve successful existing report bytes. Old checked raw carriers see 409 as transient `ServerError` and cannot decode the new receipt. New clients talking to old NSD retain conservative handling of untyped 403; do not infer lapse from elapsed client time or a reason substring. Deploy NSD before relying on new-client recovery. If a capability is later required for UI discovery, add it only with a concrete consumer requirement; the initial fix does not need speculative negotiation.

### Metadata/sign-out addendum boundary

The confirmed 03:57:40Z metadata-refresh SignedOut and missing retained source are consumer lifecycle/persistence defects. They require no change to M6 runtime bind, runtime generation, Account activation, identity or enrollment serialization. Existing metadata HTTP 401 remains a renewable credential challenge with its generic outward problem response; ns already has an exact signed-renewal/refetch path. NSD adds safe internal machine-attributed diagnostics and verifies TTL/renewal behavior; ns separates GET, renewal and retained-old-session rejection and shares the complete sign-out lifecycle.

Do not reuse `NodeLivenessRefusal` as a context-GET receipt or let its runtime code mark Account authority revoked. No extra JWT claim, new metadata endpoint or shared permanent-signout message is proposed without a demonstrated contract gap. A current authoritative rejection and a stale local verdict must retain their source/ownership distinctions in consumer types. Tests cover the separation alongside the Node's retained-source/browser-readmission integration; no fabricated prior Active manifest or implicit readmission authority is supplied by the wire contract.

### Verification (planned)

- Independent Python vectors under `tools/vectors/nsvec/producers/control/account/control/`; Rust round trips and exact-byte fixtures for both operations and every result/reason.
- Reject wrong arity/discriminator/version, unknown enum combinations, malformed/zero fence or request IDs, oversized input, trailing bytes and noncanonical encodings.
- Cross-type rejection: a refusal is never a successful heartbeat/posture acknowledgement; wrong operation/scope/fence/request ID must fail correlation. Consumer tests additionally reject bad signer, recipient, kind, nonce, replay or stale envelope.
- Preserve all existing v0.9.0 request/success/M6 vectors byte-for-byte, both gateway and ordinary Node forms; no gateway liveness response shape changes.
- After approval, run the focused account integration target (with its account feature), independent vector check, semver check and `just qa` in an isolated checkout. No builds/tests were run in the shared checkout during proposal work.

## Risks

Adding a recovery code without an authenticated and correlated envelope creates a sign-out bypass or reconnection trigger. Altering M6's existing schema instead would unnecessarily break unrelated consumers. An enum that merges explicit stop with ordinary lapse would weaken lifecycle fencing. Exact current tag availability and older-client behavior need release qualification, not a presumed patch number.

## Scope

Node report codec/type, public re-exports, contract specification, independent vectors and refusal/correlation tests; package release metadata after approval. NSD and ns own business admission, recovery orchestration, deadlines and persisted state. No database or identity schema changes.

## Alternatives

NSD-local JSON/text plus client substring matching duplicates a security contract and cannot authenticate refusal reliably; reject. Extending M6 error strings alone does not cover the affected report operations; reject. HTTP 409 alone can contain this older-client cancellation but does not complete typed client recovery; retain the signed result contract.

## Annotations

Owner approval of the shared encoding and rollout is recorded in the summary and preserved. Confirm the exact CBOR discriminator and unused package release tag during authorized implementation. The metadata SignedOut writer is now identified; its exact 401-stage/cause remains open. Track current-production/install-source provenance in #1158; repository tracking is recorded below for implementation.

## Repository adoption

Owner approval recorded at 2026-11-10 08:30 UTC covers implementation and a pull request. The base is main f76374fd (v0.10.0). Account is now unconditional; no feature flag is introduced. Prepare workspace 0.11.0 without merging, tagging or publishing.

The exact new version-1 form is the proposed seven-item array, distinguished by its operation text and arity from success receipts. Operation is `node.heartbeat` or `node.posture`. Code/reason pairs are `runtime_rebind_required` with `lease_elapsed` or `authority_epoch_changed`, `runtime_conflict` with `runtime_stopped` or `runtime_superseded`, and `authority_revoked` with `authority_changed`. HTTP status is respectively 409, 409 and 403. Authority unavailable remains HTTP 503 without a typed revocation claim, outside this refusal payload. Nonzero logical request IDs and runtime fences are required.

Repository plan status is initially approved on adoption, then implementing during the authorized work. The original approved proposal above is retained as the scope record.

- Remote validation: v0.10.0 resolves to main f76374fd; v0.11.0 is unused. The fixed seven-item arity plus text operation discriminator requires no change to the approved encoding. The refusal payload has its own version 1 and a 256-byte bound.
