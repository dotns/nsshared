# 20261111-1309-private-account-record Define authenticated private ordinary NodeRecord submission

- **status**: implementing
- **createdAt**: 2026-11-11 13:09 UTC
- **approvedAt**: standing user authorization for continued accurate E2E and necessary repairs, applied 2026-11-11 13:09 UTC
- **relatedTask**: 20261111-1309-private-account-record

## Context

See parent NS task20261111-1255-private-account-record and actual new-tuple failure/snapshot evidence. Existing root LocalRecord is signed and persisted without a publisher; the Network record is separately signed by a derived identity and cannot satisfy root NodeBinding equality. The private authenticated control carrier already owns source, registration and runtime fences.

## Proposal

Add an ordinary-node private record report operation, strict request and exact digest-correlated receipt. Request fields: existing MembershipScope, NodeBinding, RegistrationCondition, SignedSourceBinding, NodeRuntimeFence, and unchanged signed root NodeRecord bytes. Validate structural/context equality without sampling a hidden clock. Consumer must verify current exact enrollment/source/registration/runtime and freshness at its serialized admission cut and reuse existing RecordMarks replay/conflict ordering. Define receipt as persisted submission evidence only, never ready membership or authorization. Keep every existing wire format unchanged and introduce no external dependency. NS producer will reuse the durable root Store without waiting for the missing peer collection; NSD integration remains a separately tested consumer task.

## Risks

Security-sensitive cross-repository contract. Wrong root/derived identity, key, generation, scope, source, registration, runtime, issuer, recipient, nonce or digest must not be accepted. A record cannot establish its own membership, extend expiry or clear conflict. Current-custody enforcement and write cancellation require consumer integration tests beyond this pure contract.

## Scope

Shared operation/type exports, canonical codecs, focused independently signed negative/positive fixtures and contract documentation. No relay registry, DATA, roster, NodeRecord signature context or database schema change. No deployed compatibility fallback.

## Alternatives

Unscoped Account publication and broader registry read/admission grants violate the approved Network boundary. Replacing root membership identities with derived identities would widen policy/address semantics. Private signed delivery preserves existing root policy and independently scoped relay records.

## Annotations

All original E2E failures remain failed. New shared source is not pinned by product consumers or deployed until normal integration validation is complete.


### Contract qualification

Test-first initial offline attempt exits101 before compilation because proptest1.11.0 was not cached. Locked fetch succeeds with the original lock bytes unchanged. The second attempt establishes only the expected E0432 missing-public-contract build boundary; no behavioral test executes, and it is not a runtime E2E RED. Implement the additive typed request/receipt contract with current-custody/freshness enforcement explicitly left to the consumer. Independent Python canonical CBOR and Ed25519 fixture matches exact581-byte request,36-byte receipt and full domain digest.

Focused six contract tests and58 control-contract tests initially pass, while Clippy fails at two redundant one-literal concat macros in the new fixture constants. Replace those macros with identical literal bytes, preserving a byte-equality proof. The final candidate passes6/6 focused,208/208 complete Account contract tests and package all-target Clippy,0 failed/ignored. Focused6 overlap Account208. All admitted source/Cargo hashes stay unchanged; owned cgroups and private fixtures retire. Full static/project delivery checks and producer/consumer integration remain pending; no product pin, runtime acceptance or deployment.


### Canonical self-check and scoped review (2026-11-11 13:54 UTC)

The first canonical `just self-check origin/main` fails because cargo-semver-checks is unavailable; preserve that original failed receipt. Install the verified official cargo-semver-checks0.51.0 archive only into an owned private bin directory, then run the unchanged entry point. The admitted snapshot passes formatting, workspace lint, dependency policy, dependency usage, spelling, vectors, default-feature semver checks, all649 selected affected tests (0 skipped), doctests (3 passed,1 ignored across packages) and final documentation gates. Actual exit0; all773 admitted tracked/untracked inputs unchanged and the owned unit/fixture retired. Source/Cargo policy and product consumer pins are unchanged.

PMA-CR local working-tree review against8fd05da covers the complete new request/receipt implementation, exports, operation, independent fixtures, adjacent envelope/source/binding contracts and specification. No confirmed correctness or policy findings; scoped contract verdict PASS. Current registration/runtime admission, expiry, serialized commit and product delivery are explicitly consumer-owned and remain unimplemented; this verdict does not qualify those integrations, deployment or real Account/Gateway E2E. Keep the additive protocol draft until both consumers are validated.
