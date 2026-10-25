# Confidential authentication configuration

- **status**: completed
- **priority**: P1
- **owner**: account-contract
- **createdAt**: 2026-10-20 19:02
- **plan**: ../plan/20261020-1902-confidential-auth.md

## Investigation and implementation

The catalog needs provider client secrets, cookie keys, API/Basic verifiers,
signed URL keysets, mTLS joins and public JWT key-source configuration. Existing
subject bindings retain credential identity, enabled state, subject and expiry.
Route imports retain supplied method order, bypass/failure flags and explicit
redirect overrides. NSD management API credentials are outside gateway projection.

## Acceptance

- Independent confidential_auth_generation fixtures bind exact request, realm,
  reference and generation; mismatches refuse.
- Strict canonical, size, shape, missing-value and nested-value refusals.
- Existing authenticated control envelopes only; no public payload secrets.
- Formatting, lint and the current self-check pass.

## ActiveForm

Completed confidential authentication configuration

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Results

- Added exact confidential request/response and configuration tuples, actual
  provider/cookie/verifier values, existing public binding reuse and explicit JWT
  consumer joins. Realm catalog method selectors preserve request-time credential
  selection. No private value is derived from a public reference.
- Added typed correlation/scope/realm/reference/generation/current-dependency
  refusal. Envelope authority/recipient binding, installation and route ownership
  remain consumer responsibilities. No runtime or publication kind was added.
- The first consumer build failed with E0432 because confidential_auth and
  EDGE_AUTH_CONFIG_GET did not yet exist. This established the missing interface
  before implementation. The later envelope test exposed a fixture pin error:
  raw public-key encoding was replaced by an independently generated JWK
  thumbprint. No product authentication check was weakened.
- confidential_auth_generation and confidential_auth_current_dependency_and_refusals
  passed; 57 independent vectors round-trip accepted content or reject invalid
  data. Secret Debug output is redacted. Oversized complete objects refuse.
- The repository self-check passed on source commit `5fdeff3`, selecting full QA:
  469 Rust tests passed with zero skips, 41 check-selection tests passed and one
  documentation test passed. Static checks, vector consistency, semver checks and
  documentation generation passed. Only these acceptance records changed after
  that successful run.
- Public-edge inventory, profile and review family rows now link the confidential
  contract. NSD producer confirmation and producer-owned vectors remain
  outstanding; fixture acceptance does not record agreement or interoperability.

## Credential identity and acquisition follow-up

Reopened to enforce cross-method anchor uniqueness and preserve exact fixed
HTTPS JWKS query data. Check private/public binding equality, consumer references,
JWT binding cardinality and ownership, all four confidential HTTPS call sites,
and their shared URL predicate before completing acceptance again.

## Credential identity and acquisition results

- The credential collision test initially failed with "one credential anchor
  identifies both an API-key verifier and a JWT binding". A shared anchor set
  now refuses collisions across private verifiers and JWT bindings before any
  ambiguous JWT consumer lookup. The regression requires successful fixture read
  and valid baseline, then asserts refusal at canonical construction.
- The fixed JWKS test initially failed with "a fixed HTTPS JWKS URI can select
  its tenant by query: InvalidField". Dedicated acquisition validation now
  preserves exact query data while retaining HTTPS, canonical authority/port,
  bounds, whitespace/control, userinfo, fragment and backslash checks. Malformed
  percent escapes refuse. Issuer and both redirect validators are unchanged.
- The independent fixture now contains 126 vectors, including every private/JWT
  collision, private method pairs, JWT duplicate/distinct identities, exact-query
  controls and malformed/insecure controls for all four HTTPS call sites.
- Reviewed all new credential/consumer/public-binding joins, key-source authority
  cardinality, mTLS material joins and route method selectors. Private binding
  equality includes realm/subject/enablement/expiry; consumer selection remains
  by explicit reference and subject. Global credential uniqueness removes the
  ambiguous JWT lookup. No additional confirmed defect was found.
- The current repository self-check passed on source commit `34c53e2` with 473
  Rust tests, zero skips, 41 check-selection tests and one documentation test.
  Formatting, lint, dependency checks, spelling, independent vector reproducibility,
  API compatibility and documentation generation passed. Only these two completion
  records changed after that successful source check.
