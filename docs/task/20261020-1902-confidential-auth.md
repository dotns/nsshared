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
