# Confidential authentication configuration

- **status**: implementing
- **createdAt**: 2026-10-20 19:02
- **approvedAt**: 2026-10-20 19:02
- **relatedTask**: 20261020-1902-confidential-auth

## Context

PublicEdge carries generation-qualified dependencies and public subject bindings,
but cannot supply the private verifier, OIDC client or cookie material needed by
the authentication catalog. The existing producer projects current and previous
secret values with explicit expiry. Route import order and redirect overrides
are distinct from provider defaults. Management credentials remain producer-local.

## Proposal

Specify exact confidential configuration tuples and independent Python fixtures
before adding pure Rust codecs. Reuse EdgeMaterialRef, EdgeAuth, SubjectBinding
and PolicySubject. Bind responses to pending requests and authenticated current
public dependencies with typed refusals. Keep envelope authentication, accepted
binding comparison, transport, installation and persistence in consumers.

## Risks

Wrong realm/generation joins could expose credentials to an unrelated scope.
Strict correlation, bounded canonical decoding and explicit confidential envelope
requirements prevent an opaque reference from standing in for private values.
Secret-bearing values must redact Debug output.

## Scope

Pure account DTOs/codecs, independent fixtures and consumer tests, specification,
profile and review request. No runtime, publication kind or registry bytes change.

## Alternatives

Embedding private values in PublicEdge would disclose confidential configuration.
Duplicating predecessor JSON would preserve an obsolete wire shape and is excluded.

## Acceptance results

The specification and independent Python candidate vectors preceded the codecs.
The confidential_auth_generation consumer exercises 57 independent vectors,
including authenticated envelopes, exact successful generation delivery, mismatched
realm/reference/generation/scope/correlation refusals, complete empty configuration,
all key-source variants, malformed shapes and value/collection bounds.

The repository self-check passed on source commit `5fdeff3`, selecting full QA.
All 469 Rust tests passed with zero skips, 41 check-selection tests passed, and
one documentation test passed. Formatting, lint, dependency checks, spelling,
vector reproducibility, API compatibility and documentation generation passed.
NSD producer confirmation and producer-owned vectors remain outstanding.

## Credential identity and fixed key acquisition

Inspection found that private credential ordering did not exclude reuse of an
anchor by a JWT binding. Enforce one credential anchor across both lists, checking
each JWT binding before resolving the consumer join. Independent fixtures cover
every private method against JWT, private method pairs and distinct identities.

Fixed JWKS acquisition may require an exact query to select a tenant. Validate the
complete bound, HTTPS authority and URL safety while preserving query bytes;
issuer and provider/route redirects keep their existing query prohibition. Add
independent accepted controls and malformed/insecure refusals for every URL site.
