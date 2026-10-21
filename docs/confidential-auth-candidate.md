# Confidential authentication configuration candidate

Membership realm identities follow the [canonical RealmId contract](canonical-realm-identity.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
NSD/ns producer and consumer updates, including the other active consumer delivery,
remain outstanding. Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


Version 1 uses shortest-form definite CBOR, strict UTF-8, exact tuple arities,
no trailing bytes and at most 1,048,576 bytes per object. Lists contain at most
256 entries. Unknown fields/discriminants, missing fields and null required
values refuse. Tokens reuse the account 1..256-byte whitespace-free syntax.
Data strings preserve exact UTF-8, including spaces, with 1..8192 bytes; optional
data uses null for absence, never an empty required value. No normalization occurs.

## Delivery and correlation

`AuthConfigRequest = [1, request_id_16, recipient_I, served_realm, scope,
realm_16, material]`. Material is the unchanged EdgeMaterialRef and must be auth.
`AuthConfigResponse = [1, request_bytes, configuration_bytes]` echoes the complete
request, including recipient. `AuthConfiguration = [1, realm_16, generation,
default_provider_ref_or_null, providers, cookie_keys, consumers, credentials,
public_auth_bytes, key_sources, jwt_consumers, imports]`. Generation is a positive u64.
public_auth is unchanged EdgeAuth with the same realm; credential bindings are
included there verbatim. Configuration supplies values, not inferred secrets.

Only operation `edge.auth.config.get` in the existing BootstrapEnvelope request
and response directions over the existing confidential control transport carries
these objects. They never occur in PublicEdge, signed publication content, public
HTTP discovery, logs or URLs. Envelope domains, signing inputs, effective pins,
nonce replay retention and time validation are unchanged. The consumer verifies
the envelope before decoding configuration and requires an explicit envelope
recipient. Request envelope recipient is the accepted authority; response envelope
recipient is the request's gateway recipient. Authenticated signer/recipient must
match the configured/accepted binding; body correlation alone grants no authority.

`validate_for(pending, current_realm, current_material)` compares request id,
recipient, served realm, scope, contributing realm and exact kind/reference/
generation, then payload realm/generation, then the current authenticated
PublicEdge dependency, which must also be present verbatim in public_auth.materials. Each mismatch is a typed refusal. Authority/accepted-binding
checks remain consumer-owned. Validation performs no installation, replay storage,
publication or ACK. Only actual installation of this exact reference/generation
can produce an installed EdgeMaterialAck; all dependencies precede route exposure.
An old pending request cannot satisfy a changed current dependency.

## Configuration tuples

- `AuthSecretVersion = [reference, version, expires_seconds, value]`. Version is
  positive u32, expiry positive u64, and value is required exact data. No reference
  supplies a value. `AuthSecretSet = [current, previous]`; previous versions are
  strictly increasing, unique, below current.version, and share current.reference.
  Actual expiry, overlap and key usability remain catalog checks, without a clock
  in this codec. Secret-bearing Debug output is redacted.
- `AuthProvider = [reference, kind, issuer, client_id, client_secret, scopes,
  audience_or_null, subject_template_or_null, idp_template_or_null, subject_realm,
  organization_id_or_null, organization_mode_or_null, redirect_base_url]`.
  Kind 0 is OIDC. Organization mode null means generic; 0 means Logto and requires
  organization_id. Logto retains organization scope, consent and resource-token
  exchange semantics. Templates and external namespace are exact data, not a
  control realm or a principal grant. Issuer and redirect are explicit HTTPS URLs without whitespace or controls;
  discovery, URL screening, template evaluation and OIDC verification stay external.
  Scopes are ordered unique tokens. Providers are ordered by reference. A present
  default names an existing provider; null selects none, never a guessed default.
- `AuthConsumer = [reference, subject_bytes, enabled, display_name_or_null]`.
  Subject is unchanged PolicySubject, realm-qualified and non-group; display name
  is presentation only. Consumers are ordered by reference.
- `AuthCredential = [consumer_ref, binding_bytes, scopes, verifier]`.
  Binding is unchanged SubjectBinding with a credential anchor, matching the
  consumer's explicit subject and realm and present in public_auth.bindings.
  Credential enabled/expiry live in that binding; consumer enabled remains
  independent. Credentials are ordered by anchor reference. Anchors are unique across all
  private verifier credentials and JWT bindings, including distinct JWT claims;
  the same anchor cannot identify more than one credential method.
  Verifier is `[0, key_id, verifier_hash]` API key, `[1, username, phc_hash]` Basic,
  `[2, kid, hmac_keys]` signed URL, or `[3, spiffe_id, trust_material]` mTLS.
  Trust material reuses EdgeMaterialRef, kind client CA, present in public_auth.
  Hashes and keys are required actual data. Verification algorithms, hash parsing,
  SPIFFE validation and actual deadlines stay with their existing consumers.
- `AuthKeySource = [authority_ref, enabled, kind, value_or_null]`, ordered by
  authority_ref. Kind 0 OIDC discovery requires null; 1 fixed HTTPS JWKS URI and
  2 inline public JWKS require data. Fixed acquisition URIs preserve exact query
  bytes, including order, repeated parameters, literal plus and percent-escape
  spelling. They require a canonical HTTPS host/optional port and valid percent
  escapes; whitespace, controls, userinfo, backslashes, fragments and values over
  8192 UTF-8 bytes refuse. Queries are not subject to the issuer query prohibition.
  Provider issuer and provider/route redirect restrictions remain unchanged. Each public_auth.authority has exactly one
  source and vice versa. Authority issuer/audiences/material and JwtSubjectBinding
  are reused unchanged. Public key trust qualification and JWKS parsing stay
  external. JWT consumer joins are explicit: `AuthJwtConsumer = [credential_ref, consumer_ref]`,
  ordered uniquely by credential_ref, with exactly one join per JwtSubjectBinding.
  Each join matches the binding subject to that consumer; consumer enablement
  stays independent from credential enablement. Equal subjects never imply a join.
- `AuthRouteImport = [route_id, methods, anonymous_bypass, fail_closed]`, ordered
  by route_id. `AuthImportMethod = [kind, reference, redirect_or_null]`; method
  order is evaluator order and duplicate kind/reference pairs refuse. Kinds are
  0 OIDC, 1 client mTLS, 2 API key, 3 bearer JWT, 4 signed request, 5 Basic.
  OIDC references a provider; bearer a public authority; mTLS a client-CA material;
  API/signed/Basic retain an opaque method-catalog selector (including the
  producer-supplied `__ns_realm__` selector); they do not select a credential
  before a request presents its key id, signature kid or username. Redirect overrides are
  HTTPS data and allowed only for OIDC; null uses the provider's explicit redirect.
  Empty chains remain explicit empty, with no implicit provider substitution.
  The producer resolves a predecessor empty/default OIDC chain to an explicit
  provider before encoding; no predecessor fallback is introduced in consumers.
  OAuth2 is retired as a reserved, unimplemented method. Route ownership and
  import-to-route joins are checked against the current public contribution by
  the consumer; this object creates no route or membership authority.

## Predecessor field disposition

| Source | Retained meaning or retirement |
| --- | --- |
| GatewayAuthConfig.realm_id/generation | Binary realm and positive generation; reference comes from echoed EdgeMaterialRef |
| default_provider_ref/providers/cookie_keys | Explicit optional default, complete providers, actual current/previous cookie values |
| GatewayAuthProvider.provider_ref/kind/issuer/client_id/client_secret/scopes/audience | AuthProvider exact counterparts; only OIDC kind |
| subject_template/idp_template/subject_realm | Exact AuthProvider data; label construction and PolicySubject qualification remain external |
| organization_id/organization_mode/redirect_base_url | Explicit AuthProvider organization data and HTTPS redirect; null generic or Logto marker |
| GatewayAuthSecretVersion.ref/version/expires_at/value, SecretSet.current/previous | AuthSecretVersion and AuthSecretSet retain rotation versions, real deadlines and confidential values |
| GatewayAuthConsumer.consumer_ref/subject/enabled/display_name | AuthConsumer explicit subject; no credential-derived subject synthesis |
| Credentials.consumer_ref/credential_id/enabled/expires_at/scopes | Consumer join, SubjectBinding credential anchor/enabled/expiry and ordered opaque scopes |
| API key key_id/verifier_hash, Basic username/phc_hash | AuthVerifier actual verifier values; plaintext API/password values are never projected |
| Signed URL kid/hmac_keys | AuthVerifier actual rotating HMAC keyset; existing SignedUrlScope signing input unchanged |
| mTLS spiffe_id/trust_ref | AuthVerifier SPIFFE data and exact client-CA material generation; CA bytes remain separately confidential |
| JWT authorities authority_ref/issuer/audiences/enabled/key_source | Reused EdgeJwtAuthority plus AuthKeySource; discovery/URI/inline source and enabled state retained |
| JWT consumer binding claim_name/claim_value and common credential fields | Existing JwtSubjectBinding with exact strings plus explicit AuthJwtConsumer reference join |
| Legacy JWT issuer jwks/consumer_claim and common fields | Existing authority + inline source + JwtSubjectBinding, with explicit producer-supplied claim value; no legacy wire clone or inferred claim |
| webhook_hmac.secret_ref | Retired unsupported verifier reservation; no implemented catalog verification or producer value; auth consumer owns any later contract |
| HttpExternalIdentityImport.providers/anonymous_bypass/fail_closed | AuthRouteImport exact method order and flags, with explicit route id |
| ExternalIdentityProviderRef.kind/ref_id/redirect_base_url | AuthImportMethod typed kind/reference/optional OIDC redirect; OAuth2 reservation retired |
| API key last4 | Retired presentation hint; not consumed by the verifier |
| NSD provider management credentials/directory settings | Not projected; remain NSD-only, never gateway auth material |

The pinned NSD producer supplies no JWT issuers; its absence is not proof of
candidate producer support. The independent Python fixture is a labelled candidate
producer. NSD confirmation and producer-owned vectors remain outstanding. This
contract changes no family registry bytes or publication channel. Full replacement
and generation conflict handling, original expiry, OIDC refresh/rotation and
`auth_jwks_max_stale_secs` remain consumer responsibilities.
