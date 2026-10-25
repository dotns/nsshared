# Public edge

## Purpose and contracts covered

Family 7 `public-edge` carries the public routing contributions a gateway serves,
the authentication policy embedded in each realm contribution, generation-qualified
material references, and the confidential exchanges that deliver authentication
configuration and certificate or client-CA material. It also covers the confidential
service declaration, report and listener operations that carry M6 objects in their exact M6 encoding.

| Contract | Carrier | Purpose |
| --- | --- | --- |
| `PublicEdge`, `EdgeRealm`, `EdgeRoute`, `EdgeRouteOptions` | Family 7 kind `public-edge`, complete Data on the signed publication stream | Public routes, names, ports, backends and policy per contributing realm |
| `EdgeAuth`, `EdgeJwtAuthority` | Embedded in each `EdgeRealm` | Realm material set, subject bindings, JWT bindings and JWT authorities |
| `EdgeMaterialRef`, `EdgeMaterialAck` | Embedded references; ACK on the confidential report exchange | Generation-qualified dependencies and installation status |
| `AuthConfigRequest`, `AuthConfigResponse`, `AuthConfiguration` | Operation `edge.auth.config.get` | Confidential authentication configuration values |
| `EdgeMaterialRequest`, `EdgeMaterialResponse` | Operation `edge.material.get` | Confidential certificate and client-CA values |
| `EdgeServiceRequest`, `EdgeServiceResponse` | Confidential service operations | Exact M6 declarations, reports and listener intents with local floor metadata |

The family registry entry is specified in [profile.md](profile.md): publication
`public-edge`, cleared kinds `backends,names,aliases,ports,domains,subjects,auth,materials`,
scope the exact signed issuer/recipient/served_realm/scope with per-realm
contributions, and additional M6 reuse `declarations`, `listeners`, `snapshots`.
Policy subjects, bindings and rules are specified in [realm.md](realm.md); the
signed publication carrier in [publication.md](publication.md); the confidential
control carrier and report exchanges in [control.md](control.md). Provider mapping
eligibility (family 4 `provider-mappings`) is specified in [subnet.md](subnet.md).

### Common encoding

- Version 1. Every object uses shortest-form definite CBOR, strict UTF-8, exact
  tuple arity and no trailing bytes, and is at most 1,048,576 encoded bytes.
  Tags, indefinite lengths, negative integers, unknown fields, unknown
  discriminants, missing fields and null required values refuse.
- Each encoded collection has at most 256 items. Caller-supplied snapshot and
  material-ACK collections may contain up to 65,536 entries to cover all
  realm/route references.
- References and general tokens are 1 to 256 UTF-8 bytes without control
  characters or whitespace.
- Sets are strictly ordered by their documented key. The decoder never sorts,
  deduplicates or repairs input.
- Scope text follows [profile.md](profile.md#scope-text).
- `served_realm` is RealmId text and `realm_16` is binary RealmId, both per the
  [canonical RealmId](../realm-id.md).
- Identities (`recipient_I`, `backend_I`, publisher) are validated full 32-byte
  Ed25519 Node identities.

## Public-edge content

### Realm contributions

`PublicEdge` = `[1, 7, served_realm, scope, realms]`.

Each `EdgeRealm` = `[realm_16, auth_bytes, routes]`, ordered by binary realm.
`auth_bytes` is the canonical `EdgeAuth` of that realm (see
[EdgeAuth](#edgeauth)); its realm equals the contribution realm.

### Routes

`EdgeRoute` = `[id, name_or_null, aliases, domains, service_ref_bytes, backend_I_or_null,
protocol, public_port, virtual_port, policy_bytes, headers_bytes, dependencies, options]`.

- The tuple has exactly thirteen positions. Routes are ordered by id; the id is a
  token.
- `protocol` is 0 HTTP, 6 TCP or 17 UDP.
- `public_port` and `virtual_port` are 1..65535.
- `service_ref_bytes` is the canonical M6 `ServiceRef` value in a byte string.
- `policy_bytes` is `SubjectPolicy` exactly, with realm equal to the contribution
  realm. `headers_bytes` is `SignedSubjectHeaderPolicy` exactly (see
  [Signed subject headers](#signed-subject-headers)).
- Each dependency is an `EdgeMaterialRef` (see [Material references](#edgematerialref)).
  It must exist in that realm's complete material set (`EdgeAuth.materials`) at
  the exact generation.
- An enabled signed-header policy requires an auth material dependency whose
  reference equals `keyset_ref`.
- No credential, token or ACL evaluation is performed by the codec.

### Protocols and names

- HTTP requires a text name. HTTP names, aliases and domains are canonical
  lowercase ASCII DNS names of at most 253 bytes, made of dot-separated labels of
  1..63 letters, digits or hyphens with alphanumeric first and last bytes.
  Uppercase, wildcards, trailing dots and empty labels refuse.
- TCP and UDP require exactly CBOR null for the name and empty aliases and
  domains. A text name on a raw route, a null name on an HTTP route, and nonempty
  raw alias or domain collections refuse. No empty-string substitute or inferred
  hostname is accepted, and there is no fallback for named raw routes.
- Aliases and domains are each strictly ordered.
- Within a realm, names and aliases cannot collide, including within one route.
  A domain may equal its own route's name or alias; a hostname used by two
  different routes in one realm refuses.
- These public hostnames are not M6 service labels. Upstream authority, TLS SNI
  and confidential material hostnames follow their own rules.
- Producer projection: an NSD raw exposure protocol/port supplies a null name
  and empty collections; an NSD HTTP `public_host` supplies the HTTP name.

### Route options

`options` = `[transport, upstream_authority_or_null, upstream_tls_or_null,
policy_references, request_body_limit_or_null, response_body_limit_or_null,
source_ip_or_null, audit_metadata]`.

- `transport` is 0 WG, 1 WSS, 2 prefer WG, 3 prefer WSS.
- `upstream_authority` is a canonical hostname.
- `upstream_tls` is `[sni, accept_untrusted]` and always means reencryption.
  `sni` is a canonical hostname. `accept_untrusted` false requires trusted
  validation; there is no implicit fallback.
- `policy_references` holds the eleven optional token references, in order:
  middleware chain, WAF, external authorization, rate limit, connection limit,
  slow client, session limit, request rewrite, response headers, forwarded subject
  and audit. No arbitrary named extension is permitted.
- Body limits are positive u64 when supplied.
- `source_ip` is `[allow_cidrs, deny_cidrs, fail_closed]`. CIDRs use canonical
  network addresses and decimal prefix lengths, ordered uniquely by their UTF-8
  strings.
- `audit_metadata` is an ordered unique sequence of bounded token key/value pairs.
- Consumers resolve policy references through existing configuration; the codec
  never applies them. Referenced policy implementations remain consumer-owned.

### Backends and service references

- A backend is a full validated Node identity. Identity is never inferred from an
  address, display name or gateway-local backend.
- A null backend explicitly means no connector: the consumer retains discovery
  metadata, withholds forwarding and never falls back to a guessed address,
  display name or gateway-local backend. A null backend owns no Node endpoint.
- A consumer joins each non-null backend against the authenticated M6 snapshot
  `Resource` by `ServiceRef`, publisher identity, published virtual port and
  supported transport. The snapshot must belong to the signed recipient.
- Contributions spanning several M6 networks join against one authenticated
  snapshot per exact NSD/Network scope. Duplicate snapshot scopes refuse, and no
  scope is inferred from an unrelated resource.
- The validated `Resource.service_label` is the sole source of service DNS labels.
  The codec carries no standalone label and adds no standalone service-label codec
  or copied validator.

### Listener and endpoint conflicts

Discovery name, alias and domain ownership stays realm-local for HTTP. Raw routes
claim no hostname ownership; their identity is the realm-qualified route id.
Physical listener ownership is gateway-wide across every served realm in the
complete publication:

- Raw TCP and UDP listeners are identified by protocol and public port; a
  duplicate raw listener refuses.
- HTTP listeners are identified by every name, alias and domain paired with the
  listener port. Different HTTP hosts may share a port, and the same HTTP host may
  appear in different realms on distinct ports.
- Raw TCP cannot share a port with HTTP, in either contribution order.
- TCP and UDP may use the same port number because their transports are distinct.

Backend virtual ports are unique across the complete publication by full Node
identity, underlying transport and virtual port; HTTP and TCP share the TCP
transport. These gateway-wide checks do not globalize realm-qualified material
references.

### Publication and replacement

- Only family 7 kind `public-edge`, complete Data on the signed publication stream,
  may carry this content. The inner `served_realm` and `scope` equal the signed
  key exactly.
- The consumer authenticates with the publication acceptance decision before
  interpreting the payload, and commits version, expiry and content atomically
  only after validation and joins.
- All realm contributions replace the previous set under that exact key; omitted
  routes, realms and materials are removed. Empty `realms` withdraws all
  contributions; the complete empty carrier also withdraws.
- Malformed or noncanonical payloads never advance accepted versions or renew a
  previous expiry. Missing publications retain state until the original expiry.
- Different signed keys never merge into wildcard authority.
- Family 7 owns complete replacement of the embedded visitor, auth and
  public-edge values.

## Authentication policy

### Embedded policy values

`SubjectPolicy`, `SubjectBinding` and `PolicySubject` are specified in
[realm.md](realm.md) and embedded verbatim. `JwtSubjectBinding` and
`SignedSubjectHeaderPolicy` are specified below and embedded verbatim.
`SignedUrlScope` is the shared request signing input specified in
[realm.md](realm.md). These values own no publication kind; consumers
authenticate the enclosing carrier before interpreting any value, and decoding
never authenticates a caller or evaluates a rule. Display names are presentation
only.

### EdgeAuth

`EdgeAuth` = `[1, realm_16, materials, bindings, jwt_bindings, authorities]`.

- `materials` is the realm's complete `EdgeMaterialRef` set, ordered by
  kind/reference.
- `bindings` are exact `SubjectBinding` byte strings in strict canonical-byte
  order. `jwt_bindings` are exact `JwtSubjectBinding` byte strings in the same
  order.
- All subjects and bindings belong to `realm_16`.
- Each JWT authority reference resolves locally to an entry of `authorities`.

### JWT authorities

`EdgeJwtAuthority` = `[reference, issuer, audiences, key_material]`, ordered by
reference.

- `issuer` is an explicit HTTPS URL with a canonical DNS host or bracketed IPv6,
  an optional nonzero canonical decimal port, and no userinfo, backslash, fragment
  or query.
- `audiences` are nonempty ordered token strings.
- `key_material` is an auth reference present at the exact generation in
  `materials`.
- JWT verification, actual key acquisition and trust qualification stay external.

### JWT subject bindings

`JwtSubjectBinding` = `[1, binding_bytes, authority_ref, claim_name, claim_value,
scopes]`.

- It joins an already verified exact authority/claim to a credential binding;
  the binding's anchor must be a credential reference.
- `claim_name` and `claim_value` are exact UTF-8 string data, each 0 to 256 bytes
  inclusive. Empty strings are present data, distinct from a missing field. All
  original bytes are preserved, including leading, trailing and internal
  whitespace, control characters, case and Unicode normalization form. They are
  never trimmed, percent-encoded, case-folded or normalized: consumers look up the
  exact claim name and compare the exact string value.
- Missing fields, null or non-text fields, invalid UTF-8, values over the byte
  bound, non-shortest CBOR and trailing bytes refuse.
- References, subjects, HTTP header names, destination matcher tokens, URL
  realm/route labels and scope tokens retain their own syntax restrictions.
- `scopes` are opaque ordered unique whitespace-free text and never become
  `AdminScope`.
- Family 7 supplies issuer, audience and public key source metadata and material
  separately; this value neither fetches nor verifies keys.

### Signed subject headers

`SignedSubjectHeaderPolicy` = `[1, enabled, header_name_or_null,
signature_header_name_or_null, keyset_ref_or_null, validity_seconds_or_null,
strip_inbound]`.

- Header names are lowercase HTTP tokens and distinct when both are present.
- An enabled policy requires all four optional fields, positive validity and
  inbound stripping. A disabled policy with partial settings grants no header
  authority.
- Key material and signed-header production remain with family 7 and gateway
  consumers; an enabled policy requires the matching auth dependency described in
  [Routes](#routes).

### Signed URL keys

`SignedUrlScope` remains the request-borrowed signing input with no second
canonicalization. Key selection uses auth material references, never serialized
HMAC or private key bytes.

### Anonymous selectors and verified-only matching

`EdgeRoute.policy` carries the explicit `SubjectSelector` of `SubjectPolicy`
verbatim for HTTP, TCP and UDP. `Anonymous` is the byte string containing
canonical CBOR `[1, 3]` (`82 01 03`, outer byte string `43 82 01 03`). It is a
rule selector, never a `PolicySubject` and never a null wildcard. A consumer that
does not implement the selector refuses it rather than reading it as null or an
identity. `AnyVerified` (null) and `Subject` selector bytes are unaffected.
Credential bindings, group members, admin claims and signed identity subjects
keep their own types and bytes.

Matching:

- Only a trusted ingress adapter may classify an observed unauthenticated visitor
  as Anonymous, without fabricating a subject or carrying a `PolicySubject`
  payload. Missing or untrusted input denies.
- A verified principal never matches Anonymous. `AnyVerified` and explicit
  subject or expanded group selectors match verified principals only; null never
  matches an anonymous visitor.
- "Verified matching subject/group" means a verified principal equal to the
  subject selector, or a member of the selector's explicit group entry. Group
  expansion uses the realm-qualified members. A group label presented as the
  principal is refused input and denies under every selector, like missing or
  untrusted input.
- After selector matching, consumers still check the actual backend destination,
  port and protocol, with default deny. Verified-only callers keep their meaning.

| Selector | Explicit anonymous visitor | Verified matching subject/group | Verified other subject | Missing/untrusted |
| --- | --- | --- | --- | --- |
| AnyVerified (null) | deny | match | match | deny |
| Subject | deny | match | deny | deny |
| Anonymous | match | deny | deny | deny |

Routes without an Auth dependency:

- An explicitly anonymous HTTP route or TCP/UDP listener needs no Auth dependency.
- Absence of Auth alone authorizes nothing: an exact matching Anonymous rule must
  admit the actual backend destination, port and protocol.
- Source-IP checks, served realm and source lifetime, connector availability,
  independently bound activation, certificate and client-CA dependencies,
  withdrawal and transport restrictions still apply.

Routes with an Auth dependency:

- The route retains the exact installed configuration/generation of its Auth
  dependency and the `AuthRouteImport` behavior, including ordered methods,
  `anonymous_bypass` and `fail_closed`, which keep their types and bytes.
- An Anonymous selector never skips a required dependency or converts failed
  required authentication into bypass.
- An explicitly allowed anonymous-bypass outcome matches Anonymous only, never
  `AnyVerified` (null) or an explicit subject/group selector.
- Ordered methods, default versus ACL-selected OIDC and the redirect host are
  unaffected by the selector.

The codec only validates and carries these facts; matching and forwarding stay
external.

## Material references and acknowledgements

### EdgeMaterialRef

`EdgeMaterialRef` = `[kind, reference, generation]`.

- `kind` is 0 auth, 1 certificate, 2 client CA.
- `reference` is a token; it is an opaque reference, never secret bytes or a
  filesystem path.
- `generation` is a positive u64.
- Reference sets are ordered by kind/reference.

The public content carries references only. Certificates, CA bytes, verifier
hashes, HMAC secrets and cookie secrets are carried by the confidential
exchanges below, never in a public-edge publication.

### EdgeMaterialAck

`EdgeMaterialAck` = `[1, request_id_16, served_realm, scope, realm_16, material,
status]`; `status` is 0 installed, 1 rejected.

- The gateway reports installed only after actual installation of the exact
  material reference and generation, never on mere receipt. A receipt cannot
  cause installation.
- For auth configuration, `request_id` is the exact request id of the pending
  `AuthConfigRequest`.
- For certificate and client-CA material, `request_id` is a separately
  gateway-minted installation-status id that is unique per report, not the
  acquisition request id. The gateway retains the local association with the
  acquisition and the full material scope/generation.
- The ACK is transported with the exact report/receipt correlation of the
  material status exchange in [control.md](control.md).
- Receivers compare the request id, all realm and scope fields and the full
  material kind/reference/generation against the exact retained context.

### Route readiness

- Routes remain withheld until every referenced dependency is installed and
  acknowledged; all dependencies precede route exposure.
- A rejected ACK or a missing or different generation is never ready.
- Retaining only a numeric generation without its kind, reference and realm
  cannot establish readiness.
- Consumer installation and route readiness remain external to the codec.

## Confidential authentication configuration exchange

### Encoding

The common encoding applies. Data strings preserve exact UTF-8,
including spaces, with 1 to 8192 bytes; optional data uses null for absence, never
an empty required value. No normalization occurs. Tokens use the account token
syntax.

### Delivery

`AuthConfigRequest` = `[1, request_id_16, recipient_I, served_realm, scope,
realm_16, material]`. `material` is an `EdgeMaterialRef` and must be kind auth.

`AuthConfigResponse` = `[1, request_bytes, configuration_bytes]`. It echoes the
complete request, including the recipient.

- Only operation `edge.auth.config.get` (`EDGE_AUTH_CONFIG_GET`) in the
  `BootstrapEnvelope` request and response directions over the confidential
  control transport carries these objects. The operation is auth-only.
- They never occur in `PublicEdge`, signed publication content, public HTTP
  discovery, logs or URLs.
- Envelope domains, signing inputs, effective pins, nonce replay retention and
  time validation are those of the envelope ([control.md](control.md)).
- The consumer verifies the envelope before decoding the configuration and
  requires an explicit envelope recipient. The request envelope recipient is the
  accepted authority; the response envelope recipient is the request's gateway
  recipient. The authenticated signer and recipient must match the configured or
  accepted binding; body correlation alone grants no authority.
- The exchange defines no family registry entry or publication channel.

### Correlation

`validate_for(pending, current_realm, current_material)` compares, in order:

1. request id, recipient, served realm, scope, contributing realm and exact
   material kind/reference/generation against `pending`;
2. payload realm and generation;
3. the current authenticated `PublicEdge` dependency, which must also be present
   verbatim in `public_auth.materials`.

Each mismatch is a typed refusal (`AuthConfigError`: `Correlation`, `Scope`,
`Realm`, `Reference`, `Generation`, `Dependency`, or `Contract` for malformed
data). A pending request cannot satisfy a current dependency that has since changed.
Authority and accepted-binding checks remain consumer-owned. Validation performs
no installation, replay storage, publication or ACK. Only actual installation of
the exact reference and generation can produce an installed `EdgeMaterialAck`.

### Configuration tuples

`AuthConfiguration` = `[1, realm_16, generation, default_provider_ref_or_null,
providers, cookie_keys, consumers, credentials, public_auth_bytes, key_sources,
jwt_consumers, imports]`.

- `generation` is a positive u64.
- `public_auth` is an `EdgeAuth` with the same realm; credential bindings are
  included there verbatim.
- The configuration supplies values, never inferred secrets, and implies no
  defaults.
- `cookie_keys` is an `AuthSecretSet`.

`AuthSecretVersion` = `[reference, version, expires_seconds, value]`.

- `version` is a positive u32, `expires_seconds` a positive u64, and `value`
  required exact data. No reference supplies a value.
- `AuthSecretSet` = `[current, previous]`. Previous versions are strictly
  increasing, unique, below `current.version`, and share `current.reference`.
- Actual expiry, overlap and key usability remain catalog checks; the codec reads
  no clock. Secret-bearing `Debug` output is redacted.

`AuthProvider` = `[reference, kind, issuer, client_id, client_secret, scopes,
audience_or_null, subject_template_or_null, idp_template_or_null, subject_realm,
organization_id_or_null, organization_mode_or_null, redirect_base_url]`.

- `kind` 0 is OIDC, the only kind.
- Organization mode null means generic; 0 means Logto and requires
  `organization_id`. Logto retains organization scope, consent and resource-token
  exchange semantics.
- Templates and the external namespace are exact data, not a control realm or a
  principal grant.
- `issuer` and `redirect_base_url` are explicit HTTPS URLs without whitespace or
  control characters. Discovery, URL screening, template evaluation and OIDC
  verification stay external.
- `scopes` are ordered unique tokens. Providers are ordered by reference.
- A present default names an existing provider; null selects none, never a
  guessed default.

`AuthConsumer` = `[reference, subject_bytes, enabled, display_name_or_null]`.

- The subject is a `PolicySubject`, realm-qualified and non-group. The display
  name is presentation only. Consumers are ordered by reference.

`AuthCredential` = `[consumer_ref, binding_bytes, scopes, verifier]`.

- The binding is a `SubjectBinding` with a credential anchor, matching the
  consumer's explicit subject and realm and present in `public_auth.bindings`.
- Credential enabled state and expiry live in that binding; consumer enablement
  remains independent.
- Credentials are ordered by anchor reference. Anchors are unique across all
  private verifier credentials and JWT bindings, including distinct JWT claims;
  one anchor cannot identify more than one credential method.
- `verifier` is `[0, key_id, verifier_hash]` API key, `[1, username, phc_hash]`
  Basic, `[2, kid, hmac_keys]` signed URL, or `[3, spiffe_id, trust_material]`
  mTLS. `hmac_keys` is an `AuthSecretSet`. `trust_material` is an
  `EdgeMaterialRef` of kind client CA, present in `public_auth`. Hashes and keys
  are required actual data; plaintext API keys and passwords are never carried.
- Verification algorithms, hash parsing, SPIFFE validation and actual deadlines
  stay with their consumers.

`AuthKeySource` = `[authority_ref, enabled, kind, value_or_null]`, ordered by
`authority_ref`.

- `kind` 0 OIDC discovery requires null; 1 fixed HTTPS JWKS URI and 2 inline
  public JWKS require data.
- A fixed acquisition URI preserves exact query bytes, including order, repeated
  parameters, literal plus and percent-escape spelling. It requires a canonical
  HTTPS host, an optional port and valid percent escapes; whitespace, control
  characters, userinfo, backslashes, fragments and values over 8192 UTF-8 bytes
  refuse. Queries are not subject to the issuer query prohibition. Provider issuer
  and provider/route redirect restrictions are unaffected.
- Each `public_auth.authorities` entry has exactly one source and each source
  exactly one authority. Authority issuer, audiences, material and
  `JwtSubjectBinding` are reused verbatim. Public key trust qualification and
  JWKS parsing stay external.

`AuthJwtConsumer` = `[credential_ref, consumer_ref]`, ordered uniquely by
`credential_ref`.

- There is exactly one join per `JwtSubjectBinding`, and each join matches the
  binding subject to that consumer. Equal subjects never imply a join.
- Consumer enablement stays independent from credential enablement.

`AuthRouteImport` = `[route_id, methods, anonymous_bypass, fail_closed]`, ordered
by `route_id`.

- `AuthImportMethod` = `[kind, reference, redirect_or_null]`. Method order is
  evaluator order; duplicate kind/reference pairs refuse.
- Kinds are 0 OIDC, 1 client mTLS, 2 API key, 3 bearer JWT, 4 signed request,
  5 Basic. OAuth2 is not a method.
- OIDC references a provider; bearer a public authority; mTLS a client-CA
  material. API key, signed request and Basic carry an opaque method-catalog
  selector (including the producer-supplied `__ns_realm__` selector); they do not
  select a credential before a request presents its key id, signature kid or
  username.
- Redirect overrides are HTTPS data and allowed only for OIDC; null uses the
  provider's explicit redirect.
- An empty chain remains explicitly empty, with no implicit provider substitution.
  The producer resolves an empty or default OIDC chain to an explicit provider
  before encoding; consumers apply no fallback.
- Route ownership and import-to-route joins are checked by the consumer against
  the current public contribution; this object creates no route or membership
  authority.

### Consumer responsibilities

Full replacement and generation conflict handling, original expiry, OIDC
refresh/rotation and `auth_jwks_max_stale_secs` remain consumer responsibilities.

## Confidential certificate and client-CA material exchange

### Carrier

`edge.material.get` (`nsshared_control::account::control::EDGE_MATERIAL_GET`) uses
the authenticated confidential `BootstrapEnvelope` request/response carrier and
signed control endpoint ([control.md](control.md)). No certificate, private key or
CA bytes travel in a public-edge publication. `edge.auth.config.get` remains
auth-only. There is no acquisition runtime or I/O in the contract.

### Request

`EdgeMaterialRequest` = `[1, request_id, recipient, served_realm, scope, realm,
material]`, with the same encodings as `AuthConfigRequest`:

- `request_id` is exactly 16 bytes, minted independently of the envelope replay
  nonce.
- `recipient` is a validated 32-byte Ed25519 `IdentityKey`.
- `served_realm` is canonical RealmId text; `realm` is 16 binary RealmId bytes.
- `scope` follows [profile.md](profile.md#scope-text).
- `material` is an `EdgeMaterialRef` whose kind is Certificate (1) or ClientCa
  (2). Auth (0) and unknown kinds refuse.

### Success response

`EdgeMaterialResponse` = `[1, request_bytes, hostnames, not_after_unix_seconds,
values]`.

- `request_bytes` is a byte string containing the complete canonical request. It
  is not a partial correlation or a digest; the consumer compares it byte for byte
  with the complete pending canonical request.
- `hostnames` contains 0 to 256 strictly increasing unique hostnames under the
  `PublicEdge` hostname rules (ASCII, 1 to 253 bytes, labels of 1 to 63 lowercase
  alphanumeric or hyphen bytes starting and ending alphanumeric, separated by
  dots). Uppercase, wildcards, trailing dots, empty labels, duplicates and
  reordered names refuse. The list limits material use and never grants route
  authority.
- `not_after_unix_seconds` is an exclusive unsigned u64 Unix-seconds deadline,
  never milliseconds. The consumer supplies its own clock and rejects expired
  material; the codec reads no clock and permits every unsigned value, including
  an already expired zero.
- `values` is exactly `[1, fullchain_pem, private_key_pem]` for Certificate or
  `[2, ca_pem, trust_domain]` for ClientCa, matching the request kind. PEM fields
  are nonblank UTF-8 text, preserving newlines and optional CA CRLs verbatim; no
  PEM or X.509 parsing occurs. `trust_domain` is a token; semantic comparison and
  SPIFFE validation remain with the consumer.
- No null, missing, empty or whitespace-only PEM represents successful
  acquisition. Unavailable material uses the authenticated operation failure
  instead.

### Bounds

Every request, response and nested request is bounded by the 1 MiB account limit.
Each PEM text is individually bounded by that limit, and the entire encoded
response must also fit it. The confidential carrier limits still apply to the
final envelope, including its overhead.

### Validation API

- `EdgeMaterialRequest { request_id: [u8; 16], recipient: IdentityKey,
  served_realm: RealmId, scope: String, realm: RealmId, material: EdgeMaterialRef }`.
- `EdgeMaterialValues::Certificate { fullchain_pem: String, private_key_pem: String }`
  and `ClientCa { ca_pem: String, trust_domain: String }`, with redacted `Debug`.
- `EdgeMaterialResponse { request: EdgeMaterialRequest, hostnames: Vec<String>,
  not_after_unix_seconds: u64, values: EdgeMaterialValues }`.
- Request and response `canonical(&self) -> Result<Vec<u8>, EdgeMaterialError>`
  and `decode(bytes: &[u8]) -> Result<Self, EdgeMaterialError>`.
- Response `validate_for(&self, pending: &EdgeMaterialRequest)
  -> Result<(), EdgeMaterialError>` validates both values and the complete
  canonical echo. Typed refusals are `Contract(AccountError)`, `Kind`, `Realm`,
  `Generation` and `Echo`. A wrong echoed realm or generation has its own refusal;
  every other valid but different request field returns `Echo`. `Kind` covers
  forbidden request kinds and request/value disagreement.

### Consumer obligations

- NSD checks the authenticated requester and the requested recipient, scope,
  realm, reference and generation against authorized material custody before
  release.
- The gateway verifies signer, explicit recipient, operation and envelope
  response correlation against accepted control custody before consuming these
  payloads. It rechecks the full dependency against the current authenticated
  `PublicEdge` view; a delayed acquisition cannot restore a replaced or withdrawn
  dependency.
- The gateway joins permitted hosts with current realm-qualified routes and
  requires coverage for each activating host. For ClientCa it compares
  `trust_domain` with the current validated auth configuration for that exact CA
  reference.
- Certificate/key matching, certificate host coverage, CA/CRL and X.509 parsing,
  supplied-clock validity, limiting the deadline to certificate validity and
  actual installation remain with the gateway installer. Acquisition success is
  not installed readiness; installation status uses `EdgeMaterialAck`.

## Service declarations, floors, reports, responses and ACKs

`EdgeServiceRequest` and `EdgeServiceResponse` carry M6 objects on the
confidential service operations ([control.md](control.md)). Body kinds are
0 declaration (`Declaration`), 1 report (`ReportContent`) and 2 listener
(`ListenerIntent`); no other M6 message kind is introduced, and the M6 bytes and
serializers are used as is.

Kinds 0 and 2 use nine-field tuples:

- request `[1, request_id, publisher, nsd_id, network_id, revision, kind,
  body_bytes, digest]`;
- response `[1, request_id, publisher, nsd_id, network_id, revision, kind,
  digest, status]` with a whole-content accepted/rejected status.

Kind 1 is the complete local floor report:

- request `[1, request_id, publisher, nsd_id, network_id, revision, 1,
  exact_M6_ReportContent_bytes, metadata, exit_profiles, digest]`;
- metadata holds exactly one `[declaration_key, capabilities, policy_labels]` per
  submitted M6 declaration, in declaration-key order; Exit profiles are
  non-authoritative declarations that reuse `SubnetSelection`/`SubnetPrefix`
  semantics and never carry Subnet route authority;
- the floor digest covers the M6 report bytes, all declaration metadata and every
  Exit profile;
- the response keeps the first eight fields, including that digest, and its last
  field is the per-reference outcomes `[accepted_services, accepted_exit_profiles,
  rejected]`.

The kind 1 tuples, digest domain and outcome rules are specified in
[control.md](control.md).

Correlation and outcomes:

- Scope (publisher, NSD and Network), request id, revision, body kind and the
  entire digest must match the exact pending request
  (`EdgeServiceResponse::validate_request`).
- Unknown or missing submitted-reference outcomes are typed refusals
  (`EdgeServiceAckError`).
- Rejection carries a reason and creates no readiness. Acceptance records
  submitted content only, never listener readiness or route authority.

## Code and vectors

Public items are at `nsshared_control::account::edge` unless noted.

| Contract | Source | Public items |
| --- | --- | --- |
| Public-edge content | `crates/nsshared-control/src/account/families/edge/routing.rs` | `PublicEdge` (`canonical`, `decode`, `validate_publication`, `validate_snapshot`, `validate_snapshots`, `validate_materials`), `EdgeRealm`, `EdgeRoute`, `EdgeProtocol`, `EdgeRouteOptions`, `EdgeTransport`, `EdgeUpstreamTls`, `EdgeSourceIp` |
| Embedded auth | `crates/nsshared-control/src/account/families/edge/auth.rs` | `EdgeAuth`, `EdgeJwtAuthority` |
| Material references | `crates/nsshared-control/src/account/families/edge/material.rs` | `EdgeMaterialRef`, `EdgeMaterialKind`, `EdgeMaterialAck` (`validate_installation`), `MAX_EDGE_ITEMS` |
| Confidential auth exchange | `crates/nsshared-control/src/account/families/edge/auth.rs`, `crates/nsshared-control/src/account/families/edge/auth/values.rs` | `AuthConfigRequest`, `AuthConfigResponse` (`validate_for`), `AuthConfigError`, `AuthConfiguration`, `AuthSecretVersion`, `AuthSecretSet`, `AuthProvider`, `AuthProviderKind`, `AuthOrganizationMode`, `AuthConsumer`, `AuthCredential`, `AuthVerifier`, `AuthKeySource`, `AuthKeySourceKind`, `AuthJwtConsumer`, `AuthRouteImport`, `AuthImportMethod`, `AuthMethodKind` |
| Confidential material exchange | `crates/nsshared-control/src/account/families/edge/material_request.rs` | `EdgeMaterialRequest`, `EdgeMaterialResponse` (`validate_for`), `EdgeMaterialValues`, `EdgeMaterialError` |
| Service operations | `crates/nsshared-control/src/account/families/edge/declaration.rs` | `EdgeServiceRequest`, `EdgeServiceResponse` (`validate_request`), `EdgeServiceBody`, `EdgeServiceMetadata`, `EdgeExitProfile`, `EdgeFloorOutcomes`, `EdgeFloorRejection`, `EdgeServiceAckError` |
| Operation names | `crates/nsshared-control/src/account/control/methods.rs` | `nsshared_control::account::control::EDGE_AUTH_CONFIG_GET`, `nsshared_control::account::control::EDGE_MATERIAL_GET` |
| Embedded policy values | `crates/nsshared-control/src/account/families/realm/claims.rs` | `nsshared_control::account::realm::JwtSubjectBinding`, `nsshared_control::account::realm::SignedSubjectHeaderPolicy` |

Tests and vectors (`crates/nsshared-control/tests/account/edge/`):

| Test module | Vectors | Coverage |
| --- | --- | --- |
| `account::edge::routing` | `crates/nsshared-control/tests/vectors/account/edge/routing.vec` | Complete replacement, valid empty withdrawal, malformed/noncanonical refusal without renewal, names, aliases, ports and domains, full backend identity joins against authenticated M6 resources, material generation mismatch, exact pending context for material and service ACKs, dependency installation before exposure, exact M6 object bytes and digests; `public_edge_protocol_names` covers HTTP host bytes, unnamed TCP/UDP on one numeric port with distinct backend endpoints, protocol/name mismatches, nonempty raw name collections and listener conflicts |
| `account::edge::routing_scope` | | Gateway-wide listener, HTTP hostname/port, HTTP/TCP overlap and backend endpoint ownership; realm-qualified discovery names and material references |
| `account::edge::routing_listeners` | | Served realms cannot claim the same TCP listener |
| `account::edge::anonymous` | `crates/nsshared-control/tests/vectors/account/edge/anonymous.vec` | Anonymous selector encoding and order, matching table, refusal of group-label principals |
| `account::edge::auth` | `crates/nsshared-control/tests/vectors/account/edge/auth.vec` | `confidential_auth_generation`: pending/current dependency correlation and private configuration refusals |
| `account::edge::auth_anchors` | | Credential anchor uniqueness across JWT and private verifiers |
| `account::edge::auth_jwks` | | Fixed JWKS URI query preservation |
| `account::edge::material_request` | `crates/nsshared-control/tests/vectors/account/edge/material-request.vec` | `confidential_edge_material_generation`: certificate/key and client-CA bytes at generation 7 with complete request echoes; refusal of wrong realm/generation, changed echo, other-kind values, Auth and unknown kinds, missing/unknown fields, noncanonical and oversized encodings and empty values |
| `account::edge::floor_text` | `crates/nsshared-control/tests/vectors/account/edge/floor-text.vec` | Floor data text |
| `account::edge::declaration_keys` | | Floor keeps spaced declaration keys, Exit references and policy labels |

Raw-route vectors, including anonymous-policy vectors, carry null names. The
embedded policy values are also covered by `account::realm::claims` and
`account::realm::claim_strings` with
`crates/nsshared-control/tests/vectors/account/realm/claims.vec`. Report
exchange vectors are `crates/nsshared-control/tests/vectors/account/control/reports.vec`
(`account::control::reports`). M6 objects use the service vectors
`crates/nsshared-control/tests/vectors/service/canonical.json`
(`service::canonical`) directly; they are never copied or re-encoded as account
vectors.
