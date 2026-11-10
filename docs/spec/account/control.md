# Account control layer

The account control layer is the set of pure contracts a Node and its NSD use to
discover each other, exchange signed confidential requests and responses, enroll
and authenticate a Node, report observations, issue Node route commands, report
Node L3 application, and carry M6 service control. The contracts define exact
bytes, bounds, signature domains, correlation and comparison predicates. They add
no transport execution, session runtime, credential custody, key acquisition,
pin-store or other I/O, and no signing keys: clocks, replay observations,
authentication results and accepted state are supplied by the caller.

Membership realm text throughout this document is the exact canonical
26-character spelling of [canonical RealmId](../realm-id.md); binary realm
positions are its exact 16 bytes.

Contracts covered:

- Bootstrap discovery (`BootstrapDiscovery`, `ConfidentialCarrier`, `EnvelopePins`).
- Signed confidential carrier (`BootstrapEnvelope`, `EnvelopeExpectation`) and
  its boundaries (`ControlBoundary`, `validate_control_input`).
- Operation names and endpoint paths (`nsshared_control::account::control::*`
  constants).
- Registration, authentication and information exchanges, including source
  authority in responses and explicit authentication source selection.
- Machine tokens and key sets (`MachineClaims`, `RsaJwk`, `JwkSet`).
- Control reports: heartbeat, gateway observations, service and Exit floors,
  usage and material status.
- Signed account requests and signed URL request inputs (`SignedAccountRequest`,
  `SignedUrlScope`).
- Node route commands and immutable receipts (`RouteCommand`, `RouteReceipt`,
  `RouteResponse`).
- Node L3 applied status (`node.l3.status`).
- M6 service control carrier (`service.control.v1`).

The publication subscription, publication stream framing and independent
publication snapshot poll are specified in [publication](publication.md); source
authority (`SourceBinding`, `SignedSourceBinding`) and source-bound publications
are also specified there. Local Node naming and the retirement of legacy
registration naming values are specified in [Node](node.md#local-node-naming).

## Bootstrap discovery

Bootstrap discovery is the payload contract of family 11 `v1-replacement`; it
changes neither the family registry nor its bytes. Enrollment remains a distinct
membership binding publication (see [Node](node.md#enrollment)). The caller obtains
discovery through HTTPS WebPKI, supplies the authenticated HTTPS origin, clock
and replay observations, and performs transport execution. No legacy key field,
JSON fallback, discovery age denial or plaintext is defined.

The client requests `GET DISCOVERY_PATH` (`/api/v1/info`) with exactly
`Accept: application/cbor`, using `DISCOVERY_MEDIA_TYPE`. This selector chooses
the canonical family-11 `BootstrapDiscovery` CBOR tuple. The response carries
`Content-Type: application/cbor` (the same `DISCOVERY_MEDIA_TYPE`) and
`Vary: Accept` to keep cached representations separate. An absent Accept, a
wildcard-only Accept or any other request gets the producer's other
representation, which is outside this contract. The client decodes only the
CBOR tuple and has no fallback to that other representation.

Discovery CBOR is `[1, 1, https_origin, [1], endpoints, noise_key_or_null,
quic_spki_pins, envelope_pins]`: schema, trust version, authenticated discovery
origin, supported envelope versions, ordered endpoints and trust material.

- An endpoint is `[kind, origin]`, with kinds 0 HTTPS, 1 Noise, 2 QUIC only.
- Origins are exact ASCII `scheme://host[:port]/`, without userinfo, path beyond
  `/`, query or fragment.
- Hosts are lowercase DNS labels (1..63 alphanumeric or interior hyphen, total at
  most 253 bytes, no terminal dot), canonical dotted IPv4, or bracketed canonical
  compressed hexadecimal IPv6. DNS hosts whose final label is an IPv4 number are
  refused unless already canonical dotted IPv4.
- HTTPS omits default port 443; Noise and QUIC require an explicit nonzero
  decimal u16 port without leading zeroes.
- Unicode hosts must already be canonical ASCII IDNA labels. DNS hosts must pass
  UTS #46 ToASCII with URL forbidden-domain-code-point checking, and its ASCII
  result must equal the supplied hostname exactly. Malformed Punycode, forbidden
  decoded characters and noncanonical A-labels fail; validation never rewrites a
  hostname. The same predicate applies to the HTTPS source and every endpoint
  kind.
- Discovery itself requires HTTPS.
- Endpoints are nonempty and duplicate-free and retain advertised preference
  order; validation never sorts, normalizes or attempts a fallback. A caller
  selects the first supported endpoint in this validated order
  (`BootstrapDiscovery::first_supported`); all three kinds are confidential.
- Noise needs the optional raw 32-byte static X25519 key; QUIC needs nonempty
  SPKI pins.
- Pins are canonical unpadded base64url SHA-256 values (43 ASCII bytes),
  duplicate-free in advertised order. QUIC pins hash the full DER
  SubjectPublicKeyInfo. Envelope pins are RFC 7638 Ed25519 JWK thumbprints:
  SHA-256 of exact UTF-8 `{"crv":"Ed25519","kty":"OKP","x":"<base64url public key>"}`.
- Envelope pins are nonempty. Local pins are validated identically; when
  configured, the effective set is their intersection with discovered pins, in
  discovery order (`EnvelopePins::intersect`,
  `BootstrapDiscovery::effective_envelope_pins`). An empty intersection is
  refused. Legacy fields cannot supply missing trust.

Envelope signer pins are a trust purpose separate from machine token key pins
and are never used as token key pins.

The consumer transport parameters are Noise `Noise_IK_25519_ChaChaPoly_BLAKE2s`
with a two-byte frame length prefix, and the `nsd-http1` ALPN for QUIC; transport
execution is consumer-owned.

## Signed confidential carrier

### Envelope and signature domains

The authenticated carrier is `[content_bytes, signature_64_bytes]`. Content CBOR
is `[1, direction, signer_I, recipient_I_or_null, kind, unix_seconds, nonce_16,
payload_bytes]`; direction 0 is request and 1 is response. The signature is
Ed25519 over `ns.account.call.request.v1\0 || content_bytes` or
`ns.account.call.response.v1\0 || content_bytes`, where `\0` is one zero byte
(`domains::ACCOUNT_REQUEST_DOMAIN`, `domains::ACCOUNT_RESPONSE_DOMAIN`). These
domains are specific to this carrier.

- The signer is the issuer, validated as an identity key and against
  caller-established effective pins in both directions; request verification uses
  pins for its authorized request issuers.
- Every signature is verified; absence of a pin never bypasses verification.
- Verification (`BootstrapEnvelope::verify` with an `EnvelopeExpectation`)
  requires the expected direction and exact nonempty kind (operation); an optional
  recipient must equal the caller's expected identity. A response without a
  recipient is permitted for bootstrap, but is still pinned and signed.
- The payload is opaque. M6 `Message::encode` bytes remain unchanged inside it;
  no M6 message or raw M6 envelope is duplicated.
- `BootstrapEnvelope::signing_input()` is the sole public pure
  domain-plus-canonical-content encoder, for both request and response; signing
  and private keys stay outside the contract.

### Boundaries

Limits count encoded bytes, including CBOR overhead.

| Boundary | Maximum | Meaning |
| --- | ---: | --- |
| Discovery (`MAX_BOOTSTRAP_BYTES`) | 262,144 bytes | Complete discovery document |
| Call body (`MAX_CONTROL_BODY`) | 8,388,608 bytes | Complete unary response body / signed carrier |
| Headers (`MAX_CONTROL_HEADERS`) | 16,384 bytes | Complete HTTP response headers |
| Encoded subscription (`MAX_ENCODED_SUBSCRIPTION`) | 16,384 bytes | Subscription envelope before hex/base64 decoding |
| Noise payload (`MAX_CONTROL_NOISE_PAYLOAD`) | 65,519 bytes | Plaintext excluding authentication tag |
| Noise frame (`MAX_CONTROL_NOISE_FRAME`) | 65,535 bytes | Ciphertext including 16-byte authentication tag, excluding two-byte length prefix |
| Clock skew (`CONTROL_CLOCK_SKEW_SECONDS`) | 60 seconds | Absolute difference between signed timestamp and supplied time, inclusive |
| Replay retention (`CONTROL_REPLAY_WINDOW_SECONDS`) | 120 seconds | Previously accepted issuer/direction/nonce retained for this inclusive window |

`validate_control_input` checks the exact supplied boundary bytes before decoding
or handing them to a transport. Discovery and carrier decoders also enforce their
own total limits and nested declared lengths before allocation. Kind length is
1..256 UTF-8 bytes. Endpoint and pin counts are limited by the discovery byte
bound, not by a separate small rotation limit. Typed errors (`BootstrapError`)
distinguish version, origin, endpoint kind, duplicate endpoints, missing
Noise/QUIC trust, invalid pins, empty pins/intersection, signer, recipient, kind,
direction, skew, replay, signature, bounds and canonical encoding errors. Unknown
fields, nonminimal CBOR and trailing data fail. Constructed values obey the same
checks as decoded values.

### Clock and replay

Replay state is external: the caller supplies the previous acceptance time for
this exact `(signer_I, direction, nonce)` after authentication. A previous
observation at most 120 seconds old (or in the future) refuses replay. The caller
must retain observations through that window and atomically record success;
`None` asserts no retained observation. This contract neither stores nonces nor
claims state-free replay prevention. Timestamp skew remains 60 seconds even when a
nonce observation has aged beyond replay retention. There is no JSON path.

## Operations and endpoint paths

Operation names and endpoint paths are defined once, as constants at
`nsshared_control::account::control`. All signed operations use the confidential
control endpoint. Discovery uses the WebPKI information endpoint and machine
signing keys use the key-set endpoint. No JSON fallback or plaintext carrier is
supported. Unknown operations are refused.

| Constant | Value | Specified in |
| --- | --- | --- |
| `CONTROL_ENVELOPE_PATH` | `/api/v1/control` | this document |
| `DISCOVERY_PATH` | `/api/v1/info` | this document |
| `DISCOVERY_MEDIA_TYPE` | `application/cbor` | this document |
| `JWKS_PATH` | `/.well-known/jwks.json` | this document |
| `MACHINE_REGISTER` | `machine.register` | this document |
| `MACHINE_AUTH` | `machine.auth` | this document |
| `MACHINE_AUTH_PURPOSE` | `control` | this document |
| `INFO_GET` | `info.get` | this document |
| `MACHINE_HEARTBEAT` | `machine.heartbeat` | this document |
| `GATEWAY_REPORT` | `gateway.report` | this document |
| `GATEWAY_SERVICES_REPORT` | `gateway.services_report` | this document |
| `GATEWAY_USAGE_REPORT` | `gateway.usage_report` | this document |
| `GATEWAY_MATERIAL_STATUS` | `gateway.material_status` | this document |
| `NODE_ROUTE_SELECT` | `node.route.select` | this document |
| `NODE_ROUTE_CLEAR` | `node.route.clear` | this document |
| `NODE_L3_STATUS` | `node.l3.status` | this document |
| `SERVICE_CONTROL` | `service.control.v1` | this document |
| `CONFIG_STREAM`, `CONFIG_STREAM_PATH` | `config.stream`, `/api/v1/config/stream` | [publication](publication.md#subscription-requests-and-stream-delivery) |
| `CONFIG_SNAPSHOT`, `CONFIG_SNAPSHOT_PATH` | `config.snapshot`, alias of `/api/v1/control` | [publication](publication.md#snapshot-poll-requests) |
| `EDGE_AUTH_CONFIG_GET` | `edge.auth.config.get` | [edge](edge.md#confidential-authentication-configuration-exchange) |
| `EDGE_MATERIAL_GET` | `edge.material.get` | [edge](edge.md#confidential-certificate-and-client-ca-material-exchange) |
| `NODE_SUBNET_REPORT` | `node.subnet.report` | [subnet](subnet.md#provider-subnet-route-reports) |

Requests and answers are payload bytes of `BootstrapEnvelope`. A caller uses a
confidential authenticated `BootstrapDiscovery` carrier and verifies the envelope
with `EnvelopeExpectation` before interpreting payloads. Nonces, skew, replay
observations and signing domains are exactly those of the signed carrier above.

The exchanges reuse the enrollment binding, lifecycle and capabilities of
[Node](node.md) and the bootstrap carriers and signing input above; they define no
publication kind and change no family registry bytes.

## Registration and authentication exchanges

### Common tuple rules

All exchange tuples use shortest definite CBOR, schema 1, no trailing bytes, and
the account size limit. Nested contracts are exact canonical byte strings.
Membership realm text is the canonical RealmId spelling. Other text fields are
nonempty control-free UTF-8 of at most 256 bytes. Capabilities reuse Enrollment's
sorted unique bounded identifier set. No normalization occurs.

Membership scope (`MembershipScope`) is `[nsd_id_16, network_id_16]`.

### Registration

Registration (`machine.register`) requests must be signed by the presented
enrollment binding's I. Answers must be signed by the trusted authority, response
directed, with the matching operation and recipient.

`RegistrationRequest` is `[1, scope, enrollment_bytes, profile, credential_bytes,
lifecycle_bytes_or_null]`.

- Credential is opaque, nonempty and at most 16 KiB; it is interpreted only by the
  provisioned authority. Provisioning selects the credential; no auth-key or OAuth
  inference or fallback occurs.
- Lifecycle is absent for initial enrollment and otherwise reuses `Lifecycle`
  (see [Node](node.md#registration-only-placeholders)). Its last two mandatory 16-byte slots are
  registration-only placeholders: the requesting Node supplies sixteen zero bytes
  in each, including without grants or a reporter. Receivers decode them
  structurally and ignore their values, including nonzero values; nonzero values
  are structural receiver coverage, not a registration producer form. No response
  or token acquisition produces them. They are neither authority nor transition
  inputs or custody.

`RegistrationAcceptance` is `[1, scope, enrollment_bytes, profile, decision,
source_binding_bytes]`.

- Decision is 0 initial, 1 equal, 2 identity replacement, 3 record rotation.
- `source_binding_bytes` is the canonical byte string of `SignedSourceBinding`
  (see [Source authority in responses](#source-authority-in-responses)).
- Matching compares scope, the entire binding (I/K/version/generation), exact
  capabilities and profile, then recomputes `decide_enrollment` against the prior
  committed binding, supplied lifecycle and explicit rebind authorization. A typed
  mismatch never commits a new binding; a receipt or token is insufficient.

The pure registration acceptance comparison (`compare_registration_acceptance`)
takes the response envelope and its `EnvelopeExpectation` as well as the staged
request and prior binding. It verifies all envelope expectations and exact
payload equality before deciding enrollment. Request validation likewise verifies
the request envelope and checks its signer against the presented I. Pure helpers
never store authority.

Authority obligations for a differing registration binding:

- NSD compares provisioned membership authority and authenticated presented I
  with the accepted membership binding. `Lifecycle.before` must equal that
  complete accepted binding and `Lifecycle.after` must equal the presented
  enrollment binding.
- IdentityReplacement increases membership version and changes both I and K,
  allowing generation to restart under the new I.
- RecordRotation keeps I and membership version, changes K and increases
  generation, with an explicit producer-profile `RebindAuthorization`.
- Initial enrollment has no lifecycle, Equal compares the complete binding, and
  rollback, authentication and scope refusals apply. Zero placeholders grant no
  rebind authorization; ordinary self-initiated stable-I rebind is disabled.
- Provisioned enrollment is distinct from signature ownership: approval
  credentials authorize ordinary Node membership, while the request signer proves
  I ownership. Registered metadata refresh cannot silently change a peer key; a
  new binding acceptance uses the explicit lifecycle contract. The authority must
  check provisioned membership and credential before returning acceptance; no
  shared helper substitutes for that external authority lookup.
- Registration identity is the ordinary Node binding. There is no platform
  gateway registration, assigned tunnel address or server peer stub. Neither
  assigned gateway addresses nor server peer keys create a second Node identity;
  machine identity derives from I. Hostname, OS, software and system telemetry
  are not registration authority. Domain names belong to the public-edge
  publication ([edge](edge.md)).

Consumer obligations: the Node consumer compares its retained binding for the
exact membership and signing authority. Authenticated acceptance must match the
staged membership, complete binding, profile, capabilities and locally computed
`EnrollmentDecision`, with response correlation, recipient and nodes-source
checks. Rejection or mismatch preserves committed identity. Accepted history and
selected-acceptance custody remain authoritative; placeholders are not persisted,
compared with grant or usage tokens, or stored as lifecycle/retirement state.

Grant and reporter token production and custody follow the lifecycle contracts in
[Node](node.md#identity-lifecycle). Identity replacement fences old resources and never transfers
grants; NSD produces fresh incarnations for new grants and publishes K-only
binding changes through Node L3. A K rotation alone does not change
identity-keyed grants. The reporter owns its durable reporter token; pending usage
keeps original attribution and settlement custody. Neither registration
transition assigns or retires those tokens.

`RegistrationAcceptance`, `AuthenticationResponse` and `InformationResponse`
carry no legacy Node naming values; see [Node](node.md#local-node-naming) for local Node naming.

### Authentication

`AuthenticationRequest` (`machine.auth`) is exactly `[1, membership_scope,
NodeBinding, "control", [served_realm, publication_scope], registration_condition]`.

- The purpose is `control` (`MACHINE_AUTH_PURPOSE`). No WebSocket leg, companion
  token or gateway role is carried, and there is no second authentication path.
- The signer must equal the binding I.
- The source selector `[served_realm, publication_scope]`
  (`AuthenticationSourceScope`) is required, with no default and no fallback to a
  selector-free shape. Realm text is canonical RealmId; scope uses the nonempty,
  control-free UTF-8 encoding bounded to 256 bytes.
- `registration_condition` is either `[node_id, credential_incarnation,
  activation_generation]`, each a nonzero 16-byte server identifier, or explicit
  CBOR null. The immutable server Node record identifier is distinct from the
  identity-derived Node ID. Account-owned clients, including the rootless Account
  Gateway, must supply all three facts captured from their verified original
  enrollment receipt; an independently established
  gateway without an Account may send null. The server decides this from stored
  ownership and kind, never from an untrusted client role or a missing field.
- The server compares the condition atomically with current Account standing,
  the exact shared binding (including I/K), and source selection before issuing
  any token or source. An earlier receipt lookup or a second check after signing
  is insufficient. A stale condition must not fall back to unconditional auth.
- Account activation, credential incarnation, Node binding generation and source
  generation are independent. Same-I/K Account A to B to A requires a fresh
  receipt condition; a legitimate source refresh within the same registration
  may return a newer source without changing this condition.
- The six-element request preserves the established bytes at
  `9969abd8507ea3de057b0b870492755908206e89`, introduced by
  `3b5c4878e71b4b77d21cf86c442272a088e0ba65`. It is incompatible in both
  directions with five-element clients at
  `cc8d22b8be4d284ccfd7c9cd64216b743b8e58a8`: this decoder rejects their
  requests, and their decoder rejects six-element requests. Null must be explicit;
  no dual-arity decoder, implicit null, downgrade or alternate authority path is
  provided. Producers, consumers and copied vectors adopt compatible immutable
  revisions together.
- Decoding null establishes no server-side authority. Historical Account-Gateway
  omission exceptions are not broadened and do not provide old-registration
  fencing. Never synthesize a condition from the current server row, substitute
  a current receipt for the captured operation, or infer historical acceptance
  from current observations.


- `registration_condition` is either `[node_id, credential_incarnation,
  activation_generation]`, each a nonzero 16-byte server identifier, or explicit
  CBOR null. The immutable server Node record identifier is distinct from the
  identity-derived Node ID. Account-owned Connectors must supply all three facts
  from their authenticated enrollment receipt; an independently established
  gateway without an Account may send null. The server decides this from stored
  ownership and kind, never from an untrusted client role or a missing field.
- The server compares the condition atomically with current Account standing,
  the exact shared binding (including I/K), and source selection before issuing
  any token or source. An earlier receipt lookup or a second check after signing
  is insufficient. A stale condition must not fall back to unconditional auth.
- Account activation, credential incarnation, Node binding generation and source
  generation are independent. Same-I/K Account A to B to A requires a fresh
  receipt condition; a legitimate source refresh within the same registration
  may return a newer source without changing this condition.
- The six-field request was an incompatible change to the pre-v0.8.0 candidate contract.
  Old five-field requests are rejected, including for gateways; null must be
  explicitly encoded. Producers, consumers and copied vectors adopt together.
  Decoding a null condition does not establish gateway authority.

`AuthenticationResponse` is `[1, compact_token, source_binding_bytes]`. The token
is opaque bounded ASCII; decoding is not signature verification, trust or
acceptance. Authentication never grants registration acceptance. Authentication
request signature and subject matching, key qualification and external RSA
verification are mandatory even when a consumer explicitly permits unbound
machine claims.

Machine-control token minting binds the registered machine key, actual membership
and current authority.

### Source authority in responses

Every successful registration decision, including Equal, and every successful
authentication carries the canonical byte string of `SignedSourceBinding`
([publication](publication.md#source-binding)). A standalone source acceptance payload does not
exist, and response arities without the binding are refused. Refusals keep their
encodings. These are the sole payloads of successful `machine.register` and
`machine.auth` responses on the confidential carrier.

The response must verify the expected enrolled NSD pin, response direction,
explicit recipient, exact operation, freshness and replay rules, and the
enclosing nonce must equal the caller's pending request id; no payload request-id
field is carried. The consumer verifies the nested binding signature against the
independently enrolled NSD and compares its recipient, realm/scope, assigned
profile and full source Node with independent expectations, as specified in
[publication](publication.md#source-authority-in-registration-and-authentication-responses). Registration also retains all staged scope,
enrollment, capability, profile and lifecycle comparisons with retained history.
Authentication uses the selected accepted Node binding and retains consumer token
signature, claims and custody checks. Only a fully validated response supplies
source authority; contribution and counters come from the NSD binding, never the
token. Decoding alone never establishes authority.

### Explicit authentication source selection

- Registration, including pending gateway enrollment and Equal, returns nodes
  authority in the accepted registration Network. Recipient and `source_node`
  equal the enrolled identity. The contribution field is the NSD-allocated Node
  source record in this scope; it grants no gateway contribution, service resource
  or M6 admission.
- Nodes authentication selects the enrollment Network; egress authentication
  selects an independently accepted contribution Network, including home.
- Consumers retain the exact pending realm/scope and nonce, compare returned
  authority against that pair and independently accepted NSD, recipient, profile
  and source Node facts, and verify both signatures and the normal token.
- Unknown or unauthorized selectors are refused, never replaced with another
  binding. Each accepted scope is retained independently.

## Information exchange

`InformationRequest` (`info.get`) is `[1]`.

`InformationResponse` is `[1, discovery_bytes, instance_realm_hint, provider,
version, auth_methods, capabilities]`.

- Auth methods are sorted unique values from `auth_key`, `device_flow`, `oauth2`.
- Capabilities use the enrollment capability rules. Feature understanding maps to
  declared capability identifiers without creating grants.
- The instance realm hint is instance-level display metadata, not tenant
  authority. Provider and version are informational metadata.
- `discovery_bytes` retains the exact ordered endpoints and separate envelope and
  transport pins; signed information reuses the same discovery trust as
  authenticated HTTPS discovery.
- Update-distribution metadata, optional attestation and deployment display type
  are not enrollment authority and are not carried.

## Machine tokens and key sets

### Machine claims

Machine JWTs are compact RS256. Public `MachineClaims` JSON has `iss` (default
empty), required `sub`, `realm`, `iat`, `exp`, `jti`, optional `aud` (string or
string array, `TokenAudience`), and `mid_kty` and `mid_pub` (default empty). Role,
gateway-id and gateway peer-key claims are inert unknown JSON members; they create
no authority. Subject is the exact registered machine identifier; ordinary Node
consumers supply their accepted identity-derived identifier. No string-to-binary
payer conversion occurs. Admin claims and `PolicySubject` reuse the types in
[realm](realm.md#admin-token-claims-and-jwt-subject-bindings); machine claims do not duplicate admin scopes.

Gateway predicate (`MachineClaims::validate_gateway`):

- The JWT header algorithm must be RS256 before a verification key is selected
  (`MachineTokenHeader::select_key`). External RS256 signature and qualified-key
  verification precede the claim comparison.
- `sub` is always compared exactly.
- Unless explicitly allowed by consumer policy, `mid_kty` must equal `ed25519`
  and `mid_pub` the lowercase hex of the accepted I.
- Expiry is refused only when the supplied now > `exp` + 30
  (`MACHINE_EXPIRY_LEEWAY_SECONDS`); arithmetic uses i128.
- Refresh is needed for a missing expiry or `exp` - now <= 300 seconds
  (`MACHINE_REFRESH_WINDOW_SECONDS`, `machine_refresh_needed`).
- Failed authentication or refresh preserves the previously verified bearer in
  consumer custody.
- The gateway predicate does not compare `aud`: absent, unrelated single and
  array values have the same outcome.

The distinct NSD machine-audience predicate (`MachineClaims::validate_nsd_audience`)
requires the single string `nsd-machine-control` (`MACHINE_AUDIENCE`); it rejects
array-shaped `aud` even when an element matches. Wrong-audience vectors are
labelled `nsd-audience`; they are not gateway refusals. NSD's machine `aud` is
string-shaped and its separate RS256 verifier requires the machine audience. NSD's
JWT library expiry leeway is separately 60 seconds; the gateway's 30-second
predicate must not be replaced by it. The contract exposes only the NSD audience
comparison, not an imitation of NSD's complete verifier or external OIDC.

### Key sets

`RsaJwk` JSON has `kty`, optional `kid`/`alg`/`use`, and `n`/`e`; `JwkSet` has
`keys` in source order.

- Unsupported object descriptions are discarded in source order; scalar members,
  duplicate key lists and malformed or trailing JSON are refused.
- Usable keys require RSA, RS256, nonempty `kid`/`n`/`e`, `use` absent or `sig`,
  and strict base64url `n`/`e`. No leading-zero predicate applies to component
  bytes; cryptographic RSA verification is external. Explicit non-`sig` use
  (including `enc`) is refused without learning pins.
- RFC 7638 thumbprints (`RsaJwk::thumbprint`) hash exact JSON
  `{"e":"E","kty":"RSA","n":"N"}`.
- The pure qualifier (`qualify_key_set`) discards unsupported members, filters by
  effective pins and refuses when there are no usable or no trusted keys.
- Selection (`QualifiedKeySet::select`): duplicate `kid` selection retains the
  first source-order match. A missing `kid` selects exactly one qualified key; no
  keys refuses a missing `kid` and multiple keys refuse as ambiguous. An unknown
  `kid` is a typed miss; the consumer performs at most one paced refresh, then
  repeats selection.

Pin ownership (`KeySetOwner`) is the exact realm plus key-set address after
trimming outer whitespace and trailing slashes.

- Static pins bypass persisted first-use pins and stored ownership.
- Without static pins, matching-owner stored pins (`StoredKeyPins`,
  `qualify_owned_key_set`) are authoritative; absent stored pins learn all usable
  fetched keys once.
- Existing pins never append advertised rotations. Rotation may add or remove
  keys only inside the effective pin set; substitution without a matching pin is
  refused.
- Qualified keys and newly learned pins are returned as values; consumers durably
  persist first-use pins before publishing them.

Consumer runtime obligations (not shared timers): a 300-second successful receipt
cache (strictly younger), an 8-second forced-refresh quiet period,
replaced-observation sharing, and a 31-second acquisition deadline. Failed
acquisition preserves the last complete keys and their original receipt,
publishes a diagnostic failure and never extends freshness.

## Control reports

### Carrier

The report operations `machine.heartbeat`, `node.heartbeat`, `machine.disconnect`, `gateway.report`,
`gateway.services_report`, `gateway.usage_report` and `gateway.material_status`
(`ControlReportOperation`) use the confidential `BootstrapDiscovery` carrier,
`BootstrapEnvelope` request/response domains and `CONTROL_ENVELOPE_PATH`. The
report decoder verifies `EnvelopeExpectation` before decoding and checks direction
and operation. Signers and recipients are the accepted Node and the pinned
authority; no payload supplies registration authority. Signing uses
`BootstrapEnvelope::signing_input`. Machine authentication and key-set
verification are those of this document; reports define no separate credential
model. No auth configuration acquisition is defined by the report contract.

### Tuple rules

All report tuples use schema 1, shortest definite CBOR, no trailing bytes and the
1 MiB account ceiling. Every list has at most 256 entries, checked before
allocation. Text is nonempty control-free UTF-8 of at most 256 bytes, except that
policy-label values may be empty. Floor references and policy-label keys are data
text: internal, leading and trailing spaces and Unicode whitespace are preserved
exactly. They are nonempty, at most 256 UTF-8 bytes and control-free; M6
declaration keys keep their 255-byte bound. No trimming, case folding or Unicode
normalization is performed. Capability fields keep enrollment token syntax,
including its stricter byte/count bounds, independently of data text. Sets are
strictly ordered; decoding never sorts or deduplicates them.

### Heartbeat

`HeartbeatRequest` is `[1, request_id_16, uptime_seconds, local_ips,
policy_version_or_null]`.

- Addresses are IP literal strings, in supplied order. An empty list explicitly
  reports no addresses; an absent counter is preserved as absent.
- Uptime is process uptime, not wall time.
- Policy version is the last observed authenticated diagnostic counter, not
  applied policy or authority.

`HeartbeatResponse` is `[1, request_id_16, features]`. Features are ordered unique
tokens, preserved including unknown tokens; they grant no authority.

### Ordinary Node heartbeat and disconnect

`node.heartbeat` (`ControlReportOperation::NodeHeartbeat`) is distinct from the
existing gateway `machine.heartbeat` operation. `NodeHeartbeatRequest` is
`[1, membership_scope, runtime_fence, heartbeat_request_bytes]` when all transport
observations are absent. With any transport observation it is
`[1, membership_scope, runtime_fence, heartbeat_request_bytes, udp_reachable,
pair_transport, gateway_rtt]`. The three extension positions use CBOR null for
omission; an all-null extension is refused because the four-item form is its
unique canonical encoding. Existing four-item vectors remain byte-identical.
`NodeHeartbeatResponse` is
`[1, membership_scope, runtime_fence, heartbeat_response_bytes]`.
The nested bytes are the canonical `HeartbeatRequest` and `HeartbeatResponse`
forms defined above, including request ID, uptime, local IPs, policy counter and
inert response features. Node and gateway outer tuples have different arities:
neither decoder accepts the other form. Nested lists retain the 256-item bound,
checked before allocation, and the whole payload retains the 1 MiB ceiling.

The Node-only extension fields are:

| Field | Canonical value | Meaning |
| --- | --- | --- |
| `udp_reachable` | boolean or null | Node transport verdict; null preserves the stored verdict, including a previous false value. |
| `pair_transport` | `[runtime_id_16, revision, unhealthy]` or null | Full unhealthy set for the reporter/runtime. Null leaves it unchanged; a present empty `unhealthy` explicitly clears it. |
| `gateway_rtt` | array of `[gateway_identity_32, tier, samples, timeouts]` or null | Probe measurements; null supplies no observation. An empty array reports no entries and is distinct from omission. |

Each unhealthy entry is `[peer_identity_32, gateway_identity_32]`. Both keys must
be valid full shared `IdentityKey` values, as used by GatewayNode roster entries;
legacy machine IDs and derived NodeIds are refused. Entries are strictly sorted
lexicographically by full peer bytes, then full gateway bytes, with no duplicate
pair. RTT entries are strictly sorted and unique by full gateway bytes. Each
list is bounded to `MAX_NODE_OBSERVATIONS` (256) before allocation. Invalid
fields, including a pair runtime ID different from the enclosing fence, return
`AccountError::Field`; malformed CBOR, invalid byte lengths and oversized decoded
lists return `AccountError::Cbor`. Oversized in-memory lists return
`AccountError::Bounds`. The complete payload remains bounded to 1 MiB.

`revision`, `samples` and `timeouts` are u64, including zero. Consumers compare
pair revisions with stored state for that exact reporter/runtime before replacing
the set; shared decoding does not claim freshness. RTT tier strings are exactly
`lt30`, `lt100`, `ge100`, and `unreachable`; other strings are refused. Identities
come from authenticated peer/gateway publications used by the actual reporters.
The consumer resolves them against authoritative records within the membership
scope. It must not silently drop unresolved identities from a full pair snapshot
or acknowledge that snapshot as consumed. Observations grant no authority.

`NodeHeartbeatResponse.heartbeat.features` advertises the features consumed by
that endpoint, including `gateway_rtt.v1` and `pair_transport_fallback.v1`.
Pair and RTT reporting require both discovery and current endpoint support; pair
reporting also retains the enrolled capability requirement. An empty feature list
withdraws optional reporting. Feature tokens are ordered and unique; unknown
ones remain inert. The response wire form is unchanged.

A successful authenticated, correlated receipt acknowledges only observations
included in that exact retained request. Consumers compare request ID, both
membership IDs and every runtime fence field before marking those observations
delivered. The receipt follows heartbeat persistence and pair-snapshot acceptance,
with RTT passed to its existing best-effort measurement consumer; it does not
prove durable RTT storage. Omitted, unmapped or failed observations remain
undelivered. A liveness-only receipt cannot acknowledge a richer source report.

`machine.disconnect` (`ControlReportOperation::NodeDisconnect`) uses
`NodeDisconnectRequest`:
`[1, membership_scope, runtime_fence, request_id_16]`.
`NodeDisconnectResponse` is `[1, canonical_request_bytes]`, an exact receipt of
the committed disconnect intent. A receipt introduces no new runtime authority.
Both response types provide `validate_for` to compare the retained request's
membership, runtime fence and request identifier. Consumers authenticate the
response carrier and correlate it before accepting the receipt.

`membership_scope` is `[nsd_id_16, network_id_16]` (`MembershipScope`). These are
provisioned identifiers, never signing keys or an internal machine row ID.
`runtime_fence` is `[runtime_id_16, runtime_generation, authority_epoch]`
(`NodeRuntimeFence`), using the same field types as `ServiceControlBinding`.
The runtime ID must be nonzero and both u64 counters must be positive. The
Node supplies scope from its accepted registration and source custody, and
supplies the fence from its accepted service runtime. The Node creates a pending
request ID; uptime and IPs are process observations, and the optional policy
counter retains its diagnostic meaning.

`NodeReportContext` is trusted input from the consumer's persisted accepted
state, never copied from the incoming payload. It contains the accepted
`MembershipScope`, the enrolled Node signing identity (`subject`) and the NSD
signing identity (`authority`) for that membership. Its additive
`validate_envelope(operation, envelope, expected)` API authenticates the existing
carrier using `EnvelopeExpectation`, requires a Node heartbeat or disconnect
request, compares signer with subject and explicit recipient with authority,
and compares both provisioned scope identifiers exactly. `NodeReportError`
distinguishes carrier, contract, operation, subject, authority and scope refusals.
The context-free `ControlReportOperation::validate_envelope` refuses the two new
operations with `ExchangeError::Scope`; validation of all existing operations is
unchanged. `validate_payload` only validates canonical shape, for either direction;
it cannot authorize membership or renew a runtime. Responses use the existing
carrier verification followed by exact pending-request correlation.

NSD supplies the trusted context from persisted enrollment and source custody,
and compares the carried runtime ID, generation and authority epoch with its
persisted current runtime before selecting its internal machine row and
committing renewal or disconnect. Shared decoding checks fence shape only:
success does not establish freshness, capability admission, current source
custody or a committed effect. Those checks and transactions remain consumer
responsibilities. No transport, registration acceptance field, or payload
identity key is added. These contracts are part of the public account API from `v0.8.0`.

### Signed Node liveness refusals

`NodeLivenessRefusal` is a separate version-1 negative receipt. Its exact
canonical CBOR form is:

```text
[1, operation, membership_scope, requested_runtime_fence,
 logical_request_id_16, refusal_code, reason]
```

The array has exactly seven items. `operation` is the text `node.heartbeat`
or `node.posture` (`NodeLivenessOperation::{Heartbeat, Posture}`) and must equal
the signed envelope kind. Arity and the text in position 1 distinguish refusals
from successful heartbeat/posture receipts. Existing success-only
`ControlReportOperation::validate_payload` stays success-only for these response
operations; consumers select the separate refusal decoder for the statuses below.

`membership_scope` retains `[nsd_id_16, network_id_16]`.
`requested_runtime_fence` retains the rejected request's exact
`[runtime_id_16, runtime_generation, authority_epoch]`: nonzero runtime ID and
positive u64 counters. It asserts no fresh custody and reveals no replacement
runtime. `logical_request_id_16` is nonzero: heartbeat's nested
`HeartbeatRequest.request_id` or posture's `NodePostureRequest.request_id`.
The outer nonce is the separate transmission nonce. Integers use shortest
unsigned CBOR encodings; arrays/strings are definite length, with no trailing
bytes. `MAX_NODE_LIVENESS_REFUSAL_BYTES = 256` bounds the payload. Unknown
versions, operations, codes, reasons, wrong arities, malformed IDs, zero fence
fields and noncanonical encodings refuse. No free-form diagnostic text is carried.

Code and reason are exact CBOR text strings. Only these pairs are legal;
every other combination, including a known reason under the wrong code, refuses.

| Code (`NodeLivenessRefusalCode`) | Reason (`NodeLivenessRefusalReason`) | Required HTTP status | Meaning |
| --- | --- | --- | --- |
| `runtime_rebind_required` (`RuntimeRebindRequired`) | `lease_elapsed` (`LeaseElapsed`) | 409 | Presence elapsed; current credential/enrollment and scoped business authority remain valid. |
| `runtime_rebind_required` (`RuntimeRebindRequired`) | `authority_epoch_changed` (`AuthorityEpochChanged`) | 409 | NSD authority epoch changed; current credential/enrollment and scoped business authority remain valid. |
| `runtime_conflict` (`RuntimeConflict`) | `runtime_stopped` (`RuntimeStopped`) | 409 | Explicit runtime stop was committed; no automatic takeover permission. |
| `runtime_conflict` (`RuntimeConflict`) | `runtime_superseded` (`RuntimeSuperseded`) | 409 | Another process superseded this runtime; no automatic takeover permission. |
| `authority_revoked` (`AuthorityRevoked`) | `authority_changed` (`AuthorityChanged`) | 403 | Current credential/enrollment or scoped business authority was genuinely refused. |

The typed code determines behavior; the reason only refines diagnostics. An
unavailable authority remains HTTP 503 with no `NodeLivenessRefusal` and no
invented revocation claim. Invalid or untrusted requests retain existing HTTP
security behavior; no unauthenticated receipt is synthesized. A missing,
malformed, unknown or status-mismatched reply is a protocol failure, never a
guessed recoverable or permanent Account verdict. Elapsed client time and reason
substrings supply no authority.

NSD authenticates the request against persisted Node membership custody and
classifies refusal under its locked current business/enrollment and runtime
authority. Genuine authority refusal must not become rebind permission merely
because a runtime also lapsed. NSD signs the canonical refusal in the existing
`BootstrapEnvelope`, response direction, explicit Node recipient, same operation
and exact request transmission nonce. Current authority, durable effects and
classification precedence remain NSD responsibilities.

The Node retains the complete pending request and nonce, and uses persisted
`NodeReportContext` and pinned NSD trust. First call
`NodeReportContext::validate_liveness_refusal(envelope, expected, pending_nonce,
http_status)`. This verifies existing signature/pins, response direction,
explicit enrolled Node recipient, exact persisted NSD signer, kind, timestamp,
replay facts, nonce, membership and code/status pair. Then call
`validate_for_heartbeat(pending)` or `validate_for_posture(pending)` to validate
the complete retained request and compare operation, both membership IDs, all
three fence fields and logical request ID. **Both checks must succeed before
acting.** The consumer supplies replay facts for the exact signer/direction/nonce,
atomically records acceptance after complete correlation, and fences obsolete
local ownership before any recovery or lifecycle change. Decoding alone
authenticates nothing, renews no lease and grants no bind.

`authority_revoked` alone does not specify permanent Account sign-out scope:
current credential, enrollment or scoped business authority and the consumer
lifecycle determine that scope. This is not a context-GET/metadata receipt and
changes no metadata renewal or sign-out wire contract. It carries no credential,
bearer, user identity, lease-owner token or replacement runtime ID. M6 error
codes, `service_control.v1`, envelope v1, gateway forms and existing successful
report bytes and fixtures remain unchanged.

Deploy NSD's correct signed 409/403 behavior before relying on new Node recovery.
Older raw carriers treat 409 as transient and cannot decode the new payload;
new clients talking to old NSD retain conservative handling of untyped 403.
No capability negotiation is introduced. Consumers pin the same immutable
release/commit and lockfile once released. This change prepares 0.11.0 without
creating a tag; the API is additive under the 0.x policy, and the minor version
follows the coordinated delivery requirement.

Code is `reports/node_liveness_refusal.rs`, re-exported through
`nsshared_control::account::control`. Independent Python-produced
`account/control/node-liveness-refusal.vec` fixtures cover every legal pair for
both operations, exact bytes/signatures, invalid combinations, zero/malformed
IDs, bounds and canonicality. Rust tests cover complete pending correlation,
success/refusal separation, bad signatures/pins/recipients/kinds/nonces,
stale/replayed carriers and HTTP status mismatches. Runtime classification,
recovery and sign-out behavior require separate consumer tests.

### Gateway observations

The 0.9.0 clean-break [Exit readiness contract](exit-readiness.md) extends the
existing authenticated report exchange. `GatewayReport` is
`[2, request_id_16, software_version_or_null,
source_revision_or_null, connections_or_null, terminate_enabled_or_null,
public_http_port_or_null, internal_http_port_or_null, draining, capabilities,
public_ingress_scopes, certificates, public_host_or_null, exit_installation_or_null]`.

- Ports are 1..65535 and authorize no public route.
- Connections are u32; absent means unknown, distinct from zero.
- The terminate flag records local service intent, never permission.
- Capabilities reuse enrollment's bounded identifier set; scopes use ordered token
  sets. Grants remain separately authenticated.
- Node identity, endpoints and addresses come from the ordinary accepted Node
  identity, signed NodeRecord and family 10 publications; the report carries no
  second gateway identity, assigned-address authority, connector listener,
  datagram relay endpoint or relay capacity.

`GatewayCertificateObservation` is `[id, hostnames, issuer, not_after_seconds,
fingerprint, ack_generation_or_null, last_error_or_null]`. Hostnames are ordered
unique text; generation, when present, is positive. These nonsecret activation
observations do not replace exact material-installation correlation and are never
installation authority. Fingerprints and issuer are opaque observations, not trust
pins.

`GatewayReportResponse` is `[2, request_id_16, accepted_exit_installation_or_null,
exit_challenge_or_null]`. The accepted digest names only the exact pending Exit
observation; an ordinary health receipt is not an installation ACK. The next
challenge supplies no forwarding authority. The gateway mints a unique request id
per observation; authenticated responses are correlated with the exact pending
request (`validate_for`). Old report/response forms refuse. Exact fields,
canonical rules and installation-owner/currentness obligations are normative in
[Exit readiness](exit-readiness.md).

### Fenced shared gateway reports

The shared `gateway.report` operation carries `FencedGatewayReportRequest`:
`[1, scope, fence, canonical_GatewayReport_bytes]`. `scope` is the exact
`MembershipScope` pair `[nsd_id_16, network_id_16]`; `fence` is the existing
`NodeRuntimeFence` tuple `[runtime_id_16, runtime_generation, authority_epoch]`.
The runtime id is nonzero and both counters are positive. Missing fields, null
context, noncanonical encodings (including nested bytes) and invalid observations
are refused with typed `AccountError` values. The embedded `GatewayReport`
uses the extended clean-break form above; its `request_id` is the request correlation. Drain
uses this same operation with `report.draining = true`, without another payload
or identity model.

`FencedGatewayReportResponse` is
`[1, scope, fence, canonical_GatewayReportResponse_bytes]`. It echoes the exact
accepted scope, runtime fence and existing operation receipt. After authenticating
the response envelope's authority signer, recipient, direction and operation,
the gateway calls `validate_for` against its retained pending request; either
membership id, runtime id, generation, authority epoch or request id differing
is a typed `AccountError::Field` refusal. Receipt has the existing observation
receipt semantics and grants no registration or forwarding authority. Exit
acceptance is a separately correlated observation, not a health-success inference.

The gateway process produces observations and drain intent from its actual
state, membership from accepted registration/source custody and runtime fields
from its accepted service runtime. The signed shared `BootstrapEnvelope` carries
these bytes on `gateway.report`. `NodeReportContext::validate_envelope` verifies
the signed request and compares its enrolled subject, NSD recipient and exact
membership against trusted persisted context. The context-free report envelope
validator refuses this operation with `ExchangeError::Scope`; bare observation
and receipt bytes remain independently decodable but are not shared operation
payloads.

Before applying the existing gateway store handlers, NSD compares signer,
membership, source custody and current runtime fence with persisted custody and
checks the persisted accepted `explicit-gateway-profile`. Decoding or envelope
validation alone does not prove runtime freshness or profile acceptance. A
device-enrolled gateway acts as its own ordinary enrolled Node and needs no
gateway identity root or legacy machine lookup. The gateway compares the signed
response with its pending operation/request and scoped runtime. Runtime renewal
continues to use fenced Node heartbeat; report and drain do not replace it.

Independent `account/control/fenced-gateway` vectors cover report and drain,
correlated receipts, absent/zero fences, missing scope, mismatches, canonical
encoding and signed persisted-context checks. Existing observation, heartbeat
and posture vector bytes remain unchanged.

### Services and floor metadata

`EdgeServiceRequest`/`EdgeServiceResponse` ([edge](edge.md#service-declarations-floors-reports-responses-and-acks)) keep body kinds 0
declaration, 1 report and 2 listener. Kinds 0 and 2 and all other public-edge,
auth, material and declaration bytes are as specified in [edge](edge.md); this
section specifies kind 1.

Kind 1 request is `[1, request_id, publisher, nsd_id, network_id, revision, 1,
exact_M6_ReportContent_bytes, metadata, exit_profiles, digest]`.

- M6 service declarations and their serializer are unchanged; each declaration
  supplies its `declaration_key`, protocols, `backend_host`/`backend_port` and
  enabled values. No address-derived Resource reference is formed.
- Metadata (`EdgeServiceMetadata`) contains exactly one `[declaration_key,
  capabilities, policy_labels]` per submitted M6 declaration, in declaration-key
  order, including empty metadata. Labels are ordered unique `[key, value]` pairs.
  They are local floor metadata, never grants or policy.
- Exit profiles (`EdgeExitProfile`) are ordered by reference and encoded as
  `[profile_ref, selection, enabled, capabilities, policy_labels]`. Selection
  reuses `SubnetSelection` semantics ([subnet](subnet.md#prefixes-and-subnet-selection)): `[0]` default route
  or `[1, cidrs]` explicit SubnetPrefix tuples, strictly ordered by
  family/address/length, without overlaps; an empty explicit selection selects
  none. Profiles are declarations, not SubnetPublication route authority. No
  provider/client binding or enabled permission is inferred.
- A valid empty floor withdraws the declared floor.
- The digest is `domain_digest("ns.account.service-floor.v1", canonical
  [M6_report_bytes, metadata, exit_profiles])`, committing the entire submitted
  floor. The M6 report's own canonical bytes and digest API are unchanged.

Kind 1 response keeps the first eight fields, including that exact digest; its
last field is `[accepted_services, accepted_exit_profiles, rejected]`
(`EdgeFloorOutcomes`).

- Accepted sets are ordered unique exact data-text reference strings.
- Rejections (`EdgeFloorRejection`) are ordered unique `[kind, reference,
  reason]`, kind 0 service or 1 Exit, with a nonempty bounded reason.
- Each submitted reference has exactly one outcome of its own kind. Unknown,
  duplicate, contradictory and missing outcomes are typed refusals; the response
  never acknowledges an unsubmitted reference. A matching explicit rejection is a
  refusal of that reference, with its reason preserved. An empty floor requires
  empty outcomes.
- Kinds 0 and 2 keep whole-content accepted/rejected status.
- Acceptance records submitted content only, never listener readiness or route
  authority.

### Usage

Usage requests and answers reuse the exact `UsageReport`/`UsageAnswer` bytes and
the original immutable reporter/incarnation/profile/sequence/part/digest domain
([usage](usage.md#usage-reports)). Conflict and repair answers are never acknowledgements.
`UnknownMapping` is valid only for relay reports: a service answer carrying it
fails `validate_for` and is never an acknowledgement, even if every other
correlation field matches.

Retention seals and their acknowledgements are participant-session-only payloads
([retention](usage.md#retention-seals-and-acknowledgements)); this control carrier
does not accept them as usage reports or answers.

### Material status

Material status requests reuse the exact `EdgeMaterialAck` bytes ([edge](edge.md#edgematerialack)).

- For auth configuration, the gateway copies the request id from its exact
  pending confidential auth configuration request. That separate request/response
  and its private configuration payload are owned by the confidential auth
  configuration contract ([edge](edge.md#confidential-authentication-configuration-exchange)), not by this document.
- For certificates and client CA, the gateway mints its own unique report request
  id and retains the exact report. Certificate and client-CA acknowledgement ids
  are installation-status ids, not acquisition ids.
- In both cases correlation includes request id, served_realm, scope,
  contributing realm, material kind/reference/generation, and status. No
  identifier or generation is inferred from a certificate observation or current
  state.
- Installed is reported only after actual installation of that exact reference
  and generation; a receipt cannot synthesize installation. Rejection is explicit.

`MaterialStatusResponse` is `[1, exact_EdgeMaterialAck_bytes]`; the authority
echoes the exact accepted report. `validate_for` compares the full pending report,
including status. A rejection receipt is not successful installation.
`EdgeMaterialAck::validate_installation` compares the retained request id, full material and all
realm/scope fields and requires installed. Authentication and actual effect are
caller responsibilities.

## Signed URL requests

### Signed account requests

Account requests reuse `BootstrapEnvelope` exactly, including the request domain
`ns.account.call.request.v1\0`, schema, signer, recipient, operation, timestamp,
nonce, payload and signature bytes. `signing_input` exposes the domain followed by
canonical content, for both request and response. `SignedAccountRequest` accepts
only request-direction envelopes and exposes their canonical carrier; it defines
no second signature format. Wrong direction and response-domain signatures are
refused by the envelope verifier. M6 message payloads remain opaque and unchanged.

### Signed URL scope

Signed URL request text uses the gateway's HMAC input algorithm without
implementing HMAC or credential verification. `SignedUrlScope` binds method
(GET/HEAD), http/https scheme, host, raw path, raw query, realm, route and
absolute expiry.

- Host, path and query are each bounded to 16,384 UTF-8 bytes and contain no
  controls; realm and route use the 256-byte label limit and cannot contain `/`.
- Path starts with `/` and excludes a separate query or fragment.
- Query pairs split at `&` and the first `=`; percent decoding preserves `+` and
  duplicate names. Every byte except RFC 3986 unreserved bytes is
  percent-encoded using uppercase hex, the decoded `X-Nsgw-Signature` is removed,
  encoded name/value pairs are sorted and joined with `&`.
- The trimmed host is lowercased and only the scheme's default port is removed; a
  nondefault port and raw path bytes are preserved without normalization.
- Canonical request text (`SignedUrlScope::canonical_request`) is
  `METHOD\nPATH\nQUERY\nhost:HOST\n\nhost\nUNSIGNED-PAYLOAD`.
- String-to-sign (`SignedUrlScope::signing_input`) is
  `NSGW-HMAC-SHA256\nEXPIRY\nREALM/ROUTE/nsgw_signed_url\nHASH`, where HASH is
  the lowercase hex SHA-256 of that canonical request.
- Malformed percent escapes, non-GET/HEAD methods and multiline components are
  refused rather than silently changing the signed request.

Control parameter parsing, duplicate/missing control refusal, actual expiry,
rotation, HMAC comparison and transport admission stay in the gateway consumer.
No secret or key enters this API.

## Route commands and receipts

### Encoding

Route payloads are exact canonical CBOR with minimal integers, definite lengths,
no extra fields and no trailing bytes. Integers are unsigned u64 unless stated.
Complete command, receipt and response payloads are bounded by 16,384 encoded
bytes. Identity fields are complete validated 32-byte Ed25519 public keys. Realm
text is canonical RealmId. Opaque identities are nonzero 16-byte values. Scope
text is nonempty, at most 256 UTF-8 bytes, without control characters.

### Commands

The confidential operations are `node.route.select` and `node.route.clear`, on
the control endpoint. They do not reuse gateway-ID operation identifiers.

`RouteCommand` is `[1, bstr(SignedSourceBinding), request_id, selection_id,
action]` (`RouteAction`).

- Select action is `[0, provider_node_I, bstr(canonical_M6_ServiceRef),
  selection]`. Selection reuses `SubnetSelection`'s exact `[0, []]` default or
  `[1, ordered_prefixes]` explicit scope; prefixes use its family/address/length
  encoding, validation, ordering and overlap bounds. An empty explicit selection
  selects none. Resource authorization and containment in a published route are
  NSD transaction checks, not inferred from identity or decoded bytes.
- Clear action is `[1, target_selection_generation]` with a positive generation.
  Clear's source binding, selection identity and generation name an exact target.
- Full provider I and a stable ServiceRef are required; gateway strings, carrier
  credentials, gateway-ID fields and unknown appended fields are refused. Request
  and selection identities are required, not optional.

The signed carrier request nonce is a fresh nonzero transmission-attempt
identity, independent of the immutable payload `request_id`. The signer equals
the binding recipient, the recipient equals the binding NSD, and the operation
equals the action's operation. The binding signature verifies against the
independently trusted NSD. The transaction compares the authenticated caller,
assigned profile and supplied binding with committed current source authority
before a new mutation. NSD assigns the `explicit-gateway-profile` profile in
enrollment ([publication](publication.md#source-binding)).

### Receipts

`RouteReceipt` is `[1, bstr(RouteCommand), selection_generation, outcome]`
(`RouteOutcome`): outcome 0 selected, 1 cleared, 2 clear target absent.

- Select generation is NSD's positive committed generation. Clear results keep the
  exact targeted generation whether cleared or absent.
- A receipt is immutable for its exact profile/source/request identity: every
  original receipt is stored, never only the latest per machine. Original
  receipts survive source replacement and restart with no current mutation
  authority.
- The same identity with changed command bytes conflicts. A different source has
  a separate request namespace even when I/K/addresses and request ids match.

### Responses

`RouteResponse` is `[1, bstr(RouteReceipt), replayed_bool]` in an NSD-signed
control response with the action's operation, explicit recipient and the pending
attempt's nonce. The consumer supplies and compares that exact nonce as well as
its entire pending immutable request and source/profile with the receipt.

- Retransmission uses a fresh carrier timestamp and nonce under the unchanged
  carrier replay rules while keeping payload `request_id` and exact command
  bytes. Fetching the original receipt never reuses the first carrier's replay
  authority.
- A response establishes the committed command outcome, never applied routing.
- A replay returns the original receipt bytes and reports `replayed=true`; it
  grants no current mutation authority.

### Decisions

`decide_route_command` returns a `RouteDecision` distinguishing Replay from
Select, Clear and ClearAbsent. Replays verify the original binding, caller and
exact receipt content, then return before comparing mutation authority with a
replacement source. New requests must match the current source. Clear only
removes a caller-supplied `CommittedSelection` with the exact binding, identity and
generation. Receipts of a profile other than the current assigned profile are
refused, not translated. Errors are reported as `RouteError`.

Durable transaction rechecks, generation allocation, receipt lookup and history,
and restart restoration are NSD responsibilities; pending journals and routing are
Node consumer responsibilities.

## Node L3 status

### Mapped-prefix route admission

This subsection specifies the admission predicate summarized in
[Node](node.md#mapped-route-admission) and
[subnet](subnet.md#exit-grants-and-client-route-views).

Ordinary Node-L3 rules govern direct identity-derived N6/N4 destinations. A
Subnet mapped-prefix destination is resolved to its exact resource and selected
route, never converted into a Node-L3 destination rule naming the provider.
Neither a Subnet permission nor provider membership opens direct N6/N4 access.
`NodeL3` and `NodeL3Authority` bytes ([Node](node.md#normalized-node-l3-form)) are unchanged by this
admission. Independent service admission keeps its source ownership and is
separate from ordinary host permission.

- Provider: admit a mapped-prefix packet only through the current Exit owner's
  exact join of resource, authenticated client and provider, grant incarnation,
  payer and expiry, the embedded validated route's real/mapped selection minus
  exclusions and its SubnetProxyCoverage, and validated local enablement/binding.
  Existing resource-authority/payer joins and retirement apply. A client route
  view alone cannot authorize service.
- Client: the current authenticated `subnet-routes` view authorizes selecting only
  its named resource's selected mapped destinations and covered TCP/UDP/echo
  traffic for the route's provider. The client compares client with self and
  provider with the independently installed peer identity/key, within the
  accepted source and Network. This is permission to select that route, not
  provider-side grant authority.
- Neither side creates or requires a Node-L3 rule for the mapped-prefix path.
  Direct N6/N4 traffic still needs its independent authority; route withdrawal,
  exclusion or missing coverage cannot fall back to a provider-wide Node rule.
- Bypass data and its routing semantics, source/destination ownership, and
  established reverse-flow ownership are preserved. Real IPv6 forwarding and live
  default Exit are outside this scope.

Provenance: NSD produces provider Exit grants and the separate client route view
from committed permission, mapping, offers and selection; authenticated source
publications carry them under the respective recipient's current nodes binding.
The Subnet validator derives the selected cover and protocol coverage from those
route bytes. Local configuration and validated Linux state produce provider
enablement/binding, and peer installation supplies authenticated identity/key
ownership. Each side compares its own current inputs as above; the client neither
receives nor fabricates provider payer/incarnation facts.

### Status operation

Family 11 snapshot `node-l3` keeps its bytes and source ownership. The
confidential operation `node.l3.status` uses `BootstrapEnvelope` to report actual
application of an exact signed inner family 11, kind `node-l3`, snapshot event.
It is available to the authenticated recipient Node, including a gateway. It does
not reuse the Node-L3 ACK, M6 SnapshotAck or heartbeat `policy_version`. There is
no separate accepted-only phase: only actual enforcement application can produce
Applied.

### Request

`NodeL3StatusRequest` is `[1, request_id, key, source_binding_bytes,
event_version, event_digest, status]`.

- `request_id` is a recipient-produced nonzero 16-byte byte string identifying its
  pending report.
- `key` (`NodeL3StatusKey`) is `[issuer, recipient, served_realm, scope, 11,
  "node-l3"]`, using full 32-byte identity byte strings, canonical RealmId text
  and the publication scope text.
- `source_binding_bytes` is a byte string containing the `SourceBinding::canonical()`
  bytes, copied from the independently accepted `SignedSourceBinding`; it carries
  every source field, not just its generation, without duplicating the binding
  signature. Its NSD/recipient/realm/scope must match the key.
- `event_version` is the positive enclosing event version; a nonempty Data
  `NodeL3Authority` must have matching `NodeL3` issuer, recipient and revision.
- `event_digest` (`node_l3_event_digest`) is exactly 32 bytes:
  SHA-256(ASCII `ns.account.node-l3.v1` || one zero byte ||
  `PublicationEvent::canonical()` of the signed inner event), computed with the
  `domain_digest` helper. It includes the inner signature and all publication
  metadata and payload, but excludes the outer SourcePublication and delivery
  context. Retransmission of the same retained inner event therefore keeps its
  digest; its source is separately compared in full. A re-created policy or only
  the `NodeL3Authority` bytes are never hashed.
- `status` (`NodeL3Status`) is exactly `[0]` Applied, `[1, reason]` Rejected, or
  `[2]` FetchFailedDenied. The rejection reason is nonempty UTF-8 text of at most
  256 bytes without control characters and grants no authority.

Status meanings:

- Applied means the recipient's current enforcement has installed that exact Data
  event's replacement, including completed removal for a complete-empty
  withdrawal.
- FetchFailedDenied is only for a verified authenticated FetchFailed event after
  its exact collection has been denied.
- Rejected reports a verified event that could not be installed; it is never
  applied evidence.
- Unauthenticated input and outer fetch failure produce no report purporting to
  identify an authenticated issuance. Invalid-input, version/tombstone and expiry
  rules of the publication contract apply unchanged.

Encoding is strict canonical CBOR within the control, source and publication
bounds; unknown statuses and extra fields fail.

The request uses the confidential authenticated Request envelope with operation
`node.l3.status`, signer equal to `key.recipient` and envelope recipient equal to
`key.issuer`. NSD uses authentication and source authorization and compares the
full key, all binding fields, version and digest with its retained current
issuance for that recipient (`NodeL3StatusRequest::validate_issuance` with a
`NodeL3StatusContext`); a report's own values cannot establish that expected
context. NSD retains the exact signed inner event and its source when issuing it
and computes the same digest. Only a matching Applied Data report establishes
applied evidence for that issuance. Rejected and FetchFailedDenied never become
affirmative permission evidence; an Applied empty withdrawal proves removal, not
access. A superseded source or issuance cannot satisfy the current predicate.
`policy_required` and effective-authority checks remain independent; successful
report transport does not authorize a resource.

### Response

A successful Response envelope from that NSD to the Node echoes the pending
envelope nonce and carries `NodeL3StatusResponse` `[1,
bstr(exact_canonical_request)]`. The Node compares the full echoed request bytes,
including `request_id` and status, with its pending report under envelope
trust/direction/operation checks (`NodeL3StatusResponse::validate_for`). This is
receipt of the exact status, not an assertion of remote data-plane observation. A
mismatch or refusal is not a success receipt. Request ids correlate reports; they
do not replace event identity or source fencing.

### Application association

The runtime carries the accepted key, source, and event bytes/version/digest from
the control writer to the enforcement application result. The Node compiler
supplies the actual install/deny result for that collection; the status sender
compares that result with the still-current accepted context before reporting it
(`NodeL3StatusRequest::validate_application`). A global maximum revision,
aggregate rule count, successful decode, queued installation or diagnostic counter
cannot substitute for this association. This requires only a narrow local
application association/readback and report adapter, not a shared enforcement
runtime or a change to other collections' ownership.

| Family | Collection | Applied state | Other statuses |
| --- | --- | --- | --- |
| 11 | exact nodes/source/realm node-l3 snapshot | Exact installed Data replacement; empty means removal | Rejected and FetchFailedDenied grant no permission |

## M6 service control carrier

Versioned whole-floor `report.replace` content is specified in
[the M6 floor contract](../m6-floor.md). The operation and Node runtime fence
are unchanged; floor-aware decoding and pending correlation retain metadata
and Default or explicit-CIDR Exit profiles in the acknowledged content digest,
including disabled profiles. Default is exactly `[0]`; it requires compatible
immutable producer/consumer revisions as specified in
[Default compatibility and delivery](../service/default-exit-floor.md#compatibility-and-immutable-delivery).
Old explicit-only decoders are not Default-capable; unsupported tuples remain
unavailable. Profile publication alone grants no traffic authority.

The carrier maps M6 service control onto the confidential control endpoint. It
has no transport, persistence, session state or I/O. It replaces the JSON
ControlEnvelope carrier of the M6 service lifecycle; the M6 schema, runtime and
admission state are unchanged and no publication family is added.

### Unary operation

`SERVICE_CONTROL` is `service.control.v1`, on the confidential `/api/v1/control`
endpoint. The Node signs Request `BootstrapEnvelope`s addressed to its
authenticated NSD; NSD signs Responses addressed to the Node. The envelope
signature domains, trust pins, recipient, clock, replay and size checks apply.
Except for the receipt below, ordinary payloads are exactly
`nsshared_control::service::Message::encode()` bytes, decoded by
`Message::decode`. Extended whole-floor `report.replace` payloads use
`FloorReportMessage::encode` and `decode` (or authenticated `from_envelope`),
as specified in [the M6 floor contract](../m6-floor.md). The outer operation and
the inner MessageBody kind are distinct.

| Node request body | Successful response |
| --- | --- |
| RuntimeFloor | RuntimeFloorResult |
| RuntimeBind | RuntimeBindResult |
| SessionOpen | SessionOpenResult |
| ReportHead | ReportHeadResult |
| ReportReplace | ReportAccepted |
| ListenerReady, LeaseRefresh | LeaseResult |
| LeaseAcquire | LeaseResult for its sole service |
| SnapshotAck, PortResult, PortQueryResult, ServiceRetryPort | Empty carrier receipt |

No other body is a Node unary request (`validate_unary_request`). Every response
echoes the pending outer nonce. A logical retry keeps the M6 `request_id`, exact
content and original lease timing anchor, using a fresh outer nonce.
`PendingRequest` retains the exact validated message, NSD identity and nonce;
consumers retain its association with current contribution/source ownership
before calling `validate_unary_reply`, which yields a `UnaryReply`.

A receipt is an authenticated Response with exactly zero payload bytes, never CBOR
null, an empty Message, HTTP-only success or Error. It confirms carrier acceptance
only, never application, termination, readiness, lease authority or completion of
a retry allocation round. It is refused for other requests and on streams.
ServiceRetryPort refusal, including recovery-required, is failure.

Typed replies compare `request_id`, NSD/Network, subject, runtime pair, epoch and
session.

- Floor and bind results echo the supplied optional/runtime pair, carry the
  current positive epoch consistently with their body and have no session. They
  do not compare an unknown request epoch for equality.
- SessionOpenResult echoes the requested session.
- ReportAccepted matches the submitted revision/digest.
- Publisher LeaseResult matches service, listener revision/digest and
  `refresh_seq`; consumer LeaseResult additionally matches `consumer_seq` and
  snapshot revision/digest.
- On this carrier LeaseAcquire must contain exactly one service. Empty and batched
  requests are refused without changing the underlying M6 list type; use separate
  logical requests with distinct `request_id` and scope/runtime `consumer_seq`
  values.

Error is a separately returned failure, never success. It matches NSD/Network,
subject and `request_id`, echoes the supplied runtime pair, and has no session.
Non-bootstrap errors echo the request epoch; floor errors with a supplied runtime
pair and bind errors carry NSD's current positive epoch. The outer nonce and
retained pending context supply session ownership. Floor without a runtime pair
cannot receive a representable Error. Such failures, pre-decode failures and
failures without correlation facts are carrier failures; no runtime or epoch is
fabricated. Typed negative lease/port results keep their M6 meanings.

### Subscription binding

`PublicationSubscriptionRequest` ([publication](publication.md#request-tuple)) is exactly
`[1, subscriber_I, scopes, capabilities, public_ingress, boot_nonce,
attempt_counter, service_control]`. Inputs of any other arity, including seven
elements, are refused with no fallback. The `service_control` slot
(`ServiceControlBinding`) is null or exactly `[nsd_id, network_id,
runtime_generation, runtime_id, authority_epoch, session_seq,
session_request_id]`.

- Identifiers are M6 16-byte strings; the three counters are positive u64 values.
- `runtime_id` and `session_request_id` must each be nonzero, matching the M6
  `runtime_id` and `request_id` constraints. All-zero NSD and Network identifiers
  remain representable where the M6 codec permits them; this does not establish
  their authority.
- Canonical construction, decoding, authenticated subscription ingress and
  directly supplied stream bindings all apply the same identifier checks.
- The other seven fields keep their meanings as specified in
  [publication](publication.md#subscription-requests-and-stream-delivery).

The caller authenticates current contribution/source authority independently. It
persists a runtime, reserves a fresh `session_seq` and logical SessionOpen
`request_id` for each actual connection attempt, obtains admission, then sends
that exact accepted tuple. `session_request_id` is the accepted SessionOpen id, not
the envelope nonce or publication `boot_nonce`. Each stream binds one Network;
separate Networks use separate bound attempts. A null binding permits no M6
delivery. The authority compares the full tuple against its current persisted
admitted session and contribution before delivery. Ordinary publication authority
and versions remain independent; this slot grants no scope. Reconnect opens a new
session and retains replay observations and content floors.

### Stream events

The SSE event name is `service.control.v1`; data is URL-safe unpadded Base64 of a
complete signed `BootstrapEnvelope`. Response direction, operation, authenticated
NSD signer and mandatory Node recipient are checked. The payload is exactly one
SnapshotPush, PortCancel or PortQuery Message. No receipt or other body is
accepted. The event nonce is generated by NSD under the carrier replay rules;
there is no pending unary nonce correlation.

`validate_stream_event` compares NSD/Network, subject, runtime, epoch and session
against the accepted stream binding (`StreamExpectation`) and exact authenticated
authority/subject. Consumers additionally compare retained current
contribution/source ownership. For SnapshotPush they compare persistent snapshot
revisions/digests and apply the M6 application/ready rules; a snapshot or ACK
never grants a lease.

### Reverse operations

NSD retains each reverse operation's `request_id` and exact proposal under the
current session. The Node compares it against persisted proposal/ownership state,
durably handles cancel or reads query state, then sends a unary PortResult for
cancel or PortQueryResult for query, using a fresh Node outer nonce.
`validate_reverse_result` compares the retained operation with every answer
proposal field and its `request_id`, NSD/Network, subject, runtime, epoch and
session. Its empty receipt echoes this new unary nonce. An unsolicited PortResult
uses a Node-produced `request_id` and requires the consumer's known proposal.

Cancel delivery and receipt are never termination proof: the consumer checks the
durable terminal floor and pinned lifecycle rules. Contribution withdrawal or
replacement fences pending requests and streams; source binding epochs and
generations ([publication](publication.md#source-binding)) are never substituted for M6 epochs or
generations. Original report ownership and bytes are unchanged. Receipts, content
ACKs and cancel delivery never grant readiness, termination or lease authority.

Authentication, clocks, replay observations and accepted stream facts are caller
supplied. Source contribution custody, persistence, content floors, persistent
proposal and lease timing checks are consumer work. Errors are reported as
`ServiceControlError`.

## Code and vectors

Code, in `crates/nsshared-control/src/account/control/` with public items at
`nsshared_control::account::control`:

| File | Contract |
| --- | --- |
| `bootstrap.rs` | `BootstrapDiscovery`, `BootstrapEndpoint`, `ConfidentialCarrier`, `EnvelopePins`, `ControlBoundary`, `validate_control_input`, boundary constants, `BootstrapError` |
| `envelope.rs` | `BootstrapEnvelope`, `EnvelopeDirection`, `EnvelopeExpectation`, clock and replay constants |
| `methods.rs` | Operation and endpoint path constants |
| `exchange.rs` | `MembershipScope`, `RegistrationRequest`, `RegistrationAcceptance`, `compare_registration_acceptance`, `AuthenticationRequest`, `RegistrationCondition`, `AuthenticationSourceScope`, `AuthenticationResponse`, `InformationRequest`, `InformationResponse`, `ExchangeError` |
| `machine_token.rs` | `MachineClaims`, `TokenAudience`, `MachineTokenHeader`, `RsaJwk`, `JwkSet`, `QualifiedKeySet`, `KeySetOwner`, `StoredKeyPins`, `qualify_key_set`, `qualify_owned_key_set`, `machine_refresh_needed`, `TokenError` |
| `reports.rs` | `ControlReportOperation`, `HeartbeatRequest`, `HeartbeatResponse`, `GatewayReport`, `GatewayCertificateObservation`, `GatewayReportResponse`, `MaterialStatusResponse` |
| `reports/node.rs` | `NodeRuntimeFence`, `NodeHeartbeatRequest`, `NodeHeartbeatResponse`, `NodeDisconnectRequest`, `NodeDisconnectResponse`, `NodeReportContext`, `NodeReportError` |
| `signed_request.rs` | `SignedAccountRequest`, `SignedUrlScope` |
| `route_command.rs` | `RouteCommand`, `RouteAction`, `RouteReceipt`, `RouteOutcome`, `RouteResponse`, `CommittedSelection`, `RouteDecision`, `decide_route_command`, `RouteError` |
| `node_l3_status.rs` | `NodeL3StatusRequest`, `NodeL3StatusKey`, `NodeL3Status`, `NodeL3StatusContext`, `NodeL3StatusResponse`, `node_l3_event_digest` |
| `service_control.rs` | `ServiceControlBinding`, `PendingRequest`, `UnaryReply`, `StreamExpectation`, `validate_unary_request`, `validate_unary_reply`, `validate_stream_event`, `validate_reverse_result`, `ServiceControlError` |

Signature domains are at `nsshared_control::account::domains`
(`ACCOUNT_REQUEST_DOMAIN`, `ACCOUNT_RESPONSE_DOMAIN`, `SOURCE_BINDING_DOMAIN`).
Kind 1 service floor values are in `crates/nsshared-control/src/account/families/edge/declaration.rs`
(`nsshared_control::account::edge`); M6 messages and `domain_digest` are at
`nsshared_control::service`.

Vectors are produced independently by the Python producers in
`tools/vectors/nsvec/producers/control/account/` and consumed by Rust tests
without using Rust output as producer input.

| Test module | Vectors | Coverage |
| --- | --- | --- |
| `account::control::envelope` | `crates/nsshared-control/tests/vectors/account/control/envelope.vec` | Discovery and carrier bytes, signatures, expected pins/order/payload/authority, explicit decisions, trust downgrade refusals |
| `account::control::bootstrap_origins` | (inline) | Invalid IDNA origin refusal |
| `account::control::exchange` | `crates/nsshared-control/tests/vectors/account/control/exchange.vec` | Exchange tuples, registration acceptance comparison, signed source binding in responses, machine claims, audience, refresh, key selection and pin ownership |
| `account::control::reports` | `crates/nsshared-control/tests/vectors/account/control/reports.vec`, `crates/nsshared-control/tests/vectors/account/edge/routing.vec` | Report tuples, receipts, kind 1 floor outcomes, usage and material correlation |
| `account::control::reports::node_liveness_refusal` | `crates/nsshared-control/tests/vectors/account/control/node-liveness-refusal.vec` | Signed refusal bytes, closed code/reason combinations, status/nonce/trust checks and complete request correlation |
| `account::control::reports::node_liveness` | `crates/nsshared-control/tests/vectors/account/control/node-liveness.vec` | Independent Node request/response bytes, gateway separation, typed shape and trusted-context refusals, exact receipts |
| `account::edge::auth` | `crates/nsshared-control/tests/vectors/account/edge/auth.vec` | Pending/current auth configuration dependency correlation and private configuration refusals used by material status |
| `account::realm::claims` | `crates/nsshared-control/tests/vectors/account/realm/claims.vec` | `SignedAccountRequest` and `SignedUrlScope` inputs and refusals |
| `account::publication::source_selection` | `crates/nsshared-control/tests/vectors/account/publication/source-selection.vec` | Route command fence (`source_selection_fence`), pending registration, Equal and nodes/egress authentication in one Network including swapped-scope and swapped-realm refusal, exact clear target and source request namespace |
| `account::control::node_l3_route_admission` | `crates/nsshared-control/tests/vectors/account/control/node-l3-route-admission.vec` | Mapped selection versus direct host permission |
| `account::control::node_l3_status` | `crates/nsshared-control/tests/vectors/account/control/node-l3-status.vec` | Signed event digest bytes, canonical reports, exact receipts, replaced-source and same-version/different-event fencing, rejection, authenticated FetchFailed denial and complete-empty removal |
| `account::control::service_control` | `crates/nsshared-control/tests/vectors/account/control/service-control.vec` | Exact bytes for two Networks (`contribution_network_sessions`), receipts, failures and bootstrap results, singleton leases, reverse operations, encoding, bounds, cross-Network and stale-session refusals |

The route command fence sequence uses a labelled authority with the same full
source I, K and derived addresses across sources A and B: register a pending
gateway with no contribution and accept A as nodes authority in its enrollment
Network (Equal keeps that scope); authorize a contribution in that same Network,
then authenticate independently for nodes and egress with the exact pending
selector and nonce, retaining both bindings; refuse swapped scope or realm,
requests missing the selector, missing or mismatched bindings and wrong
correlation for both operations; select and clear A's route; replace only
contribution/generation with B and select B's route; refuse A's delayed signed
success at a higher per-key version; replay A's clear before and after restoring
immutable receipts and current selection from canonical bytes, keeping A's
receipt and leaving B intact; accept the current B publication. Variants refuse
wrong request, boot/attempt or poll context, wrong profile, missing binding,
gateway-ID and carrier-credential fields.

## Ordinary Node device posture

`NODE_POSTURE` (`node.posture`) is a distinct `ControlReportOperation::NodePosture`
operation in the existing signed confidential control carrier, available
unconditionally from `v0.8.0`. It is independent of `node.heartbeat`; existing heartbeat,
disconnect and observation tuples retain their bytes.

`NodePostureRequest` is exactly `[1, membership_scope, runtime_fence, request_id,
snapshot]`. Membership and runtime fence use the same tuples and validity rules
as Node liveness. `request_id` is a 16-byte string, unique for each pending exact
snapshot. There is no machine id. `NodePostureSnapshot` is exactly:

`[os, os_version, arch, client_version, hostname, disk_encryption, uptime_seconds,
local_ips]`.

The first five fields are UTF-8 strings, each at most 1024 bytes; empty strings
remain explicit collected values. `DiskEncryptionStatus` is exactly the text
`encrypted`, `unencrypted` or `unknown`. Uptime is an unsigned 64-bit number of
seconds. The complete local IP list has at most 256 entries, each a valid IPv4 or
IPv6 literal of at most 45 bytes. Supplied spelling, order and duplicates are
preserved. An empty list explicitly replaces the previous addresses. The request
is a complete snapshot, never a partial update. Strict canonical CBOR, exact
arity, the existing overall account byte bound and typed `AccountError` refusals
apply. In-memory bounds violations return `Bounds`; decoding oversized fields or
lists returns `Cbor`; invalid literals and unknown enum values within the text
bound return `Field`.

The ns platform collector produces the facts. Accepted registration and source
custody supply the membership scope; the accepted service runtime supplies the
fence. `NodeReportContext::validate_envelope` verifies the signed request and
compares signer, recipient and membership with persisted enrolled Node and NSD
identities, returning typed `NodeReportError` refusals. The generic report
validator refuses this operation without that context. NSD additionally checks
current source custody and runtime freshness, resolves the internal Node from
that authority, and commits through its existing posture store transaction and
topology notification before emitting a receipt. Client version maps to stored
`nsn_version`; NSD supplies `reported_at` at commit. Client facts neither select
an internal machine id nor grant policy or route admission by themselves.

`NodePostureResponse` is exactly `[1, membership_scope, runtime_fence,
request_id]`. The signed Response uses the existing trust, recipient, direction,
operation and pending envelope nonce checks. `validate_for` compares both scope
identifiers, all three fence fields and the request id with the retained sent
request. Senders retain the exact snapshot under that unique id and only mark
it delivered after the matching receipt. The receipt acknowledges only that
snapshot, never a later sample; missing or mismatched receipts acknowledge
nothing. It does not renew a runtime or establish current posture freshness.

Collection and reporting retain their independent periodic/triggered cadence;
they are not attached to every heartbeat. Missing, stale or nonmatching posture
continues to deny posture-conditioned policy through the existing evaluator.

The implementation is `reports/node_posture.rs`; tests in
`account::control::reports::node_posture` consume independent Python-produced
`account/control/node-posture.vec` fixtures for complete and empty snapshots,
each encryption value, exact boundaries, typed refusals, authenticated context
and each receipt correlation field.

## Historical shared registration recovery

The existing authenticated `machine.registration_receipt.v1` operation retains
its legacy named-field carrier, grant/operation locator, signature, nonce, time,
recovery deadline and separate current-authority observation. Its adapter may
carry the following pure versioned shared contracts as canonical bytes; these
are not a BootstrapEnvelope, a new endpoint or a new receipt authority.

`RegistrationRecoveryQuery` is exactly `[1, operation_id, membership_scope,
request_digest]`: operation is the existing nonzero 16-byte approved operation,
membership scope is the existing `[nsd_id, network_id]` pair, and digest is
SHA-256 of the complete canonical `RegistrationRequest` bytes, including the
credential and lifecycle. `RegistrationRecoveryAttachment` is exactly
`[1, canonical_query_bytes, original_canonical_acceptance_bytes]`. Versions,
arity, lengths, canonical integers and trailing bytes are checked strictly.
Existing request and acceptance encodings are unchanged.

NSD's original registration transaction produces the attachment from the
approved device operation and exact authorized request. It must atomically
retain the original signed acceptance with enrollment, source allocation,
old-source retirement and grant consumption, and return those persisted bytes
on first response and exact recovery. A historical result without those bytes
cannot be repaired by signing today's source. The existing named-field adapter
compares the authenticated installation and query against the immutable result.
Activation generation and credential incarnation remain facts of that existing
receipt result and its current-authority comparison, not new shared fields.

The ns pending replacement plan retains each approved operation, canonical
request, unchanged committed binding, lifecycle authorization, pinned NSD
issuer, exact source custody tuple and epoch/generation floors independently of
the response. `RegistrationRecoveryExpectation` supplies those inputs.
`validate` compares operation, NSD/Network, digest, enrollment including identity
and WireGuard key, capabilities, profile and the lifecycle decision using the
same comparisons as the original exchange. It verifies the original source
signature against the retained issuer and compares recipient, realm, nodes
scope, profile, source Node, contribution, epoch and generation exactly, while
refusing values below either retained floor. A response cannot supply its own
expected issuer or baseline. No floor is lowered to accept historical bytes.

The receipt transport is authenticated separately against the independently
pinned issuer and staged installation. A recovery query has a fresh transport
nonce; it is never compared to the original registration nonce by these pure
validators. The original source signature has no transport nonce. A fresh outer
signed receipt does not refresh the original source binding. The attachment
establishes historical acceptance only: NSD separately observes current custody,
account activation and credential authority; ns requires that fresh observation
for every Network and rechecks unchanged local baselines before publishing the
one staged identity and all accepted records together. Lookup absence alone
does not establish nonacceptance or authorize reenrollment.

Independent Python recovery vectors are appended to the existing exchange
fixture through `registration_recovery.py`; Rust consumes original signed bytes
without re-signing. The account feature remains an unstable opt-in public
surface; default-feature compatibility is checked through the existing semver
entry point.
