# Candidate control exchange

Membership realm identities follow the [canonical RealmId contract](canonical-realm-identity.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
NSD/ns producer and consumer updates, including the other active consumer delivery,
remain outstanding. Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


This pure candidate extends enrollment and bootstrap, and the existing claim
values. It adds no transport, session, credential custody, key acquisition or
pin-store I/O. Producers independently review these bytes before live adoption.

## Operations and carriers

The constants in `account::control_exchange` define `machine.register`,
`machine.auth`, `info.get`, `/api/v1/control`, `/api/v1/info` and
`/.well-known/jwks.json` once. All signed operations use the control endpoint.
Discovery uses the information endpoint and machine signing keys use the key-set
endpoint. No JSON fallback or plaintext carrier is supported.

Requests and answers are payload bytes of BootstrapEnvelope. A caller must use
a confidential authenticated BootstrapDiscovery carrier and verify the envelope
with EnvelopeExpectation before interpreting payloads. Registration requests
must be signed by the presented enrollment binding's I. Answers must be signed
by the trusted authority, response directed, with the matching operation and
recipient. Nonces, skew, replay observations and signing domains remain exactly
the bootstrap contract. `BootstrapEnvelope::signing_input()` is the sole public
pure domain-plus-canonical-content encoder; signing and private keys stay outside.

## Canonical tuples

All tuples use shortest definite CBOR, schema 1, no trailing bytes, and the
existing account size limit. Nested contracts are exact canonical byte strings.
Membership realm text is exactly the canonical 26-character RealmId spelling. Other text fields are nonempty control-free UTF-8 of at most 256 bytes. Capabilities
reuse Enrollment's sorted unique bounded identifier set. No normalization occurs.

- Membership scope: `[nsd_id_16, network_id_16]`.
- Registration request: `[1, scope, enrollment_bytes, profile, credential_bytes,
  lifecycle_bytes_or_null]`. Credential is opaque, nonempty and at most 16 KiB;
  it is interpreted only by the provisioned authority. No auth-key/OAuth inference
  occurs. Lifecycle is absent for initial enrollment and otherwise reuses Lifecycle.
- Registration acceptance: `[1, scope, enrollment_bytes, profile, decision, source_binding_bytes]`.
  Decision is 0 initial, 1 equal, 2 identity replacement, 3 record rotation.
  Matching compares scope, the entire binding (I/K/version/generation), exact
  capabilities and profile, then recomputes decide_enrollment against the prior
  committed binding, supplied lifecycle and explicit rebind authorization.
  Typed mismatch never commits a new binding; a receipt or token is insufficient.
- Authentication request: `[1, scope, binding, purpose, [served_realm, publication_scope]]`; purpose is `control`.
  Signer must equal binding I. No retired WebSocket leg or gateway role is carried.
- Authentication response: `[1, compact_token, source_binding_bytes]`. Token is opaque bounded ASCII;
  decoding is not signature verification, trust or acceptance.
- Information request: `[1]`.
- Information response: `[1, discovery_bytes, instance_realm_hint, provider, version,
  auth_methods, capabilities]`. Auth methods are sorted unique `auth_key`,
  `device_flow`, `oauth2`; capabilities use the existing enrollment rules.
  The realm hint is instance-level display metadata, not tenant authority.
  Discovery retains exact ordered endpoints and separate envelope/transport pins.

The pure registration acceptance comparison takes the response envelope and its
EnvelopeExpectation as well as the staged request and prior binding. It verifies
all envelope expectations and exact payload equality before deciding enrollment.
Request validation likewise verifies the request envelope and checks its signer
against the presented I. Pure helpers never store authority.

## Machine claims and key sets

Machine JWTs remain compact RS256. Public `MachineClaims` JSON retains `iss`
(default empty), required `sub`, `realm`, `iat`, `exp`, `jti`, optional `aud`
(string or string array), `mid_kty` and `mid_pub` (default empty). Legacy role,
gateway-id and gateway peer-key claims are inert unknown JSON members; they
create no authority. Subject remains the exact registered machine identifier;
ordinary Node consumers supply their accepted identity-derived identifier. No
string-to-binary payer conversion occurs. Admin claims and PolicySubject reuse
the existing types; machine claims do not duplicate admin scopes.

After external RS256 signature and qualified-key verification, the gateway
predicate always compares sub. Unless explicitly allowed by consumer policy,
mid_kty must equal `ed25519` and mid_pub the lowercase hex of accepted I. It
refuses expiry only when supplied now > exp + 30; arithmetic uses i128. Refresh
is needed for missing expiry or exp-now <= 300 seconds. Failed authentication
or refresh preserves the previously verified bearer in consumer custody.

The gateway does **not** compare aud: absent, unrelated single and array
values retain their existing outcome. The distinct NSD machine-audience verifier
requires the single string `nsd-machine-control`; its typed claims reject
array-shaped aud even when an element matches. Wrong-audience vectors are
labelled `nsd-audience`; they are not gateway refusals. Whether a later gateway
candidate should require machine audience remains an open owner-review item.
NSD's JWT library expiry leeway is separately 60 seconds; the gateway's 30-second
predicate must not be replaced by it. This package exposes the NSD audience
comparison alone, not an imitation of its complete verifier or external OIDC.

RsaJwk JSON has kty, optional kid/alg/use, n/e; JwkSet has keys in source order.
Unsupported object descriptions are discarded in source order; scalar members,
duplicate key lists and malformed/trailing JSON refuse.
Usable keys require RSA, RS256, nonempty kid/n/e, use absent or `sig`, and strict
base64url n/e. Leading zero component bytes retain their existing qualification
outcome; cryptographic RSA verification remains external. Wrong `enc` use refuses. RFC 7638
thumbprints hash exact JSON `{"e":"E","kty":"RSA","n":"N"}`. The
pure qualifier discards unsupported members, filters by effective pins and
refuses no usable or no trusted keys. Duplicate kid selection retains first
source-order match. Missing kid selects exactly one qualified key; no keys
refuses missing kid and multiple keys refuse ambiguity. Unknown kid is a typed
miss; the consumer performs at most one paced refresh then repeats selection.

Pin ownership is exact realm plus key-set address after trimming outer whitespace
and trailing slashes. Static pins bypass persisted first-use pins. Without static
pins, matching-owner stored pins are authoritative; absent stored pins learn all
usable fetched keys once. Existing pins never append advertised rotations.
Rotation may add/remove keys only inside the effective pin set; substitution
without a matching pin refuses. Qualified keys and newly learned pins are returned
as values; consumers durably persist first-use pins before publishing them.
Envelope signer pins are a separate trust purpose and never token-key pins.

Runtime retains a 300-second successful receipt cache (strictly younger), an
8-second forced-refresh quiet period, replaced-observation sharing, and a
31-second acquisition deadline. Failed acquisition preserves last complete keys
and their original receipt, publishes diagnostic failure and never extends
freshness. These are documented consumer obligations, not shared timers.

## Complete pinned consumer disposition

Inventory source: gateway `deps/v1-consumers.toml` at
`17264f418884227674737c0cda8acb3553c9b7e8`. Each of the 264 control-trust
and enrollment rows has one disposition below, including sender and test rows.
These mappings are candidate replacements, not claims of deployed equivalence.
Legacy hostname/OS/software/system telemetry is retired from registration authority;
provider/version remain explicit information metadata. Domain names belong to the
existing public-edge publication. Neither assigned gateway addresses nor server
peer keys create a second Node identity. Provisioning selects the credential;
no implicit OAuth/auth-key fallback survives.

| Source path | Item | Candidate disposition |
| --- | --- | --- |
| `crates/nsgw-contract-v1/tests/fixtures/events/material/oidc.json` | `wire:kind` | Retained historical fixture record pending removal of the temporary crate; not migrated. |
| `crates/nsgw-contract-v1/tests/fixtures/events/material/oidc.json` | `wire:ref` | Retained historical fixture record pending removal of the temporary crate; not migrated. |
| `crates/nsgw-contract-v1/tests/fixtures/reports/producer/usage-sequence-gap.json` | `wire:accepted_through_seq` | Retained historical fixture record pending removal of the temporary crate; not migrated. |
| `crates/nsgw-contract-v1/tests/fixtures/reports/producer/usage-window-overlap.json` | `wire:accepted_through_seq` | Retained historical fixture record pending removal of the temporary crate; not migrated. |
| `crates/nsgw-control/src/client/auth.rs` | `api::auth::AuthPayload` | AuthenticationRequest scope/binding and fixed control purpose; legacy WebSocket leg and gateway roles retired. |
| `crates/nsgw-control/src/client/auth.rs` | `api::auth::AuthResponse` | AuthenticationResponse token; external RS256 verification, never enrollment acceptance. |
| `crates/nsgw-control/src/client/auth.rs` | `claims::machine::MachineClaims` | machine_token::MachineClaims / TokenAudience / validate_gateway; exact subject and optional self-binding, no gateway audience comparison. |
| `crates/nsgw-control/src/client/auth.rs` | `claims::machine::verify_machine_claims` | machine_token::MachineClaims / TokenAudience / validate_gateway; exact subject and optional self-binding, no gateway audience comparison. |
| `crates/nsgw-control/src/client/auth.rs` | `vocabulary::core::MACHINE_AUTH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/auth.rs` | `vocabulary::core::MACHINE_AUTH_PURPOSE` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/config.rs` | `vocabulary::core::CAPABILITY_GATEWAY_PUBLIC_EDGE_V1` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/config.rs` | `vocabulary::core::LinkMode` | Retire legacy mode negotiation/default; BootstrapDiscovery explicitly advertises confidential carriers and relay directory capabilities. |
| `crates/nsgw-control/src/client/config.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/config.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_STATE_FENCE` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/config.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_UPSTREAM_TLS_ACCEPT_UNTRUSTED` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/config.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/envelope.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/src/client/envelope.rs` | `api::support::InfoGetRequest` | InformationRequest empty canonical tuple. |
| `crates/nsgw-control/src/client/envelope.rs` | `api::support::InfoGetResponse` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/src/client/envelope.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/src/client/envelope.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/src/client/envelope.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/envelope.rs` | `envelope::wrapper::DOMAIN_REQUEST` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/envelope.rs` | `envelope::wrapper::EnvelopeError` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/envelope.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/src/client/envelope.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/src/client/envelope.rs` | `rules::pins::ed25519_pubkey_hex_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/src/client/envelope.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/src/client/envelope.rs` | `rules::pins::pin_gate_response_key` | EnvelopePins::intersect and BootstrapEnvelope::verify; token pins remain independent. |
| `crates/nsgw-control/src/client/envelope.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/mod.rs` | `envelope::bootstrap::ControlTransportKind` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/src/client/mod.rs` | `rules::bootstrap::decode_lower_hex32` | Retire textual hex transport-key decoding in favor of exact bounded binary BootstrapDiscovery.noise_key. |
| `crates/nsgw-control/src/client/mod.rs` | `rules::bootstrap::decode_pin_set` | BootstrapDiscovery strict canonical origin and pin validation. |
| `crates/nsgw-control/src/client/mod.rs` | `rules::bootstrap::validate_https_origin` | BootstrapDiscovery strict canonical origin and pin validation. |
| `crates/nsgw-control/src/client/mod.rs` | `rules::pins::effective_discovered_envelope_pins` | EnvelopePins::intersect and BootstrapEnvelope::verify; token pins remain independent. |
| `crates/nsgw-control/src/client/register.rs` | `api::registration::RegisterRequest` | RegistrationRequest scope/enrollment/profile/credential/lifecycle; legacy type, server endpoint and assigned tunnel address retired for ordinary Node binding. |
| `crates/nsgw-control/src/client/register.rs` | `api::registration::RegisterResponse` | RegistrationAcceptance scope/enrollment/profile/decision; machine identity derives from I, no separately assigned gateway address or peer. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::CAPABILITY_GATEWAY_PUBLIC_EDGE_V1` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::ConnectorType` | Retire gateway-specific registration identity role; ordinary Node enrollment, roster IdentityClass supplies separate metering classification. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::LinkMode` | Retire legacy mode negotiation/default; BootstrapDiscovery explicitly advertises confidential carriers and relay directory capabilities. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_STATE_FENCE` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_UPSTREAM_TLS_ACCEPT_UNTRUSTED` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/register.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/src/client/stream.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/stream_predecessor_tests.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/tests.rs` | `api::registration::RegisterRequest` | RegistrationRequest scope/enrollment/profile/credential/lifecycle; legacy type, server endpoint and assigned tunnel address retired for ordinary Node binding. |
| `crates/nsgw-control/src/client/tests.rs` | `api::registration::RegisterResponse` | RegistrationAcceptance scope/enrollment/profile/decision; machine identity derives from I, no separately assigned gateway address or peer. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::AuthMethod` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::InfoGetRequest` | InformationRequest empty canonical tuple. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::InfoGetResponse` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::NsdInfo` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::NsdType` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/src/client/tests.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/src/client/tests.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/tests.rs` | `envelope::wrapper::DOMAIN_REQUEST` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/tests.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/tests.rs` | `envelope::wrapper::EnvelopeError` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/client/tests.rs` | `envelope::wrapper::MAX_CLOCK_SKEW_SECS` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/src/client/tests.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/src/client/tests.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/src/client/tests.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/src/client/tests.rs` | `vocabulary::core::ConnectorType` | Retire gateway-specific registration identity role; ordinary Node enrollment, roster IdentityClass supplies separate metering classification. |
| `crates/nsgw-control/src/client/tests.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/tests.rs` | `vocabulary::core::LinkMode` | Retire legacy mode negotiation/default; BootstrapDiscovery explicitly advertises confidential carriers and relay directory capabilities. |
| `crates/nsgw-control/src/client/tests.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/token_keys.rs` | `envelope::pins::JwkSet` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/client/token_keys.rs` | `vocabulary::transport::JWKS_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/token_keys_tests.rs` | `envelope::pins::JwkSet` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/client/token_keys_tests.rs` | `envelope::pins::RsaJwk` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/client/token_keys_tests.rs` | `rules::pins::rsa_jwk_thumbprint` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/client/token_keys_tests.rs` | `vocabulary::transport::JWKS_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/client/token_keys_tests/runtime_key_deadlines_preserve_machine_boot_retries.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/discovery.rs` | `envelope::bootstrap::DiscoveryDocument` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/src/discovery.rs` | `rules::bootstrap::validate_https_origin` | BootstrapDiscovery strict canonical origin and pin validation. |
| `crates/nsgw-control/src/discovery.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/discovery.rs` | `vocabulary::transport::MAX_DISCOVERY_BYTES` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/src/error.rs` | `envelope::wrapper::EnvelopeError` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/event_verification.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/event_verification.rs` | `envelope::wrapper::REPLAY_WINDOW_SECS` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/event_verification.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/src/event_verification.rs` | `rules::pins::pin_gate_response_key` | EnvelopePins::intersect and BootstrapEnvelope::verify; token pins remain independent. |
| `crates/nsgw-control/src/lib.rs` | `envelope::bootstrap::BootstrapError` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/src/token_keys.rs` | `envelope::pins::JwkSet` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/token_keys.rs` | `rules::pins::rsa_jwk_thumbprint` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/token_pins.rs` | `rules::pins::rsa_jwk_thumbprint` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/src/transport/error.rs` | `envelope::wrapper::EnvelopeError` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/transport/framing.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/transport/framing.rs` | `vocabulary::transport::MAX_CALL_BODY` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/src/transport/framing.rs` | `vocabulary::transport::MAX_HTTP_HEADERS` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/src/transport/https.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/src/transport/https.rs` | `api::support::ConfigStreamRequest` | publication_subscription::PublicationSubscriptionRequest; exact issuer/recipient/PublicationScope entries, capabilities, public ingress indices and boot nonce/attempt counter; no additional acceptance state. |
| `crates/nsgw-control/src/transport/https.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/src/transport/https.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/transport/https.rs` | `rules::bootstrap::validate_https_origin` | BootstrapDiscovery strict canonical origin and pin validation. |
| `crates/nsgw-control/src/transport/https.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/transport/mod.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/transport/noise.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/transport/noise.rs` | `envelope::wrapper::ENVELOPE_VERSION` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/transport/noise.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/transport/noise.rs` | `vocabulary::transport::NOISE_LEN_PREFIX` | Retain consumer transport parameters Noise_IK_25519_ChaChaPoly_BLAKE2s, two-byte frame prefix, nsd-http1 ALPN; execution is consumer-owned. |
| `crates/nsgw-control/src/transport/noise.rs` | `vocabulary::transport::NOISE_MAX_FRAME` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/src/transport/noise.rs` | `vocabulary::transport::NOISE_MAX_PAYLOAD` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/src/transport/noise.rs` | `vocabulary::transport::NOISE_PARAMS` | Retain consumer transport parameters Noise_IK_25519_ChaChaPoly_BLAKE2s, two-byte frame prefix, nsd-http1 ALPN; execution is consumer-owned. |
| `crates/nsgw-control/src/transport/quic.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/src/transport/quic.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/src/transport/quic.rs` | `vocabulary::transport::QUIC_HTTP1_ALPN` | Retain consumer transport parameters Noise_IK_25519_ChaChaPoly_BLAKE2s, two-byte frame prefix, nsd-http1 ALPN; execution is consumer-owned. |
| `crates/nsgw-control/tests/admin_refresh_pacing.rs` | `claims::admin::AdminClaims` | Reuse AdminTokenClaims / AdminScope and require_scope; no inferred human-login scope. |
| `crates/nsgw-control/tests/admin_refresh_pacing.rs` | `claims::admin::AdminScope` | Reuse AdminTokenClaims / AdminScope and require_scope; no inferred human-login scope. |
| `crates/nsgw-control/tests/auth.rs` | `api::auth::AuthPayload` | AuthenticationRequest scope/binding and fixed control purpose; legacy WebSocket leg and gateway roles retired. |
| `crates/nsgw-control/tests/auth.rs` | `api::auth::AuthResponse` | AuthenticationResponse token; external RS256 verification, never enrollment acceptance. |
| `crates/nsgw-control/tests/auth.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/auth.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/auth.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/auth.rs` | `claims::machine::MachineClaims` | machine_token::MachineClaims / TokenAudience / validate_gateway; exact subject and optional self-binding, no gateway audience comparison. |
| `crates/nsgw-control/tests/auth.rs` | `claims::machine::TokenAudience` | machine_token::MachineClaims / TokenAudience / validate_gateway; exact subject and optional self-binding, no gateway audience comparison. |
| `crates/nsgw-control/tests/auth.rs` | `envelope::pins::JwkSet` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/tests/auth.rs` | `envelope::pins::RsaJwk` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/tests/auth.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/auth.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/auth.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/auth.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/auth.rs` | `rules::pins::rsa_jwk_thumbprint` | machine_token::RsaJwk / JwkSet / thumbprint / qualify_key_set; separate realm/address pin ownership. |
| `crates/nsgw-control/tests/auth.rs` | `vocabulary::core::MACHINE_AUTH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/auth.rs` | `vocabulary::core::MACHINE_AUTH_PURPOSE` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/auth.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/auth.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/auth.rs` | `vocabulary::transport::JWKS_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/auth/stream_events.rs` | `envelope::wrapper::MAX_CLOCK_SKEW_SECS` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/tests/auth/stream_events.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/tests/auth/stream_events/opening.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/auth/stream_events/opening.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/tests/client.rs` | `api::registration::RegisterRequest` | RegistrationRequest scope/enrollment/profile/credential/lifecycle; legacy type, server endpoint and assigned tunnel address retired for ordinary Node binding. |
| `crates/nsgw-control/tests/client.rs` | `api::registration::RegisterResponse` | RegistrationAcceptance scope/enrollment/profile/decision; machine identity derives from I, no separately assigned gateway address or peer. |
| `crates/nsgw-control/tests/client.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/client.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/client.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/client.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/client.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/client.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/client.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/client.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/client.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/client.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/client_status_headers_stop_selection_without_reading_the_body.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/client_status_headers_stop_selection_without_reading_the_body.rs` | `vocabulary::transport::MAX_CALL_BODY` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/tests/discovery.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/discovery.rs` | `vocabulary::transport::MAX_DISCOVERY_BYTES` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/tests/endpoint.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/endpoint.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/endpoint.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/endpoint.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/endpoint.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/endpoint.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/endpoint.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/envelope_probe_preserves_terminal_http_status.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/envelope_probe_preserves_terminal_http_status.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/envelope_probe_preserves_terminal_http_status.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/envelope_probe_preserves_terminal_http_status.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/envelope_probe_preserves_terminal_http_status.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/event_support.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/event_support.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/event_support.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/event_support.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/noise.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/noise.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/noise.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/noise.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `api::registration::RegisterRequest` | RegistrationRequest scope/enrollment/profile/credential/lifecycle; legacy type, server endpoint and assigned tunnel address retired for ordinary Node binding. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/noise_discovery_rejects_noncontributory_static_keys.rs` | `vocabulary::transport::NOISE_PARAMS` | Retain consumer transport parameters Noise_IK_25519_ChaChaPoly_BLAKE2s, two-byte frame prefix, nsd-http1 ALPN; execution is consumer-owned. |
| `crates/nsgw-control/tests/noise_support.rs` | `vocabulary::transport::NOISE_PARAMS` | Retain consumer transport parameters Noise_IK_25519_ChaChaPoly_BLAKE2s, two-byte frame prefix, nsd-http1 ALPN; execution is consumer-owned. |
| `crates/nsgw-control/tests/quic.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/quic.rs` | `api::support::InfoGetRequest` | InformationRequest empty canonical tuple. |
| `crates/nsgw-control/tests/quic.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/quic.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/quic.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/quic.rs` | `rules::bootstrap::decode_pin_set` | BootstrapDiscovery strict canonical origin and pin validation. |
| `crates/nsgw-control/tests/quic.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/quic.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/quic.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/quic.rs` | `vocabulary::transport::QUIC_HTTP1_ALPN` | Retain consumer transport parameters Noise_IK_25519_ChaChaPoly_BLAKE2s, two-byte frame prefix, nsd-http1 ALPN; execution is consumer-owned. |
| `crates/nsgw-control/tests/registration_binds_payload_machine_identity.rs` | `api::registration::RegisterResponse` | RegistrationAcceptance scope/enrollment/profile/decision; machine identity derives from I, no separately assigned gateway address or peer. |
| `crates/nsgw-control/tests/registration_binds_payload_machine_identity.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/registration_binds_payload_machine_identity.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/registration_binds_payload_machine_identity.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/registration_binds_payload_machine_identity.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/registration_binds_payload_machine_identity.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/signed.rs` | `api::support::InfoGetRequest` | InformationRequest empty canonical tuple. |
| `crates/nsgw-control/tests/signed.rs` | `api::support::InfoGetResponse` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/signed.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/signed.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/signed.rs` | `vocabulary::core::MACHINE_REGISTER` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `api::support::ConfigStreamRequest` | publication_subscription::PublicationSubscriptionRequest; exact issuer/recipient/PublicationScope entries, capabilities, public ingress indices and boot nonce/attempt counter; no additional acceptance state. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `api::support::InfoGetRequest` | InformationRequest empty canonical tuple. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `api::support::InfoGetResponse` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `envelope::wrapper::DOMAIN_REQUEST` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `rules::bootstrap::decode_pin_set` | BootstrapDiscovery strict canonical origin and pin validation. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `vocabulary::transport::JWKS_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/snapshot.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/snapshot.rs` | `envelope::wrapper::MAX_CLOCK_SKEW_SECS` | Existing ControlBoundary and MAX_CONTROL_* / MAX_BOOTSTRAP_BYTES bounds. |
| `crates/nsgw-control/tests/snapshot.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/tests/snapshot_replay_covers_all_realm_entries.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/support.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/support.rs` | `api::support::AuthMethod` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/support.rs` | `api::support::InfoGetResponse` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/support.rs` | `api::support::NsdInfo` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/support.rs` | `api::support::NsdType` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/support.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/support.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | BootstrapDiscovery / ConfidentialCarrier / BootstrapError, schema and trust version 1; no legacy trust fallback. |
| `crates/nsgw-control/tests/support.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/support.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/support.rs` | `envelope::wrapper::EnvelopeError` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/support.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/support.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/support.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing BootstrapDiscovery envelope pins and EnvelopePins; no hex key facade. |
| `crates/nsgw-control/tests/support.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/support.rs` | `vocabulary::core::LinkMode` | Retire legacy mode negotiation/default; BootstrapDiscovery explicitly advertises confidential carriers and relay directory capabilities. |
| `crates/nsgw-control/tests/support.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/support.rs` | `vocabulary::transport::DISCOVERY_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/support.rs` | `vocabulary::transport::JWKS_PATH` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/transport.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/transport.rs` | `api::support::ConfigStreamRequest` | publication_subscription::PublicationSubscriptionRequest; exact issuer/recipient/PublicationScope entries, capabilities, public ingress indices and boot nonce/attempt counter; no additional acceptance state. |
| `crates/nsgw-control/tests/transport.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/transport.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/transport.rs` | `envelope::wrapper::DOMAIN_REQUEST` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/transport.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/transport.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/transport.rs` | `vocabulary::core::CAPABILITY_NSC_APPLICATION_UDP_V1` | Enrollment.capabilities and explicit consumer public-edge subscription scopes; advertising grants no authority. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `api::registration::RegisterResponse` | RegistrationAcceptance scope/enrollment/profile/decision; machine identity derives from I, no separately assigned gateway address or peer. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `api::support` | Split into InformationRequest/Response, AuthenticationResponse and per-type codecs; system telemetry retired from enrollment authority. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `api::support::InfoGetRequest` | InformationRequest empty canonical tuple. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `api::support::InfoGetResponse` | InformationResponse discovery/realm/provider/version/auth_methods/capabilities; deployment type retired as non-authorizing display metadata. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; retire permissive generic serializer as an authority boundary. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `envelope::wrapper::ControlEnvelope` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | BootstrapEnvelope / BootstrapError / ACCOUNT_REQUEST_DOMAIN / ACCOUNT_RESPONSE_DOMAIN and existing skew/replay constants; version 1. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `rules::envelope::SignatureInput` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `rules::envelope::build_signature_input` | BootstrapEnvelope::signing_input; unchanged canonical content and direction domains. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `vocabulary::core::INFO_GET` | control_exchange constants retain exact operation and endpoint values. |
| `crates/nsgw-control/tests/unary_responses_preserve_optional_recipient.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | control_exchange constants retain exact operation and endpoint values. |

## Producer checklist and outstanding review

The pinned producer distinguishes provisioned enrollment from signature ownership:
approval credentials authorize ordinary Node membership, while the request signer
proves I ownership. Registered metadata refresh cannot silently change a peer key;
new binding acceptance uses the explicit lifecycle contract. Platform gateway
registration, assigned tunnel addresses and server peer stubs are retired here in
favor of the ordinary Node binding. The candidate fixture authority must check
provisioned membership and credential before returning acceptance; no shared helper
can substitute for that external authority lookup.

Signed information reuses the same discovery trust as authenticated HTTPS discovery.
The instance realm hint, provider and version are informational. NSD currently emits
device-flow authentication, control trust, ordered endpoints and additive features;
feature understanding maps to declared capability identifiers without creating grants.
Update-distribution metadata, optional attestation and legacy deployment display type
are not enrollment authority and are retired from this control exchange.
Machine-control token minting binds the registered machine key, actual membership
and current authority. Legacy WSS companion tokens and role-specific legs are
retired; they do not acquire a second candidate authentication path. Authentication
request signature/subject matching, key qualification and external RSA verification
remain mandatory even when a consumer explicitly permits unbound machine claims.
NSD confirmation of the exact candidate tuples and independent producer vectors
remains outstanding. This checklist does not claim current producer compatibility.

## Retained predicate sources

Gateway source revision is `17264f418884227674737c0cda8acb3553c9b7e8`.
`crates/nsgw-control/src/client/auth.rs` supplies RS256-before-key-selection,
exact subject/nonwaived signing-key binding, expiry `now > exp + 30`, one
unknown-key refresh and missing-kid singleton selection. Its audience-agnostic
behavior is explicitly asserted by `tests/auth.rs` in
`machine_token_accepted_regardless_of_audience_shape`. The refresh predicate is
missing bearer or at most 300 seconds remaining. `src/token_keys.rs` supplies
static/stored/first-use pin precedence and pinned rotation;
`src/token_pins.rs` supplies exact realm plus trimmed address ownership.
`src/client/token_keys_tests.rs` explicitly rejects encryption-key use without
learning pins. The called public `crates/nsgw-realm/src/tokens.rs` qualifier
allows absent use, rejects explicit non-sig use and decodes base64url components
without a leading-zero predicate; this candidate preserves those outcomes.

NSD source revision is `3d0b71dfcba61ec858247c3c74d2d98e77d3d08b`.
`crates/nsd-auth/src/machine.rs` has string-shaped machine aud and a separate
RS256 verifier requiring the machine audience. Its default library expiry
leeway is distinct from the gateway predicate. `crates/nsd-api/src/envelope.rs`
dispatches information, enrollment and authentication; `handlers.rs` reuses
strict discovery and emits the RS256 machine-control token. Their existing
handlers are a producer checklist, not confirmation of this candidate encoding.

## Control reports

[Control report exchanges](control-report-candidate.md) defines heartbeat, gateway
observations, services, usage and material status on the same confidential endpoint.
The constants stay in control_exchange. No auth configuration acquisition is defined
by the report contract. NSD producer confirmation remains outstanding.
## Authenticated publication subscription

`control_exchange::CONFIG_STREAM` is `config.stream` and
`control_exchange::CONFIG_STREAM_PATH` is `/api/v1/config/stream`.
`account::publication_subscription::PublicationSubscriptionRequest` is the
candidate request. Its canonical CBOR tuple is:

`[1, subscriber_I, scopes, capabilities, public_ingress, boot_nonce, attempt_counter, service_control]`.

Each scope is `[issuer_I, recipient_I, served_realm, scope]`: full 32-byte
identities, canonical 26-character RealmId text and a nonempty opaque scope of
at most 256 UTF-8 bytes without control characters. Entries are strictly sorted by those four values and unique;
every recipient equals subscriber_I. There are at most 32 entries. These are
exact requested PublicationScope pairs bound to their issuer/recipient, never
wildcards or grants. The producer must compare them against externally
provisioned/accepted authority before sending publications.

Capabilities retain the predecessor's understanding-only meaning and the existing
enrollment rule: at most 64 sorted unique tokens, 1..64 ASCII bytes matching
`[a-z0-9._-]+`. Public ingress is a strictly increasing array of at most 32
zero-based indices into scopes. Each index requests family 7 `public-edge` for
that exact issuer/recipient/realm/scope. It grants no exposure or material
readiness. Unlike predecessor bare strings, indices cannot lose realm/issuer
qualification. Empty arrays request no corresponding scopes or capabilities.

The predecessor stream_session becomes two required correlation fields: a
nonzero 16-byte boot_nonce and a positive u32 attempt_counter. The caller supplies
a fresh nonce each restart, begins at one, reuses the pair across endpoint
fallbacks and increments without wrapping for each outer reconnect. Exhaustion
fails closed. The codec validates parts but cannot prove restart uniqueness.
No optional/unbound subscription is retained. The pair does not establish a
session runtime, acceptance state, replay exemption, version reset or replacement
for per-PublicationKey versions and withdrawal/failure tombstones.

The request payload is bounded to 8192 bytes before decoding. Fixed tuple arity,
minimal CBOR, no trailing bytes and bounded arrays reject unknown fields,
noncanonical encodings and oversized declarations before allocation.
The existing BootstrapEnvelope carries the exact payload and operation in request
direction; BootstrapEnvelope::signing_input supplies the unchanged domain plus
canonical content bytes. The signer equals subscriber_I and the mandatory carrier
recipient equals every requested issuer. The authenticated ingress also checks
the configured subscriber/authority and authorized exact scope set; decoding
alone confers no authority. Existing confidential HTTPS/Noise/QUIC carriers and
encoded-subscription bounds apply; no plaintext, empty unsigned request or JSON
fallback is introduced. HTTP may carry the signed envelope in the existing
base64url request parameter; URL encoding and stream I/O remain consumer work.
Stream and independently polled snapshot authority keep their existing kind
ownership; a subscription never moves a snapshot kind to the stream.

Independent publication-subscription vectors cover accepted empty and populated
sets, exact bytes, capability and attempt boundaries, wrong recipient, duplicate
and unsorted sets, oversized declarations, unknown fields and nonminimal bytes.
NSD confirmation of this exact candidate and producer vectors is outstanding;
the current predecessor handler is a checklist, not interoperability evidence.

## Independent publication snapshot poll

| Predecessor | Candidate | Meaning |
|---|---|---|
| GatewayRealmConfigSnapshotRequest.stream_session | boot_nonce, attempt_counter | Required nonzero restart nonce and positive checked u32 logical stream attempt; same caller-supplied identity as the active subscription. No session runtime or scope grant. |
| GatewayRealmConfigSnapshotRequest | PublicationSnapshotRequest | Subscriber plus exact sorted issuer/recipient/served-realm/scope entries, at most 32; every recipient is the subscriber. No predecessor kind selector existed. All snapshot-owned kinds within each entry are requested; stream kinds are never requested. |
| GatewayRealmConfigSnapshotResponse.realms[].realm_id/events | PublicationSnapshot | Existing canonical signed-event container, with each event retaining its full authenticated publication key. Empty snapshots retain state; signed empty event payloads withdraw only their exact key. |

The predecessor operation `gateway.realm_config_snapshot` is replaced by
`config.snapshot`; gateway-only machine lookup and gateway-wide wildcard
selection are retired by ordinary membership and externally authorized exact
scope selection. The predecessor stream_session also qualified a causal
`gateway_wg_relay` forwarding lease. That gateway-carrier lease is retired with
the gateway-only relay carrier; candidate relay participant authority is the
separate signed roster. The retained boot/attempt pair identifies the active
subscription only and cannot establish relay or publication authority.
The predecessor's whole realm-list omission removal is replaced by complete
`realm-peers` content within its authenticated scope and per-key publications.
Snapshot container omission itself retains state under the existing publication
rules; it cannot clear another authority scope.

The operation is `config.snapshot`, defined with the other control exchange
constants. Its endpoint aliases the existing confidential `/api/v1/control`
endpoint. HTTPS, Noise and QUIC keep their current confidentiality and trust
requirements. The request tuple is
`[1, subscriber_I, scopes, boot_nonce, attempt_counter, correlation]`.
Each scope has the subscription's existing four-field shape and ordering,
canonical 26-character RealmId text and a nonempty opaque scope bounded to
256 UTF-8 bytes without control characters.
The canonical request ceiling is 8192 bytes. Both nonce and correlation are
nonzero 16-byte strings; attempt is a positive u32 with no wrapping. Callers
retain the active subscription pair and supply a distinct correlation per poll.
No scope wildcard, capability grant, optional unbound session or kind selector
is added. Unknown fields (including a stream-kind selector), unsorted/duplicate
scopes, nonminimal CBOR and trailing input are refused.

The existing BootstrapEnvelope signs the request through signing_input. Its
signer is the subscriber, mandatory recipient is every requested issuer and
nonce equals correlation. The authority checks the requested exact scopes and
active subscription facts against its own state. The response uses the same
operation, response direction, mandatory subscriber recipient and nonce equal
to the pending correlation. Its payload is exactly the existing PublicationSnapshot,
with no second snapshot encoding. The verifier checks carrier trust, every event's
recipient, exact requested scope and declared snapshot channel. A known
stream-owned pair is refused even when it declares the snapshot channel.
An unknown family/kind pair is an extension, not known stream ownership:
after the existing snapshot validator authenticates its issuer, signature,
recipient, scope and validity, it yields UnknownKind without authority or state
changes. Known valid updates in the same ordered snapshot remain available.
An unknown event with a bad signature, wrong scope/recipient or declared stream
channel still refuses the entire poll; correlation checks apply to its carrier.
Complete replacement and per-key version decisions remain in the existing
snapshot validator. Pending requests never reset versions or tombstones.

Independent fixture producers and consumers establish candidate bytes only.
NSD confirmation of the active subscription binding, operation, exact scope
selection and response nonce echo, plus independent real producer vectors,
remains outstanding.

## Required source authority in responses

The response extension is incompatible: every successful registration decision,
including Equal, and every successful authentication requires the canonical byte
string of SignedSourceBinding. Standalone SourceAcceptance is retired with no
old-shape fallback. Operations, existing field encodings, refusal semantics and
confidential carriers are unchanged. See [source authority](source-selection-candidate.md)
for independent enrolled NSD, recipient, realm/scope, assigned profile and full
source Node comparisons and nested signature verification. The enclosing nonce
must equal the pending request id; no payload request-id field is added.
Registration retains all staged enrollment and lifecycle comparisons. Authentication
retains consumer token signature, claims and custody checks and never grants
registration acceptance. NSD N04 adoption and producer review remain outstanding.

## Explicit authentication source selection

AuthenticationRequest is exactly `[1, membership_scope, NodeBinding, "control",
[served_realm, publication_scope]]`. The selector is required, with no default or
old-shape fallback. Realm text is canonical 26-character RealmId; scope uses the
existing nonempty, control-free UTF-8 encoding bounded to 256 bytes. This is an
incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding
encodings and signing domains are unchanged. NSD N04 adoption remains outstanding.

Registration, including pending gateway enrollment and Equal, returns nodes authority
in the accepted registration Network. Recipient and source_node equal the enrolled
identity. The contribution field is the NSD-allocated Node source record in this
scope; it grants no gateway contribution, service resource or M6 admission.

Nodes authentication selects the enrollment Network; egress selects an independently
accepted contribution Network, including home. Consumers retain the exact pending
realm/scope and nonce, compare returned authority against that pair and independently
accepted NSD, recipient, profile and source Node facts, and verify both signatures
and the normal token. Unknown or unauthorized selectors are refused, never replaced
with another binding. Retain each accepted scope independently. Fixture vectors
cover pending registration, Equal and nodes/egress authentication in one Network,
including swapped-scope and swapped-realm refusal.

## M6 service control candidate

The [service control carrier specification](service-control-carrier-candidate.md)
defines `service.control.v1` on the existing confidential control endpoint,
unchanged Message bytes, exact unary pairs, signed zero-byte carrier receipts,
bootstrap/failure correlation, singleton leases and bound signed stream events.
PublicationSubscriptionRequest now has eight elements: the appended
service_control is null or a typed seven-element admitted-session tuple.
Its runtime_id and session_request_id are nonzero M6 IDs on construction,
decoding and authenticated ingress; NSD/Network zero-ID encoding semantics are
unchanged. This is
breaking for existing consumers; the old seven-element request is refused.
Existing scopes, capabilities, public ingress, boot nonce and attempt meanings
remain unchanged. Stream events admit only SnapshotPush, PortCancel and
PortQuery, with pure exact reverse-result comparison. No new publication family,
M6 schema, runtime or admission state is introduced. Current source ownership,
content floors, persistent proposal and lease timing checks remain consumer work.
NSD adoption and independent real producer confirmation remain outstanding.

## R3 local Node naming and legacy registration retirement

R3 enrollment declares `node_local_names.v1` using the public
`account::NODE_LOCAL_NAMES_V1` constant in the existing Enrollment.capabilities
set. Omission does not negotiate a legacy response or fallback. This declares
naming mode only, not service permission or permission to publish DNS.
NSD accepts the declaration through authenticated registration without allocating
or requiring a legacy Node label. Capability encoding and all existing exact
exchange tuples remain unchanged.

| Retired registration value | R3 disposition and retained meaning |
|---|---|
| `domain_base` | No R3 producer, carrier or pinned-value comparison. Retire its per-machine `.node.` root and derived `.svc.`/`.gw.` suffix selection from the R3 reader. The canonical Node name is the existing `node_dns_name(NodeId)` form `<node id>.n.ns.io`, with NodeId derived from the accepted NodeBinding identity, never from a hostname or machine-id prefix. Do not manufacture a replacement domain_base or service/gateway suffix by string substitution. |
| `dns_root` | No R3 registration producer, carrier or pinned-value comparison. The Node zone is the shared `NODE_DNS_ZONE` constant `n.ns.io`, not a remotely selected root. Existing Subnet and public-edge naming retain their own contracts; the Node zone does not replace their suffixes. |
| `network_token` | No R3 registration producer, carrier or pinned-value comparison. NSD's committed Network naming state retains this token internally for existing Subnet suffix consumers; it is not an enrollment identifier or new shared field. Any existing Subnet name remains owned by its own authenticated projection, not inferred from the Node name. |
| `node_name` | No R3 registration producer, carrier or pinned-value comparison. Retire the NSD-allocated immutable compact Node label. Manual nicknames remain local and never published as registration authority; they do not alter the identity-derived canonical Node name. |

RegistrationAcceptance, AuthenticationResponse and InformationResponse carry
none of `domain_base`, `dns_root`, `network_token` or `node_name`. There is no
substitute naming publication or shared legacy-value decoder. An R3 consumer
refuses any response or adapter supplying these values; it must not silently
accept them or compare an old pin. The legacy `dns_config.short_dns_v2`
tuple-bound snapshot supplies no R3 naming authority. Existing exact tuple
validation remains the shared boundary; adapter refusal belongs to consumers.

The staged Node Enrollment produces the capability set; authenticated registration
acceptance must carry the exact same bytes, binding and declared profile.
Consumers compare membership, full binding, capabilities, trusted authority and
source binding before committing. Missing capability or mismatched acceptance
never switches naming mode. After acceptance, `node_dns_name` derives
`<node id>.n.ns.io` from the accepted NodeBinding identity and `NODE_DNS_ZONE`.
Verified NodeRecord identity/name/address comparison remains discovery, not
authorization. M6 `Resource.service_label` remains the sole source of service
labels through the authenticated recipient/Network snapshot. Public domains
remain in authenticated public-edge publication with its existing ownership
checks. `InformationResponse.realm` remains a display hint.

The consumer owns old-pin cutover: at the authenticated R3 commit it removes all
four naming pins and tuple-bound Short DNS authority from active R3 state,
without feeding absent values through the legacy first-wins setter. Pins are
never compared, converted into identity or recovered after restart. Failure
before commit preserves the prior selected profile. Original-profile records
remain isolated and preserved under existing custody rules; no deletion,
deployment or re-enrollment is authorized here. Startup uses accepted binding
and mode. Registration history and lifecycle comparisons remain unchanged.
Retired compact Node names are not promised as aliases. Subnet names, service
labels, public-edge names and authorization retain their existing contracts.

The external R3 runtime consumer owns cutover and its commit/restart regression:
matching acceptance must drop every active old pin and Short DNS authority; mismatched acceptance or supplied legacy values must leave the prior
profile intact. NSD N04/N09 producer adoption and ns S05/S06/S11 consumer/cutover
adoption remain outstanding, including independent producer confirmation.
The review delta is a candidate, never agreement or interoperability evidence.
No new field, carrier, P-item or dependency edge is introduced; previous delivery
evidence does not establish this delta or release external cutover acceptance.
