# Candidate control exchange

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
Text fields are nonempty control-free UTF-8 of at most 256 bytes. Capabilities
reuse Enrollment's sorted unique bounded identifier set. No normalization occurs.

- Membership scope: `[nsd_id_16, network_id_16]`.
- Registration request: `[1, scope, enrollment_bytes, profile, credential_bytes,
  lifecycle_bytes_or_null]`. Credential is opaque, nonempty and at most 16 KiB;
  it is interpreted only by the provisioned authority. No auth-key/OAuth inference
  occurs. Lifecycle is absent for initial enrollment and otherwise reuses Lifecycle.
- Registration acceptance: `[1, scope, enrollment_bytes, profile, decision]`.
  Decision is 0 initial, 1 equal, 2 identity replacement, 3 record rotation.
  Matching compares scope, the entire binding (I/K/version/generation), exact
  capabilities and profile, then recomputes decide_enrollment against the prior
  committed binding, supplied lifecycle and explicit rebind authorization.
  Typed mismatch never commits a new binding; a receipt or token is insufficient.
- Authentication request: `[1, scope, binding, purpose]`; purpose is `control`.
  Signer must equal binding I. No retired WebSocket leg or gateway role is carried.
- Authentication response: `[1, compact_token]`. Token is opaque bounded ASCII;
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
requires `nsd-machine-control` membership in aud. Wrong-audience vectors are
labelled `nsd-audience`; they are not gateway refusals. Whether a later gateway
candidate should require machine audience remains an open owner-review item.
NSD's JWT library expiry leeway is separately 60 seconds; the gateway's 30-second
predicate must not be replaced by it. This package exposes the NSD audience
comparison alone, not an imitation of its complete verifier or external OIDC.

RsaJwk JSON has kty, optional kid/alg/use, n/e; JwkSet has keys in source order.
Unsupported object descriptions are discarded in source order; scalar members,
duplicate key lists and malformed/trailing JSON refuse.
Usable keys require RSA, RS256, nonempty kid/n/e, use absent or `sig`, and strict
base64url unsigned n/e without leading zero. Wrong `enc` use refuses. RFC 7638
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
| `crates/nsgw-control/src/transport/https.rs` | `api::support::ConfigStreamRequest` | PublicationScope and authenticated publication subscription in the existing publication contract; no second session model. |
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
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `api::support::ConfigStreamRequest` | PublicationScope and authenticated publication subscription in the existing publication contract; no second session model. |
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
| `crates/nsgw-control/tests/transport.rs` | `api::support::ConfigStreamRequest` | PublicationScope and authenticated publication subscription in the existing publication contract; no second session model. |
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
