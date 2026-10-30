# Account inventory

Predecessor and consumer inventory dispositions: how existing gateway, NSD and node
fields, operations and code revisions map to the account contracts. They were part of
the specification documents and are kept here verbatim; the current rules are in
[docs/spec](../spec/README.md).

## Control


### control-exchange-candidate.md: Complete pinned consumer disposition

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

### control-exchange-candidate.md: Producer checklist and outstanding review

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

### control-exchange-candidate.md: Retained predicate sources

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

### control-report-candidate.md: Heartbeat and gateway observations (predecessor sender fields)

| Predecessor sender field | Candidate disposition |
| --- | --- |
| uptime_secs, local_ips, policy_version | HeartbeatRequest; preserve absent counter and empty address list |
| gateway_id, wg_pubkey, wg_endpoint, wg_tunnel_ip | Ordinary accepted Node identity, signed NodeRecord and family 10 ENDPOINTS/RECORD/ACK; no second gateway identity or IPv4-only assigned-address authority |
| wss_endpoint | Retired legacy connector transport; ordinary Node confidential carriers replace it; no listener is inferred |
| legacy_datagram_endpoint, relay_capacity | Old zero-trust datagram relay is retired; retained sender already omits both; independent relay contracts own admission and metering |
| nsgw_version, git_sha | GatewayReport software_version/source_revision, optional exact observations |
| nsc_connections | GatewayReport connections; preserve optional zero and unknown; does not claim a legacy connector listener exists |
| nsn_service_terminate_enabled | GatewayReport terminate_enabled; observed local intent |
| envoy_http_public_port, public_ingress_internal_http_port | GatewayReport public/internal HTTP ports; no public route authorization |
| draining, capabilities, public_ingress_scopes | GatewayReport corresponding observations; grants remain separately authenticated |
| certificate_statuses cert_id/hostnames/issuer/not_after/fingerprint/gateway_ack_generation/last_error_code | Certificate tuple in that order; never installation authority |
| HeartbeatResponse.features | HeartbeatResponse features; unknown strings remain inert data |

### control-report-candidate.md: Services and floor metadata (local floor predecessor fields)

| Local floor predecessor field | Retained candidate meaning |
| --- | --- |
| service_ref, protocol, target_host, target_port, enabled | Supplied unchanged M6 Declaration declaration_key, protocols, backend_host/backend_port and enabled; no address-derived Resource reference |
| service capabilities, policy_labels | Exact per-declaration EdgeServiceMetadata; never policy/grant authority |
| profile_ref, scope, enabled | EdgeExitProfile reference, existing SubnetSelection/Prefix values and local enabled intent |
| Exit capabilities, policy_labels | Exact per-profile metadata; never permission or effective route authority |
| services, exit_profiles | Complete kind 1 floor collections; valid empty withdraws the declared floor |
| accepted_services, accepted_exit_profiles, rejected | Exact correlated outcomes below; rejection reasons retained explicitly |

### control-report-candidate.md: Complete pinned control-report consumer disposition

Inventory: gateway `582c1a4eb8c7ed1fd85f0c17e4fdc7954e00e01e`.
All allocated sender, test, transport and fixture rows are explicit candidate mappings;
this is not deployed equivalence or producer agreement.

| Source path | Item | Candidate disposition |
| --- | --- | --- |
| `crates/nsgw-contract-v1/tests/fixtures/reports/producer/usage-sequence-gap.json` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-contract-v1/tests/fixtures/reports/producer/usage-window-overlap.json` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `api::auth::AuthResponse` | Existing control_exchange authentication and machine_token verifier; no duplicate report credential model |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `api::support` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `claims::machine::MachineClaims` | Existing control_exchange authentication and machine_token verifier; no duplicate report credential model |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `envelope::pins::JwkSet` | Existing machine_token key-set qualification and separate envelope signer pins |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `envelope::pins::RsaJwk` | Existing machine_token key-set qualification and separate envelope signer pins |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `envelope::wrapper::DOMAIN_REQUEST` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `reports::heartbeat::HeartbeatResponse` | control_reports::HeartbeatResponse; exact pending id and inert feature tokens |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `rules::envelope::SignatureInput` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `rules::envelope::build_signature_input` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing machine_token key-set qualification and separate envelope signer pins |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `rules::pins::rsa_jwk_thumbprint` | Existing machine_token key-set qualification and separate envelope signer pins |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `vocabulary::core::MACHINE_AUTH` | Existing control_exchange authentication and machine_token verifier; no duplicate report credential model |
| `crates/nsgw-control/src/client/heartbeat_support.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `api::support` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `reports::heartbeat::HeartbeatRequest` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `reports::heartbeat::HeartbeatResponse` | control_reports::HeartbeatResponse; exact pending id and inert feature tokens |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `vocabulary::core::MACHINE_AUTH` | Existing control_exchange authentication and machine_token verifier; no duplicate report credential model |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/src/client/heartbeat_tests.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/src/client/report_tests.rs` | `api::support` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/report_tests.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/report_tests.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/src/client/report_tests.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/report_tests.rs` | `envelope::wrapper::DOMAIN_RESPONSE` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/report_tests.rs` | `reports::gateway::GatewayCertificateStatus` | control_reports::GatewayCertificateObservation; all nonsecret activation observations |
| `crates/nsgw-control/src/client/report_tests.rs` | `reports::gateway::GatewayReportRequest` | control_reports::GatewayReport and GATEWAY_REPORT; explicit predecessor field dispositions above |
| `crates/nsgw-control/src/client/report_tests.rs` | `reports::gateway::GatewayReportResponse` | control_reports::GatewayReportResponse; exact pending observation id |
| `crates/nsgw-control/src/client/report_tests.rs` | `rules::envelope::SignatureInput` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/report_tests.rs` | `rules::envelope::build_signature_input` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/src/client/report_tests.rs` | `rules::pins::ed25519_pubkey_to_okp_thumbprint` | Existing machine_token key-set qualification and separate envelope signer pins |
| `crates/nsgw-control/src/client/report_tests.rs` | `vocabulary::core::CAPABILITY_GATEWAY_PUBLIC_EDGE_V1` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/src/client/report_tests.rs` | `vocabulary::core::GATEWAY_REPORT` | control_reports::GatewayReport and GATEWAY_REPORT; explicit predecessor field dispositions above |
| `crates/nsgw-control/src/client/report_tests.rs` | `vocabulary::core::PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/src/heartbeat.rs` | `reports::heartbeat::HeartbeatRequest` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/src/heartbeat.rs` | `reports::heartbeat::HeartbeatResponse` | control_reports::HeartbeatResponse; exact pending id and inert feature tokens |
| `crates/nsgw-control/src/heartbeat.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/src/reports.rs` | `reports::gateway::GatewayCertificateStatus` | control_reports::GatewayCertificateObservation; all nonsecret activation observations |
| `crates/nsgw-control/src/reports.rs` | `reports::gateway::GatewayReportRequest` | control_reports::GatewayReport and GATEWAY_REPORT; explicit predecessor field dispositions above |
| `crates/nsgw-control/src/reports.rs` | `reports::gateway::GatewayReportResponse` | control_reports::GatewayReportResponse; exact pending observation id |
| `crates/nsgw-control/src/reports.rs` | `vocabulary::core::GATEWAY_REPORT` | control_reports::GatewayReport and GATEWAY_REPORT; explicit predecessor field dispositions above |
| `crates/nsgw-control/src/services_floor.rs` | `reports::services::GatewayServicesAck` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/src/services_floor.rs` | `reports::services::GatewayServicesReport` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/src/services_floor.rs` | `reports::services::GatewayServicesReportRequest` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/src/services_floor.rs` | `reports::services::GatewayServicesReportResponse` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/src/services_floor.rs` | `vocabulary::core` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/src/services_floor.rs` | `vocabulary::core::GATEWAY_SERVICES_REPORT` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/src/transport/error.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/framing.rs` | `reports::usage::ACCEPTED_THROUGH_SEQ` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/framing.rs` | `reports::usage::REPLAY_DETECTED` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/framing.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/framing.rs` | `reports::usage::usage_watermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/framing.rs` | `vocabulary::core::GATEWAY_USAGE_REPORT` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/https.rs` | `reports::usage::REPLAY_DETECTED` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/transport/noise.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/src/usage.rs` | `reports::usage::GatewayUsageReportRequest` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/usage.rs` | `reports::usage::GatewayUsageReportResponse` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/usage.rs` | `reports::usage::UsageStatus` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/usage.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/usage.rs` | `reports::usage::classify_usage_status` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/src/usage.rs` | `vocabulary::core::GATEWAY_USAGE_REPORT` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/client.rs` | `reports::heartbeat::HeartbeatResponse` | control_reports::HeartbeatResponse; exact pending id and inert feature tokens |
| `crates/nsgw-control/tests/client.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/tests/fixtures/predecessor/heartbeat.hex` | `reports::heartbeat::HeartbeatRequest` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/tests/fixtures/predecessor/report.hex` | `reports::gateway::GatewayReportRequest` | control_reports::GatewayReport and GATEWAY_REPORT; explicit predecessor field dispositions above |
| `crates/nsgw-control/tests/heartbeat.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/tests/heartbeat.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/tests/heartbeat.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/heartbeat.rs` | `vocabulary::transport::DISCOVERY_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/heartbeat.rs` | `vocabulary::transport::JWKS_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `reports::heartbeat::HeartbeatResponse` | control_reports::HeartbeatResponse; exact pending id and inert feature tokens |
| `crates/nsgw-control/tests/heartbeat_rejects_byte_string_acknowledgements.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/tests/noise.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/tests/reports.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/tests/reports.rs` | `vocabulary::core::GATEWAY_REPORT` | control_reports::GatewayReport and GATEWAY_REPORT; explicit predecessor field dispositions above |
| `crates/nsgw-control/tests/reports.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/reports.rs` | `vocabulary::transport::DISCOVERY_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/services_floor.rs` | `api::support` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/tests/services_floor.rs` | `api::support::ExitScope` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/tests/services_floor.rs` | `api::support::from_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/tests/services_floor.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/tests/services_floor.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/tests/services_floor.rs` | `reports::services::GatewayExitProfileDeclaration` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/tests/services_floor.rs` | `reports::services::GatewayServiceDeclaration` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/tests/services_floor.rs` | `reports::services::GatewayServicesAck` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/tests/services_floor.rs` | `reports::services::GatewayServicesReport` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/tests/services_floor.rs` | `vocabulary::core::GATEWAY_SERVICES_REPORT` | Extended EdgeServiceRequest/Response kind 1; exact M6 service bytes, metadata, Exit declarations and per-reference outcomes |
| `crates/nsgw-control/tests/services_floor.rs` | `vocabulary::core::Protocol` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/tests/services_floor.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/services_floor.rs` | `vocabulary::transport::DISCOVERY_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `vocabulary::core::GATEWAY_USAGE_REPORT` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/silent_endpoint_deadline.rs` | `vocabulary::core::MACHINE_HEARTBEAT` | control_reports::HeartbeatRequest and MACHINE_HEARTBEAT; uptime, local addresses and observed policy counter |
| `crates/nsgw-control/tests/usage.rs` | `api::support::to_cbor` | Per-type canonical/decode methods; no generic permissive account codec |
| `crates/nsgw-control/tests/usage.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | Existing BootstrapDiscovery trust version and confidential carrier; no downgrade |
| `crates/nsgw-control/tests/usage.rs` | `envelope::wrapper::ControlEnvelope` | Existing BootstrapEnvelope and sole signing_input API; confidential authenticated report request/response |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::ACCEPTED_THROUGH_SEQ` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::CURRENT_EPOCH` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::GatewayUsageReportRequest` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::GatewayUsageReportResponse` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::REPLAY_DETECTED` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::UsageRow` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `vocabulary::core::GATEWAY_USAGE_REPORT` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage.rs` | `vocabulary::core::INFO_GET` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/tests/usage.rs` | `vocabulary::core::MACHINE_REGISTER` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/tests/usage.rs` | `vocabulary::reports::PathClass` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/tests/usage.rs` | `vocabulary::transport::CONTROL_ENVELOPE_PATH` | Existing control_exchange endpoint constants; report operations all use CONTROL_ENVELOPE_PATH |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | Existing BootstrapDiscovery trust version and confidential carrier; no downgrade |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `reports::usage::ACCEPTED_THROUGH_SEQ` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `reports::usage::GatewayUsageReportRequest` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `reports::usage::REPLAY_DETECTED` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `vocabulary::core::GATEWAY_USAGE_REPORT` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `vocabulary::core::INFO_GET` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/tests/usage_conflict_rejects_non_http_length_whitespace.rs` | `vocabulary::core::MACHINE_REGISTER` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |
| `crates/nsgw-control/tests/usage_heads_ending_in_a_bare_cr_return_framing_errors.rs` | `envelope::bootstrap::CONTROL_TRUST_VERSION` | Existing BootstrapDiscovery trust version and confidential carrier; no downgrade |
| `crates/nsgw-control/tests/usage_heads_ending_in_a_bare_cr_return_framing_errors.rs` | `reports::usage::GatewayUsageReportRequest` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_heads_ending_in_a_bare_cr_return_framing_errors.rs` | `reports::usage::UsageWatermark` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_heads_ending_in_a_bare_cr_return_framing_errors.rs` | `vocabulary::core::GATEWAY_USAGE_REPORT` | Existing UsageReport/UsageAnswer; immutable original profile and exact correlation; conflict/repair never ACK |
| `crates/nsgw-control/tests/usage_heads_ending_in_a_bare_cr_return_framing_errors.rs` | `vocabulary::core::INFO_GET` | Existing confidential BootstrapEnvelope and control_exchange contracts; report payloads selected by exact operation |

### service-control-carrier-candidate.md: Lifecycle reference

The lifecycle reference is repository `ns`,
`docs/plan/20261017-m6-service-contract.md` at
`0e5adc17c9b05ae7fa351de00a5184a57b92e584`, sections 1–6 and 10.
Its historical ControlEnvelope/JSON carrier is replaced by this mapping.

### l8-account-payload-profile.md: M6 service control carrier (family surface table)

| Existing family surface | Candidate delta | External status |
| --- | --- | --- |
| Bootstrap / v1 replacement | Exact M6 unary, receipt and bound signed-event validation | NSD carrier adoption and real producer vectors outstanding |
| Public edge / service integration | Reuses unchanged declaration, snapshot, listener, lease and port messages | Consumer lifecycle and NSD interoperability remain separate |
| Publication subscription | Breaking eight-field tuple with optional exact per-Network M6 session | Producer and consumer adoption required; no old-arity fallback |

## Publication


### control-exchange-candidate.md: Independent publication snapshot poll

| Predecessor | Candidate | Meaning |
|---|---|---|
| GatewayRealmConfigSnapshotRequest.stream_session | boot_nonce, attempt_counter | Required nonzero restart nonce and positive checked u32 logical stream attempt; same caller-supplied identity as the active subscription. No session runtime or scope grant. |
| GatewayRealmConfigSnapshotRequest | PublicationSnapshotRequest | Subscriber plus exact sorted issuer/recipient/served-realm/scope entries, at most 32; every recipient is the subscriber. No predecessor kind selector existed. All snapshot-owned kinds within each entry are requested; stream kinds are never requested. |
| GatewayRealmConfigSnapshotResponse.realms[].realm_id/events | SourcePublication container | Canonical source-bound container `[1, [bstr(SourcePublication), ...]]`, with each entry retaining its full authenticated publication key. Empty snapshots retain state; signed empty event payloads withdraw only their exact key. |

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

### control-exchange-candidate.md: Authenticated publication subscription (predecessor notes)

- Capabilities retain the predecessor's understanding-only meaning and the existing enrollment rule.
- Unlike predecessor bare strings, indices cannot lose realm/issuer qualification.
- The predecessor stream_session becomes two required correlation fields: a nonzero 16-byte boot_nonce and a positive u32 attempt_counter.
- No optional/unbound subscription is retained.

### l8-account-payload-profile.md: Publication snapshot poll request (predecessor notes)

- The predecessor has no kind selector; stream selectors are unknown fields and refused.

## Node and Subnet


### l8-account-payload-profile.md and control-exchange-candidate.md: R3 local Node naming and legacy registration retirement

The table is identical in both sources.

| Retired registration value | R3 disposition and retained meaning |
|---|---|
| `domain_base` | No R3 producer, carrier or pinned-value comparison. Retire its per-machine `.node.` root and derived `.svc.`/`.gw.` suffix selection from the R3 reader. The canonical Node name is the existing `node_dns_name(NodeId)` form `<node id>.n.ns.io`, with NodeId derived from the accepted NodeBinding identity, never from a hostname or machine-id prefix. Do not manufacture a replacement domain_base or service/gateway suffix by string substitution. |
| `dns_root` | No R3 registration producer, carrier or pinned-value comparison. The Node zone is the shared `NODE_DNS_ZONE` constant `n.ns.io`, not a remotely selected root. Existing Subnet and public-edge naming retain their own contracts; the Node zone does not replace their suffixes. |
| `network_token` | No R3 registration producer, carrier or pinned-value comparison. NSD's committed Network naming state retains this token internally for existing Subnet suffix consumers; it is not an enrollment identifier or new shared field. Any existing Subnet name remains owned by its own authenticated projection, not inferred from the Node name. |
| `node_name` | No R3 registration producer, carrier or pinned-value comparison. Retire the NSD-allocated immutable compact Node label. Manual nicknames remain local and never published as registration authority; they do not alter the identity-derived canonical Node name. |

## Realm and grants


### Source: l8-account-payload-profile.md, "Inventory disposition and carrier boundary"


| Inventoried values | Canonical value or disposition | Carrier |
| --- | --- | --- |
| AclPolicy.rules, AclRule.action/subject/dst/proto | SubjectPolicy rules; accept is implicit, deny actions retired | Public-edge fragments embed in EdgeRoute.policy; other aggregate carriers open |
| AclPolicy.groups | Explicit qualified groups and members | EdgeRoute.policy for public-edge groups; other aggregates open |
| AclBindings.wg_peer | NodeL3Authority bindings retain I/K authority; address/key-derived subjects retired | Existing family 11 node-l3 |
| AclBindings.machine | SubjectBinding with explicit Node or credential anchor | Family 7 EdgeAuth.bindings for public-edge credentials; other aggregates open |
| AclPolicy.hosts, tests | Gateway destination alias resolution and self-test inputs remain evaluator-owned; no contract equivalence claimed | Open carrier item |
| AclPolicy.gateway_roster, service_floor | Not subject authority; roster classification and service-floor metadata stay in their existing contracts/local configuration | No policy carrier added |
| AdminClaims, AdminScope, require_admin_scope | AdminTokenClaims, AdminScope, require_scope | Authenticated admin token |
| MachineClaims, TokenAudience, verify_machine_claims | Machine token/key-set contract remains separately owned; no duplicate claims | Existing token owner |
| GatewayAuthConsumer.subject and credential-to-consumer joins | PolicySubject, SubjectBinding; enabled/expiry retained | Embedded family 7 EdgeAuth |
| GatewayAuthJwtConsumerBinding | JwtSubjectBinding plus existing subject binding; credential id is the anchor, consumer resolution belongs to the enclosing family | Embedded family 7 EdgeAuth |
| GatewayAuthJwtAuthority and legacy issuer metadata | Authority reference retained by JwtSubjectBinding; issuer/audience/key source remain family 7 values; no trust inferred | Family 7 EdgeJwtAuthority; NSD producer confirmation pending |
| SignedSubjectHeaderPolicy | Explicit typed header configuration | Embedded family 7 EdgeRoute.headers |
| SignedUrlScope and canonical request/query/string-to-sign | SignedUrlScope deterministic public signing input | Existing SignedUrlScope request input plus realm-qualified auth material reference |
| EnvelopeDirection, signed account requests | SignedAccountRequest reuses BootstrapEnvelope and its domains | Existing authenticated call carrier |
| OIDC claims, organization/role subject projection, provider/cookie configuration | OIDC token verification and label construction remain consumer-owned, referencing qualified PolicySubject | Confidential AuthConfiguration values; OIDC runtime and label construction remain external; NSD confirmation outstanding |
| Policy compilation, VerifiedSubjectSet, verifier readiness and admission results | Consumer state/evaluation, not new wire claims | No carrier added |

No evaluator moves into shared contracts. Existing NodeL3Authority is neither
wrapped nor duplicated. Family 7 owns complete replacement of embedded visitor,
auth and public-edge values. Service targets continue to use existing M6
ServiceRef and grant/Payer contracts rather than a policy-specific service claim.
Diagnostic `policy-version` remains an observation owned separately; it never
carries this policy or establishes an authorization revision. Unplaced inventory
items stay open until an enclosing family or a later design assigns a carrier;
no new kind or implicit policy publication is defined here.

### Source: realm-publication-candidate.md, "Predecessor field mapping"


| Predecessor field | Candidate disposition |
| --- | --- |
| WgConfig.ip_address | Retired gateway device address; NodeId/N6/N4 derive from I |
| WgConfig.listen_port | Retired gateway device port; no membership authority meaning |
| WgConfig.peers | Complete realm contributions with full I, authorized K and signed NodeRecord |
| PeerConfig.public_key | NodeBinding.K, checked against NodeRecord |
| PeerConfig.endpoint | Retired direct gateway carrier endpoint; existing NodeRecord relay discovery applies |
| PeerConfig.allowed_ips | Retired arbitrary device routes; Node addressing derives from I; routing and grants remain separate |
| PeerConfig.persistent_keepalive | Retired gateway device tuning; no membership field |
| GatewayConfig.gateways | Retired gateway-specific endpoint collection; ordinary NodeRecord relay contract applies |
| last_seen_policy | Observation-only policy-version counter under its exact publication key |

## Edge


### Inventory disposition (from docs/l8-public-edge-candidate.md)

| Existing surface | Candidate field, reused definition or disposition |
|---|---|
| routing RouteEntry/RoutingConfig, dns DnsRecord/DnsConfig | EdgeRealm.routes; id/name/aliases/domains, ServiceRef, backend, virtual_port, protocol; service DNS labels resolved from snapshot Resource |
| ServiceBackendKind/PublicEdgeBackendKind::NsnBacked | Full Node backend identity; address-derived identity retired because addresses cannot establish publisher authority |
| GatewayEgress/GatewayExit backend variants, capture routes | Existing grant/Subnet families, not public-edge backend authority; no public exposure inferred |
| GatewayHttpConfig/GatewayHttpRoute, GatewayL4Map/GatewayL4Route | EdgeRealm/routes; HTTP/TCP/UDP/public_port; per-realm complete replacement |
| PublicEdgeRouteIdentity/AclRef/PolicyRevision | Route id, ServiceRef, SubjectPolicy, signed publication version; gateway/internal listener ids stay consumer-local; rollback metadata cannot override monotonic signed version |
| PublicEdgeTransportPolicy and upstream TLS policy | EdgeRouteOptions.transport/upstream_authority/upstream_tls, with explicit TLS trust choice; no implicit fallback |
| HttpExternalIdentityImport/ExternalIdentityProviderRef/Kind, GatewayAuthProvider/Kind/OrganizationMode | [AuthConfiguration](../spec/account/edge.md): complete provider/import, cookie, redirect, template and organization values on confidential authenticated control transport; NSD confirmation outstanding |
| HttpMiddlewarePolicy/SourceIpAdmissionPolicy, EdgeLimitPolicy/HttpTransformPolicy/EdgeAuditPolicy/L4Policy | EdgeRouteOptions explicit policy references, body bounds, source_ip and audit_metadata; referenced policy implementations remain consumer-owned |
| SignedSubjectHeaderPolicy, AclPolicy rules/groups | Exact reused SignedSubjectHeaderPolicy and SubjectPolicy bytes |
| GatewayAuthConsumer, credential-to-consumer joins | Exact SubjectBinding; display names are presentation only |
| GatewayAuthJwtConsumerBinding/JwtAuthority/JwtKeySource/JwtIssuer | JwtSubjectBinding plus EdgeJwtAuthority issuer/audiences/auth key reference; actual key acquisition and trust qualification remain external |
| GatewayAuthConfig/Generation and Credentials (API key, Basic, signed URL, mTLS, webhook), SecretSet/SecretVersion | AuthConfigRequest/Response and AuthConfiguration supply exact realm/reference/generation and actual secret/verifier values confidentially; existing bindings reused; unsupported webhook reservation retired explicitly |
| rules::signed_url and its constants/helpers | Existing SignedUrlScope canonical_request/signing_input, no second canonicalization |
| CertificateRef/Source/Policy/ChallengePreference, CertificateBundle | Certificate material reference/generation; private key bytes are excluded; fetch/ACME/source configuration remains owned by the material consumer, not identity authority |
| ClientCaBundle/ClientCaDependency, AuthDependency/CertificateDependency | Client-CA/auth/certificate references and exact generation joins plus correlated EdgeMaterialAck |
| GatewayServiceDeclaration/ServicesReport/Request/Response/Ack | EdgeServiceRequest/Response; unchanged M6 objects, complete floor metadata and exact per-kind reference outcomes with explicit reasons |
| GatewayExitProfileDeclaration | EdgeServiceRequest kind 1 exit_profiles reuse SubnetSelection/Prefix semantics as declarations, never Subnet route authority |
| service_fqdn and standalone service-label inputs | Resolve Resource.service_label via M6 ServiceRef. Independent label-input coverage through recipient-qualified Snapshot::canonical/decode uses `crates/nsshared-control/tests/vectors/service/labels.json`: 63-byte acceptance, 64-byte refusal, non-ASCII, dot, underscore and embedded-space refusals. Original snapshot bytes/digests and existing label cases are preserved. Resource.service_label remains a String field; standalone API agreement/operation and NSD producer evidence remain open under M01/M02 with the M6 contract owner. |

### Predecessor field disposition (from docs/confidential-auth-candidate.md)

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

## Relay and usage


### Usage fixture migration (from docs/usage-contract-candidate.md, "Independent consumers and migration")

The older account usage fixtures migrate from a 32-byte identity subject to a
16-byte ULID subject, with version and tuple arity unchanged. The review request
records the incompatible predecessor.

### Participant authority and profile publications

The sources docs/participant-authority-candidate.md, docs/profile-publications-candidate.md
and the folded sections of docs/l8-account-payload-profile.md contain no predecessor
or consumer inventory disposition table.

## Current candidate additions and release inventory

This inventory describes candidate source, not a selected released contract.
Final release revision and cohort are **unset**. The earlier import migration and
adoption records remain bounded to their named revisions; they do not establish
consumer adoption of the following additions.

| Delivered candidate surface | Exported API and compatibility | Existing independent fixtures | Exact adoption disposition |
| --- | --- | --- | --- |
| M6 whole floor | `nsshared_control::service::{FloorContent, FloorMetadata, FloorExitProfile, ExitSelection, FloorReportReplace, FloorReportMessage}`; also exported by `nsshared_service_control`. `Message::with_floor` uses the existing `report.replace` carrier. Empty metadata/profiles preserve legacy report bytes and digest. Nonempty `floor_version = 1` content requires floor-aware decoding and a complete-content digest; legacy decoders refuse it. | `crates/nsshared-control/tests/vectors/service/floor.json`; legacy `service/canonical.json` under the same vector root remains a separate compatibility fixture. | Shared contracts and fixture behavior delivered. Gateway complete-floor production/pending retries and NSD complete-floor decoding, persisted custody and replacement comparisons remain consumer obligations; the historical service-control corpus match does not prove these additions. |
| Independent roster counters | `nsshared_control::account::relay::{Roster, RosterVersion, SignedRoster, ParticipantRosterGeneration, verify_participant_roster}`. `Roster.version` is publication anti-replay; `attribution_epoch` is historical billing attribution. Schema 1 preserves original bytes/signatures with epoch = version; schema 2 carries independent positive counters. | `crates/nsshared-control/tests/vectors/account/relay/participant-roster.vec` includes signed schema migration and independent-counter cases. `relay/session.vec` and `usage/reports.vec` retain existing usage carriers; `relay/admission-snapshot.vec` covers the separate local snapshot. | Shared contract delivered. NSD must derive epochs from committed classified history; relayd must persist both floors atomically and capture authenticated epochs at DATA acceptance. Existing roster/directory adoption does not establish these changes or live billing/history qualification. |

### Remaining candidate-vector and service-label work

The current vector root is `crates/nsshared-control/tests/vectors/`; the old
`crates/nsshared-service-control/tests/` locator is absent in this tree.
Existing M6 cases are `service/canonical.json` and `service/floor.json`.
They exercise enclosed objects and complete reports;
standalone `Resource::service_label` API agreement and independent label-boundary
coverage remain open under M01/M02. Display names and declaration keys never
supply service labels.

### Exact candidate case index

Q22 remains open. This is a bounded index of existing **fixture** evidence,
not an assertion that any family has every requested case. Locators below are
`file#name` relative to `crates/nsshared-control/tests/vectors/`; names select
literal `name =` records. A missing cell names the shared coverage still needed.
Typed empty content, removal, absent delivery and malformed emptiness are distinct.

| Family | Positive | Empty / removal | Refusal | Scope | Limit |
| --- | --- | --- | --- | --- | --- |
| 1 enrollment | `account/node/enrollment.vec#enrollment-accepted`; `account/control/exchange.vec#information` | `account/node/enrollment.vec#enrollment-empty-capabilities` (capabilities only); no dedicated own-node publication withdrawal case indexed (shared fixture gap) | `account/node/enrollment.vec#enrollment-unauthorized-rebind`; `account/control/exchange.vec#authentication-missing-selector` | `account/control/exchange.vec#accept-scope`, `account/control/exchange.vec#authentication-whitespace-scope` | `account/node/enrollment.vec#enrollment-capability-boundary`, `account/node/enrollment.vec#enrollment-too-many-capabilities`; `account/control/exchange.vec#authentication-scope-bound`, `account/control/exchange.vec#authentication-long-scope` |
| 2 realms-peers | `account/realm/peers.vec#two-realms` | `account/realm/peers.vec#empty`, `account/realm/peers.vec#served-empty-realm`, `account/realm/peers.vec#remove-omitted` | `account/realm/peers.vec#wrong-binding`, `account/realm/peers.vec#record-signature` | `account/realm/peers.vec#wrong-scope`, `account/realm/peers.vec#wrong-recipient` | `account/realm/peers.vec#long-realm-name`, `account/realm/peers.vec#oversized-realms`, `account/realm/peers.vec#oversized-members` (no paired at-limit collection case indexed) |
| 3 egress | `account/grants/grant-authority.vec#egress`, `account/grants/grant-authority.vec#protocol-renewed` | `account/grants/grant-authority.vec#egress-empty` | `account/grants/grant-authority.vec#3-missing-payer`, `account/grants/grant-authority.vec#unknown-protocol` | `account/grants/grant-authority.vec#3-cross-realm-payer`, `account/grants/grant-authority.vec#wrong-provider` | No dedicated grant collection at/over-limit pair in this file; shared owner must add it |
| 4 exit-subnet | `account/subnet/selection.vec#subnet-explicit`; `account/subnet/views.vec#provider-p`; `account/subnet/mapping.vec#populated` | `account/subnet/selection.vec#subnet-empty-withdrawal`; `account/subnet/views.vec#client-empty`; `account/subnet/mapping.vec#typed-empty` | `account/subnet/selection.vec#subnet-misaligned-prefix`; `account/subnet/mapping.vec#duplicate-id` | `account/subnet/views.vec#wrong-source`, `account/subnet/views.vec#wrong-membership-network`; `account/subnet/mapping.vec#wrong-network` | `account/subnet/selection.vec#subnet-prefix-count-boundary`, `account/subnet/selection.vec#subnet-prefix-count-limit`, `account/subnet/selection.vec#subnet-route-count-boundary`, `account/subnet/selection.vec#subnet-route-count-limit`; `account/subnet/mapping.vec#too-many` |
| 5 payer | `account/grants/grant-authority.vec#payer`, `account/grants/grant-authority.vec#protocol-payers` | `account/grants/grant-authority.vec#payer-empty` | `account/grants/grant-authority.vec#payer-missing-payer`, `account/grants/grant-authority.vec#payer-ambiguous-payer` | `account/grants/grant-authority.vec#payer-cross-realm-payer` | Cardinality refusal is indexed; no dedicated binding collection at/over-limit pair; shared owner must add it |
| 6 withdrawal | `account/grants/grant-authority.vec#initial-authority`, `account/grants/grant-authority.vec#selective-withdrawal`, `account/grants/grant-authority.vec#fresh-regrant` | `account/grants/grant-authority.vec#authority-empty` | `account/grants/grant-authority.vec#retired-regrant`, `account/grants/grant-authority.vec#withdrawal-truncated` | No dedicated ResourceAuthority wrong-scope fixture here (shared fixture gap); common signed-carrier scope checks are indexed below | No dedicated active/retired collection at/over-limit pair in this file; shared owner must add it |
| 7 public-edge | `account/edge/routing.vec#complete`; `account/edge/auth.vec#configuration`; `account/edge/material-request.vec#certificate-request` | `account/edge/routing.vec#empty`, `account/edge/routing.vec#remove-omitted`; `account/edge/auth.vec#complete-empty` | `account/edge/routing.vec#bad-backend`; `account/edge/anonymous.vec#anonymous-not-admin`; `account/edge/material-request.vec#certificate-null-values` | `account/edge/routing.vec#two-networks`, `account/edge/routing.vec#wrong-signed-scope`; `account/edge/auth.vec#wrong-recipient` | `account/edge/routing.vec#too-many-realms`; `account/edge/auth.vec#maximum-secret`, `account/edge/auth.vec#oversized-secret`; `account/edge/floor-text.vec#byte-limit-request`, `account/edge/floor-text.vec#metadata-reference-too-long` |
| 8 relay | `account/relay/participant-roster.vec#participant-roster-accepted`; `account/relay/session.vec#enrolled`, `account/relay/session.vec#binding-ab` | `account/relay/participant-roster.vec#participant-roster-complete-empty`; `account/relay/session.vec#binding-empty`; `account/relay/admission-snapshot.vec#complete-empty` | `account/relay/participant-roster.vec#participant-roster-bad-signature`, `account/relay/participant-roster.vec#participant-roster-epoch-decrease`; `account/relay/session.vec#revoked-authenticate` | `account/relay/participant-roster.vec#participant-roster-wrong-recipient`; `account/relay/session.vec#binding-wrong-issuer` | `account/relay/participant-roster.vec#participant-roster-minimum-lifetime`, `account/relay/participant-roster.vec#participant-roster-short-lifetime`; `account/relay/session.vec#frame-over-bound`; no roster entry-count at/over-limit pair indexed |
| 9 usage | `account/usage/catalog.vec#usage-complete`; `account/usage/reports.vec#service-report`, `account/usage/reports.vec#relay-report` | `account/usage/catalog.vec#withdraw-usage` (empty publication withdraws); `account/usage/catalog.vec#usage-empty` refuses an empty inner profile list; `account/usage/retention.vec#empty` | `account/usage/reports.vec#report-bad-digest`, `account/usage/reports.vec#report-wrong-profile`; `account/usage/retention.vec#duplicate-key-other-digest` | `account/usage/catalog.vec#wrong-reporter-context`; `account/usage/reports.vec#same-user-other-realm` | `account/usage/catalog.vec#usage-complete` (two profiles), `account/usage/catalog.vec#usage-too-many`; `account/usage/retention.vec#collection-bound` |
| 10 node-control | `account/usage/catalog.vec#control-complete`, `account/usage/catalog.vec#install-control` | `account/usage/catalog.vec#control-empty` refuses an empty inner capability list; no dedicated control-profile empty publication case here (shared fixture gap) | `account/usage/catalog.vec#control-vocabulary`, `account/usage/catalog.vec#malformed-control-replacement` | `account/usage/catalog.vec#different-membership-context` | `account/usage/catalog.vec#control-complete` (five capabilities), `account/usage/catalog.vec#control-too-many`, `account/usage/catalog.vec#control-overflow` |
| 11 v1-replacement | `account/control/node-l3-status.vec#applied`; `account/control/node-l3-route-admission.vec#selected-6` | `account/control/node-l3-status.vec#empty-withdrawal` | `account/control/node-l3-status.vec#same-version-different-digest`, `account/control/node-l3-status.vec#failure-status-for-data` | `account/control/node-l3-status.vec#replaced-source`, `account/control/node-l3-status.vec#policy-recipient` | `account/control/node-l3-status.vec#long-reason` (no paired at-limit reason case indexed) |

Common signed-publication coverage is indexed once, not counted as dedicated
payload coverage for each family: `account/publication/envelope.vec` cases
`publication-complete`, `publication-empty`, `publication-absent`,
`publication-fetch-failed`, `publication-wrong-domain`, `publication-wrong-scope`,
`publication-exact-limit`, `publication-over-limit` and
`publication-snapshot-atomic-invalid`. Delivery framing has
`account/publication/delivery.vec#lf-at-decoded-ceiling` and
`account/publication/delivery.vec#lf-over-decoded-ceiling`. These do not establish
payload collection boundaries or production source retirement for all families.

### Export, specification and missing-evidence reconciliation

Export namespaces below are under `nsshared_control::account`, except M6 under
`nsshared_control::service`. Existing specifications describe the APIs; this index
adds no interface or authority producer. Shared missing pairs above are candidate
fixture work. External gaps below are separate even when shared cases exist.
The [handoff evidence](account-handoff.md#unresolved-producer-consumer-and-review-obligations)
retains exact external repository revisions, corpus paths and reader names.

| Family | Existing export / specification | Missing producer / consumer evidence and owner |
| --- | --- | --- |
| 1 | `node` lifecycle and `control::{RegistrationRequest, RegistrationAcceptance, InformationResponse}`; [Node](../spec/account/node.md), [Control](../spec/account/control.md) | NSD owns remaining independent information/discovery accepted/refused producer vectors before H03; current matching enrollment bytes and live transition confirmation remain open. Bounded Q07/Q11 answers do not fill them. |
| 2 | `realm` peers and membership; [Realm](../spec/account/realm.md), [Publication](../spec/account/publication.md) | NSD owns complete collection-authority/refusal/limit producer corpus and review; ns owns live replacement and source-retirement confirmation. Named matched publication copies cover only their recorded cases. |
| 3 | `grants::{ServiceGrant, GrantPublication}`; [Grants](../spec/account/grants.md) | NSD owns complete independent canonical/refusal grant corpus, including protocol/deadline joins; ns/gateway own consumption of that actual corpus and live enforcement. Decoded storage assertions are not exported bytes. Q13 remains open. |
| 4 | `subnet::{SubnetPublication, SubnetSelection}` and provider mapping/report APIs; [Subnet](../spec/account/subnet.md) | NSD owns separate signed `provider-mappings` production/source handoff and independent changed/empty/refused bytes; ns owns authenticated inventory installation. Existing grant/route corpus does not substitute. Default/nested Exit live confirmation stays open. |
| 5 | `grants::{Payer, PayerBindings}`; [Grants](../spec/account/grants.md) | NSD owns complete independent payer assignment/cardinality/refusal bytes; consumers own exact corpus joins to grants and live payer custody. Q15 remains open. |
| 6 | `grants::ResourceAuthority` and successor validation; [Grants](../spec/account/grants.md) | NSD owns complete independent selective withdrawal/retirement/fresh-regrant bytes; consumers own matching history preservation and live denial after retirement. Q16 remains open. |
| 7 | `edge::{PublicEdge, AuthConfiguration}` and material acquisition; [Edge](../spec/account/edge.md), [Realm](../spec/account/realm.md) | NSD owns material/auth canonical/refusal corpus, authenticated admin scope projection and complete subject/JWT/signed-URL/header producer vectors. Existing `edge.json` still lacks a demonstrated matching downstream reader. Gateway owns actual policy/name/material enforcement; Q17 and machine audience remain unresolved. |
| 8 | `relay::{Roster, SignedRoster, verify_participant_roster}` and signed directory/participant contracts; [Relay](../spec/account/relay.md) | NSD owns committed attribution-epoch production and complete unsettled-reference sealing; relayd owns atomic persisted counter floors, current schema-3 controlled local writer/replacement and rollback/carrier-switch proof. The matched directory corpus does not close roster production/consumer or billing qualification. |
| 9 | `usage::{UsageProfilePublication, UsageReport}` and retention contracts; [Usage](../spec/account/usage.md) | NSD owns ledger producer/unit/history evidence and seal completeness; ns/gateway own demonstrated matching `profiles.json`/`ledger.json` readers, completed-I/O capture and custody. Shared supplied quantities cannot prove capture. Q19 remains open. |
| 10 | `usage::NodeControlProfilePublication`; [Usage](../spec/account/usage.md), [Control](../spec/account/control.md) | ns/gateway own matching profile-corpus consumption; NSD/ns own standalone transport agreement and Q20 answer. The catalogue describes capabilities; opaque `node.control` has no runtime semantics or newly assigned producer here. |
| 11 | `control::{NodeL3StatusRequest, node_l3_event_digest}`; [Control](../spec/account/control.md) | NSD/ns own live issuance-to-enforcement-to-Applied association and complete-empty removal. The named matching status corpus proves recorded bytes only. Policy observation is not installation or traffic authority. |

### Q23 M6 composition index

The [account profile](../spec/account/profile.md#placement-and-m6-reuse) names
existing `ServiceRef`, declaration/report, listener, snapshot and message exports.
The additional reuse groups remain those of the registry: enrollment uses
declarations; realms-peers, payer, withdrawal and relay use snapshots;
egress, public-edge and v1-replacement use declarations/listeners/snapshots;
exit-subnet uses listeners/snapshots; usage and node-control add none. Common
identity/message/vector reuse is unchanged. Registry placement cases are
`account/publication/envelope.vec` records `publication-owner-egress-grants`,
`publication-misplaced-egress-grants`, `publication-owner-node-control-profile`
and `publication-misplaced-node-control-profile`; they validate placement,
not every composition variant. Use the current control-crate fixtures directly:

| Surface | Exact existing locator | Remaining confirmation |
| --- | --- | --- |
| Declaration/report and listener bytes/domains | `service/canonical.json` keys `report_cbor`, `report_sha256`, `listener_cbor`, `listener_sha256` | NSD/ns owners must confirm every applicable family composition; these fields do not cover every body variant. |
| Populated and complete-empty snapshot | `service/canonical.json` keys `snapshot_nonempty_cbor`, `snapshot_nonempty_sha256`, `snapshot_empty_cbor`, `snapshot_empty_sha256` | M01 standalone `Resource::service_label` API agreement and M02 independent label boundaries remain open; enclosed labels do not close them. |
| Account unary, lease, reverse and subscription | `account/control/service-control.vec#report.replace-4`, `account/control/service-control.vec#lease-empty-receipt-4`, `account/control/service-control.vec#reverse-port.cancel-4`, `account/control/service-control.vec#wrong-network-reply`, `account/control/service-control.vec#oversized-envelope`; `account/publication/subscription.vec#bound-network-4` | Existing two-Network cases do not establish all type/variant/domain compositions or live sessions, contributions, proposals and leases. Q23 remains external owner confirmation. |
| Complete-floor extension | `service/floor.json` keys `floor_cbor`, `floor_sha256`, `message_cbor`, `invalid.default_exit`, `invalid.oversize_cidrs`, `signed.accepted`, `signed.legacy_digest`, `signed.stale_runtime`, `signed.wrong_nonce`; [whole-floor contract](../spec/m6-floor.md) | Gateway complete pending bytes and NSD complete digest/current-custody comparisons need actual adoption evidence. Legacy digest compatibility does not establish extension adoption. |

Policy/auth completeness, producer-owned vectors and missing downstream corpus
readers remain separate gaps. Q23 still requires owner confirmation of M6 types,
variants and domains; Q24, Q22 and M01/M02 remain open. Bounded Q07/Q11 answers
and the settled Q18 design do not close them. See the
[exact consumer dispositions](account-handoff.md#unresolved-producer-consumer-and-review-obligations).
Review approval, matched consumer readers, live qualification, retention-seal
acceptance and F04 integration remain outstanding. `unstable-account` remains
required. Production eligibility still requires H03/R01/R02/C01b and C18
re-verification; deletion stays held under Q-RET. No tag, release cohort or final
immutable release revision is selected here.
