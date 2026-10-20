# Candidate control report exchanges

These pure candidate values use the existing confidential BootstrapDiscovery
carrier and BootstrapEnvelope request/response domains. All five operations use
CONTROL_ENVELOPE_PATH. Operation names are defined only in control_exchange:
`machine.heartbeat`, `gateway.report`, `gateway.services_report`,
`gateway.usage_report`, `gateway.material_status`. Unknown operations refuse.
The report decoder verifies EnvelopeExpectation before decoding and checks direction
and operation. Signers/recipients are the accepted Node and pinned authority;
no payload supplies registration authority. Signing uses BootstrapEnvelope.signing_input.

All tuples use schema 1, shortest definite CBOR, no trailing bytes and the existing
1 MiB account ceiling. Every list below has at most 256 entries, checked before
allocation. Text is nonempty control-free UTF-8 of at most 256 bytes, except that
policy-label values may be empty and contain spaces. No normalization occurs.
Sets are strictly ordered; decoding never sorts or deduplicates them.

## Heartbeat and gateway observations

HeartbeatRequest = `[1, request_id_16, uptime_seconds, local_ips, policy_version_or_null]`.
Addresses are IP literal strings, in supplied order. Empty explicitly reports no
addresses. Uptime is process uptime, not wall time. Policy version is the last
observed authenticated diagnostic counter, not applied policy or authority.
HeartbeatResponse = `[1, request_id_16, features]`. Feature tokens are preserved,
including unknown tokens; they grant no authority. Features are ordered unique tokens.
GatewayReport = `[1, request_id_16, software_version_or_null, source_revision_or_null,
connections_or_null, terminate_enabled_or_null, public_http_port_or_null,
internal_http_port_or_null, draining, capabilities, public_ingress_scopes, certificates]`.
Ports are 1..65535. Connections are u32; absent means unknown, distinct from zero.
The terminate flag records local service intent, never permission.
Capabilities reuse enrollment's bounded identifier set; scopes use ordered token sets.
Certificate = `[id, hostnames, issuer, not_after_seconds, fingerprint,
ack_generation_or_null, last_error_or_null]`. Hostnames are ordered unique text;
generation, when present, is positive. These nonsecret activation observations do
not replace exact material-installation correlation. Fingerprints/issuer are opaque
observations, not new trust pins. GatewayReportResponse = `[1, request_id_16]`.
The gateway mints a unique request id per observation; responses compare it against
the exact pending request after envelope verification. Receipt means receipt only.

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

## Services and floor metadata

Complete the existing EdgeServiceRequest/Response, retaining body kinds 0 declaration,
1 report and 2 listener. Kinds 0 and 2 keep their exact existing bytes.
Kind 1 request becomes `[1, request_id, publisher, nsd_id, network_id, revision,
1, exact_M6_ReportContent_bytes, metadata, exit_profiles, digest]`.
M6 service declarations and their serializer are unchanged. Metadata contains exactly
one `[declaration_key, capabilities, policy_labels]` per submitted M6 declaration,
in declaration-key order, including empty metadata. Labels are ordered unique
`[key, value]` pairs. They remain local floor metadata, never grants or policy.
Exit profiles are ordered by reference and encoded as
`[profile_ref, selection, enabled, capabilities, policy_labels]`.
Selection reuses SubnetSelection semantics: `[0]` default route or `[1, cidrs]`
explicit SubnetPrefix tuples, strictly ordered by family/address/length, no overlaps;
empty explicit selection selects none. Profiles are declarations, not SubnetPublication
route authority. No provider/client binding or enabled permission is inferred.
The kind 1 digest is domain_digest("ns.account.service-floor.v1", canonical
`[M6_report_bytes, metadata, exit_profiles]`), committing the entire submitted floor.
The M6 report's own canonical bytes/digest API remains unchanged.

| Local floor predecessor field | Retained candidate meaning |
| --- | --- |
| service_ref, protocol, target_host, target_port, enabled | Supplied unchanged M6 Declaration declaration_key, protocols, backend_host/backend_port and enabled; no address-derived Resource reference |
| service capabilities, policy_labels | Exact per-declaration EdgeServiceMetadata; never policy/grant authority |
| profile_ref, scope, enabled | EdgeExitProfile reference, existing SubnetSelection/Prefix values and local enabled intent |
| Exit capabilities, policy_labels | Exact per-profile metadata; never permission or effective route authority |
| services, exit_profiles | Complete kind 1 floor collections; valid empty withdraws the declared floor |
| accepted_services, accepted_exit_profiles, rejected | Exact correlated outcomes below; rejection reasons retained explicitly |

Kind 1 response retains the existing first eight fields, including that exact digest;
its last field becomes `[accepted_services, accepted_exit_profiles, rejected]`.
Accepted sets are ordered unique reference strings. Rejections are ordered unique
`[kind, reference, reason]`, kind 0 service or 1 Exit, with a nonempty bounded reason.
Each submitted reference has exactly one outcome of its own kind. Unknown, duplicate,
contradictory and missing outcomes are typed refusals; the response never acknowledges
an unsubmitted reference. A matching explicit rejection remains a refusal of that
reference, with its reason preserved. Empty floor requires empty outcomes.
Kinds 0 and 2 retain the existing whole-content accepted/rejected status.
Acceptance records submitted content only, never listener readiness or route authority.

## Usage and material correlation

Usage requests and answers reuse exact UsageReport/UsageAnswer bytes and the original
immutable reporter/incarnation/profile/sequence/part/digest domain. UnknownMapping is
valid only for relay reports. A service answer carrying it fails validate_for and
is never an acknowledgement, even if every other correlation field matches.

Material status requests reuse exact EdgeMaterialAck bytes unchanged. For auth
configuration the gateway copies the request id from its exact pending confidential
auth configuration request. That separate request/response and private configuration
payload are owned by the confidential auth configuration contract, not defined here.
For certificates and client CA the gateway mints its own unique report request id
and retains the exact report. In both cases correlation includes request id,
served_realm, scope, contributing realm, material kind/reference/generation, and status.
No identifier or generation is inferred from a certificate observation or current state.
Installed is reported only after actual installation of that exact reference and
generation; a receipt cannot synthesize installation. Rejection remains explicit.
MaterialStatusResponse = `[1, exact_EdgeMaterialAck_bytes]`; the authority echoes the
exact accepted report. validate_for compares the full pending report, including status.
A rejection receipt is not successful installation. Existing validate_installation
compares the retained request id, full material and all realm/scope fields and requires
installed. Authentication and actual effect remain caller responsibilities.

## Candidate review

This explicitly changes only kind 1 service request/response bytes in the earlier
public-edge candidate; all other public-edge, auth, material, declaration and listener
bytes remain unchanged. The Python producer and Rust control_report_contract_vectors
consumer precede pure codecs. This is fixture-produced candidate evidence. NSD
producer confirmation and independent producer-owned vectors remain outstanding.

## Complete pinned control-report consumer disposition

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
