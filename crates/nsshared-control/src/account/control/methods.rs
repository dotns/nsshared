//! Operation names, endpoint paths and stream framing bounds of the control channel.

use crate::account::MAX_BYTES;

/// Confidential authentication configuration request/response operation.
pub const EDGE_AUTH_CONFIG_GET: &str = "edge.auth.config.get";

/// Confidential exact Node L3 application status operation.
pub const NODE_L3_STATUS: &str = "node.l3.status";

/// Confidential certificate and client-CA acquisition operation.
pub const EDGE_MATERIAL_GET: &str = "edge.material.get";

/// Registration operation inside the signed carrier.
pub const MACHINE_REGISTER: &str = "machine.register";
/// Authentication operation inside the signed carrier.
pub const MACHINE_AUTH: &str = "machine.auth";
/// Signed information operation.
pub const INFO_GET: &str = "info.get";
/// Signed process heartbeat operation.
pub const MACHINE_HEARTBEAT: &str = "machine.heartbeat";
/// Signed ordinary Node complete device posture operation.
pub const NODE_POSTURE: &str = "node.posture";
/// Signed ordinary Node heartbeat operation.
pub const NODE_HEARTBEAT: &str = "node.heartbeat";
/// Signed ordinary Node disconnect operation.
pub const MACHINE_DISCONNECT: &str = "machine.disconnect";
/// Signed gateway observation report operation.
pub const GATEWAY_REPORT: &str = "gateway.report";
/// Signed complete local service and Exit floor operation.
pub const GATEWAY_SERVICES_REPORT: &str = "gateway.services_report";
/// Signed immutable usage part operation.
pub const GATEWAY_USAGE_REPORT: &str = "gateway.usage_report";
/// Signed exact material installation status operation.
pub const GATEWAY_MATERIAL_STATUS: &str = "gateway.material_status";
/// Confidential M6 unary operation and signed stream event name.
pub const SERVICE_CONTROL: &str = "service.control.v1";
/// Authenticated publication subscription operation.
pub const CONFIG_STREAM: &str = "config.stream";
/// Confidential authenticated publication stream endpoint.
pub const CONFIG_STREAM_PATH: &str = "/api/v1/config/stream";
/// Publication SSE event containing one complete SourcePublication, never a signed carrier envelope.
pub const CONFIG_PUBLICATION_EVENT: &str = "config-envelope.v1";
/// Query parameter containing the canonical unpadded Base64 signed subscription.
pub const CONFIG_STREAM_REQUEST_PARAM: &str = "request";
/// Inclusive complete decoded SourcePublication ceiling N, independent of framing.
pub const MAX_PUBLICATION_BYTES: usize = MAX_BYTES;
/// Canonical unpadded Base64 length E(N) = 4 * floor(N/3) + remainder + 1
/// for a nonzero remainder, otherwise 4 * floor(N/3): 1,398,102 bytes.
pub const MAX_PUBLICATION_ENCODED_BYTES: usize = 4 * (MAX_PUBLICATION_BYTES / 3)
    + if MAX_PUBLICATION_BYTES.is_multiple_of(3) {
        0
    } else {
        MAX_PUBLICATION_BYTES % 3 + 1
    };
/// Inclusive complete SSE event ceiling: E(N) + event-name length + 19.
/// The 19 bytes are `event: `, `data: ` and three CRLF endings, totaling
/// 1,398,139 bytes; LF is three bytes shorter. Consumers measure each event
/// and terminate on either this bound or the independent decoded bound.
pub const MAX_PUBLICATION_FRAMED_BYTES: usize =
    MAX_PUBLICATION_ENCODED_BYTES + CONFIG_PUBLICATION_EVENT.len() + 19;
/// Independently polled publication snapshot operation.
pub const CONFIG_SNAPSHOT: &str = "config.snapshot";
/// Existing confidential signed operation endpoint for snapshot polls.
pub const CONFIG_SNAPSHOT_PATH: &str = CONTROL_ENVELOPE_PATH;
/// Machine-control token purpose.
pub const MACHINE_AUTH_PURPOSE: &str = "control";
/// Confidential signed operation endpoint.
pub const CONTROL_ENVELOPE_PATH: &str = "/api/v1/control";
/// WebPKI discovery endpoint.
pub const DISCOVERY_PATH: &str = "/api/v1/info";
/// Request Accept selector and response Content-Type for canonical CBOR bootstrap discovery.
pub const DISCOVERY_MEDIA_TYPE: &str = "application/cbor";
/// Confidential machine key-set endpoint.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Confidential Node/route selection operation.
pub const NODE_ROUTE_SELECT: &str = "node.route.select";
/// Confidential exact selection withdrawal operation.
pub const NODE_ROUTE_CLEAR: &str = "node.route.clear";

/// Confidential ordinary Node provider report operation, in both directions.
pub const NODE_SUBNET_REPORT: &str = "node.subnet.report";
