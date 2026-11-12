//! The control channel: bootstrap discovery, signed envelopes and requests, control exchanges and reports, machine tokens, Node route commands, Node L3 status and the M6 service control carrier.

pub(in crate::account) mod bootstrap;
pub(in crate::account) mod envelope;
pub(in crate::account) mod exchange;
pub(in crate::account) mod machine_token;
pub(in crate::account) mod methods;
pub(in crate::account) mod node_l3_status;
pub(in crate::account) mod node_record_report;
pub(in crate::account) mod registration_recovery;
pub(in crate::account) mod reports;
pub(in crate::account) mod route_command;
pub(in crate::account) mod runtime_declaration;
pub(in crate::account) mod service_control;
pub(in crate::account) mod signed_request;

pub use bootstrap::{
    BootstrapDiscovery, BootstrapEndpoint, BootstrapError, ConfidentialCarrier, ControlBoundary,
    EnvelopePins, MAX_BOOTSTRAP_BYTES, MAX_CONTROL_BODY, MAX_CONTROL_HEADERS,
    MAX_CONTROL_NOISE_FRAME, MAX_CONTROL_NOISE_PAYLOAD, MAX_ENCODED_SUBSCRIPTION,
    validate_control_input,
};
pub use envelope::{
    BootstrapEnvelope, CONTROL_CLOCK_SKEW_SECONDS, CONTROL_REPLAY_WINDOW_SECONDS,
    EnvelopeDirection, EnvelopeExpectation,
};
pub use exchange::{
    AuthenticationRequest, AuthenticationResponse, AuthenticationSourceScope, ExchangeError,
    InformationRequest, InformationResponse, MembershipScope, RegistrationAcceptance,
    RegistrationCondition, RegistrationRequest, compare_registration_acceptance,
};
pub use machine_token::{
    JwkSet, KeySetOwner, MACHINE_AUDIENCE, MACHINE_EXPIRY_LEEWAY_SECONDS,
    MACHINE_REFRESH_WINDOW_SECONDS, MachineClaims, MachineTokenHeader, QualifiedKeySet, RsaJwk,
    StoredKeyPins, TokenAudience, TokenError, machine_refresh_needed, qualify_key_set,
    qualify_owned_key_set,
};
pub use methods::{
    CONFIG_PUBLICATION_EVENT, CONFIG_SNAPSHOT, CONFIG_SNAPSHOT_PATH, CONFIG_STREAM,
    CONFIG_STREAM_PATH, CONFIG_STREAM_REQUEST_PARAM, CONTROL_ENVELOPE_PATH, DISCOVERY_MEDIA_TYPE,
    DISCOVERY_PATH, EDGE_AUTH_CONFIG_GET, EDGE_MATERIAL_GET, GATEWAY_MATERIAL_STATUS,
    GATEWAY_REPORT, GATEWAY_SERVICES_REPORT, GATEWAY_USAGE_REPORT, INFO_GET, JWKS_PATH,
    MACHINE_AUTH, MACHINE_AUTH_PURPOSE, MACHINE_DISCONNECT, MACHINE_HEARTBEAT, MACHINE_REGISTER,
    MAX_PUBLICATION_BYTES, MAX_PUBLICATION_ENCODED_BYTES, MAX_PUBLICATION_FRAMED_BYTES,
    NODE_HEARTBEAT, NODE_L3_STATUS, NODE_POSTURE, NODE_RECORD_REPORT, NODE_ROUTE_CLEAR,
    NODE_ROUTE_SELECT, NODE_RUNTIME_DECLARE, NODE_SUBNET_REPORT, SERVICE_CONTROL,
};
pub use node_l3_status::{
    NodeL3Status, NodeL3StatusContext, NodeL3StatusKey, NodeL3StatusRequest, NodeL3StatusResponse,
    node_l3_event_digest,
};
pub use reports::{
    BuildCapabilities, ControlReportOperation, DiskEncryptionStatus, FencedGatewayReportRequest,
    FencedGatewayReportResponse, GATEWAY_RTT_FEATURE, GatewayCertificateObservation, GatewayReport,
    GatewayReportResponse, GatewayRttObservation, GatewayRttTier, HeartbeatRequest,
    HeartbeatResponse, MAX_BUILD_FEATURES, MAX_FEATURE_TOKEN_BYTES,
    MAX_NODE_LIVENESS_REFUSAL_BYTES, MAX_NODE_OBSERVATIONS, MAX_NODE_POSTURE_IP_BYTES,
    MAX_NODE_POSTURE_IPS, MAX_NODE_POSTURE_TEXT_BYTES, MaterialStatusResponse,
    NodeDisconnectRequest, NodeDisconnectResponse, NodeHeartbeatRequest, NodeHeartbeatResponse,
    NodeLivenessOperation, NodeLivenessRefusal, NodeLivenessRefusalCode, NodeLivenessRefusalReason,
    NodePostureRequest, NodePostureResponse, NodePostureSnapshot, NodeReportContext,
    NodeReportError, NodeRuntimeFence, PAIR_TRANSPORT_FALLBACK_FEATURE, PairTransportSnapshot,
    PairTransportUnhealthy, is_feature_token,
};
pub use route_command::{
    CommittedSelection, RouteAction, RouteCommand, RouteDecision, RouteError, RouteOutcome,
    RouteReceipt, RouteResponse, decide_route_command,
};
pub use service_control::{
    PendingRequest, ServiceControlBinding, ServiceControlError, StreamExpectation, UnaryReply,
    validate_reverse_result, validate_stream_event, validate_unary_reply, validate_unary_request,
};
pub use signed_request::{SignedAccountRequest, SignedUrlScope};

pub use registration_recovery::{
    RegistrationRecoveryAttachment, RegistrationRecoveryExpectation, RegistrationRecoveryQuery,
};

pub use runtime_declaration::{
    MAX_RUNTIME_DECLARATION_BYTES, RuntimeDeclarationAccepted, RuntimeDeclarationRequest,
    runtime_declaration_digest,
};

pub use node_record_report::{
    MAX_NODE_RECORD_REPORT_BYTES, NodeRecordReportAccepted, NodeRecordReportRequest,
    node_record_report_digest,
};
