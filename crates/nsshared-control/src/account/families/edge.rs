//! Family 7: public-edge routes, service declarations, edge material, confidential authentication configuration and certificate material.

pub(in crate::account) mod auth;
pub(in crate::account) mod certificate;
pub(in crate::account) mod declaration;
pub(in crate::account) mod material;
pub(in crate::account) mod routing;

pub use auth::{
    AuthConfigError, AuthConfigRequest, AuthConfigResponse, AuthConfiguration, AuthConsumer,
    AuthCredential, AuthImportMethod, AuthJwtConsumer, AuthKeySource, AuthKeySourceKind,
    AuthMethodKind, AuthOrganizationMode, AuthProvider, AuthProviderKind, AuthRouteImport,
    AuthSecretSet, AuthSecretVersion, AuthVerifier,
};
pub use certificate::{
    EdgeMaterialError, EdgeMaterialRequest, EdgeMaterialResponse, EdgeMaterialValues,
};
pub use declaration::{
    EdgeExitProfile, EdgeFloorOutcomes, EdgeFloorRejection, EdgeServiceAckError, EdgeServiceBody,
    EdgeServiceMetadata, EdgeServiceRequest, EdgeServiceResponse,
};
pub use material::{
    EdgeAuth, EdgeJwtAuthority, EdgeMaterialAck, EdgeMaterialKind, EdgeMaterialRef, MAX_EDGE_ITEMS,
};
pub use routing::{
    EdgeProtocol, EdgeRealm, EdgeRoute, EdgeRouteOptions, EdgeSourceIp, EdgeTransport,
    EdgeUpstreamTls, PublicEdge,
};
