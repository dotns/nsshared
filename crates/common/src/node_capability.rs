//! Versioned capability vocabulary for a unified node.
//!
//! A unified node is registered as the existing connector machine type and
//! selects behavior from the capability tokens it advertises, not from a
//! mutually exclusive machine-type variant. One machine may consume services,
//! publish services, advertise subnet routes, and accept approved subnet
//! routes at the same time.
//!
//! This module is the single owner of the wire tokens. Consumers must resolve
//! them through [`NodeCapability`] rather than re-spelling the strings, so a
//! token can never drift between repositories.
//!
//! # Capabilities are not authority
//!
//! A capability describes what a peer *understands*, never what it is
//! *allowed to do*. An unrecognized token is ignored — [`NodeCapability::parse`]
//! returns `None` and [`recognized_node_capabilities`] drops it — so a node
//! cannot activate a role or authorize a route by inventing a token. Route
//! authority comes only from NSD's approved projection.

use std::collections::BTreeSet;

/// Capability token advertising that a node consumes realm services.
pub const CAPABILITY_NODE_CONSUME_SERVICES_V1: &str = "node.consume-services.v1";

/// Capability token advertising that a node publishes local services.
pub const CAPABILITY_NODE_PUBLISH_SERVICES_V1: &str = "node.publish-services.v1";

/// Capability token advertising that a node reports desired subnet routes.
pub const CAPABILITY_NODE_ADVERTISE_SUBNET_ROUTES_V1: &str = "node.advertise-subnet-routes.v1";

/// Capability token advertising that a node installs approved subnet routes.
pub const CAPABILITY_NODE_ACCEPT_SUBNET_ROUTES_V1: &str = "node.accept-subnet-routes.v1";

/// A recognized unified-node capability.
///
/// Ordering is the declaration order below and is what
/// [`recognized_node_capabilities`] iterates in, so a derived set renders
/// deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeCapability {
    /// The node consumes realm services (routing, DNS, and peer state).
    ConsumeServices,
    /// The node publishes local services into the realm.
    PublishServices,
    /// The node reports desired subnet routes. Reporting is intent only.
    AdvertiseSubnetRoutes,
    /// The node installs subnet routes NSD has approved for it.
    AcceptSubnetRoutes,
}

impl NodeCapability {
    /// Every recognized capability, in wire-stable declaration order.
    pub const ALL: [Self; 4] = [
        Self::ConsumeServices,
        Self::PublishServices,
        Self::AdvertiseSubnetRoutes,
        Self::AcceptSubnetRoutes,
    ];

    /// Wire token for this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConsumeServices => CAPABILITY_NODE_CONSUME_SERVICES_V1,
            Self::PublishServices => CAPABILITY_NODE_PUBLISH_SERVICES_V1,
            Self::AdvertiseSubnetRoutes => CAPABILITY_NODE_ADVERTISE_SUBNET_ROUTES_V1,
            Self::AcceptSubnetRoutes => CAPABILITY_NODE_ACCEPT_SUBNET_ROUTES_V1,
        }
    }

    /// Inverse of [`Self::as_str`].
    ///
    /// Matching is exact: no case folding and no separator tolerance. An
    /// unrecognized token yields `None` and must stay ignorable — it can never
    /// be coerced into a neighbouring capability.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            CAPABILITY_NODE_CONSUME_SERVICES_V1 => Some(Self::ConsumeServices),
            CAPABILITY_NODE_PUBLISH_SERVICES_V1 => Some(Self::PublishServices),
            CAPABILITY_NODE_ADVERTISE_SUBNET_ROUTES_V1 => Some(Self::AdvertiseSubnetRoutes),
            CAPABILITY_NODE_ACCEPT_SUBNET_ROUTES_V1 => Some(Self::AcceptSubnetRoutes),
            _ => None,
        }
    }
}

/// Resolve advertised tokens into the recognized capability set.
///
/// Unknown tokens are dropped rather than surfaced: an old peer ignores a
/// newer capability, and a newer peer cannot be pushed into unintended
/// behavior by an invented token. Duplicates collapse.
pub fn recognized_node_capabilities<I, S>(tokens: I) -> BTreeSet<NodeCapability>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    tokens
        .into_iter()
        .filter_map(|token| NodeCapability::parse(token.as_ref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_tokens_are_pinned() {
        assert_eq!(
            NodeCapability::ALL.map(NodeCapability::as_str),
            [
                "node.consume-services.v1",
                "node.publish-services.v1",
                "node.advertise-subnet-routes.v1",
                "node.accept-subnet-routes.v1",
            ]
        );
    }

    #[test]
    fn parse_round_trips_every_capability() {
        for capability in NodeCapability::ALL {
            assert_eq!(NodeCapability::parse(capability.as_str()), Some(capability));
        }
    }

    #[test]
    fn unknown_tokens_do_not_resolve_to_a_capability() {
        for token in [
            "",
            "node.consume-services",
            "node.consume-services.v2",
            "NODE.CONSUME-SERVICES.V1",
            "node_consume_services_v1",
            "node.route-authority.v1",
        ] {
            assert_eq!(NodeCapability::parse(token), None, "token {token:?}");
        }
    }

    #[test]
    fn recognized_set_ignores_unknown_tokens_and_duplicates() {
        let advertised = [
            "node.accept-subnet-routes.v1",
            "future.capability.v9",
            "node.consume-services.v1",
            "node.consume-services.v1",
        ];

        let resolved = recognized_node_capabilities(advertised);

        assert_eq!(
            resolved.into_iter().collect::<Vec<_>>(),
            vec![
                NodeCapability::ConsumeServices,
                NodeCapability::AcceptSubnetRoutes,
            ]
        );
    }

    #[test]
    fn an_entirely_unknown_advertisement_grants_nothing() {
        assert!(recognized_node_capabilities(["node.route-authority.v1", "admin"]).is_empty());
    }
}
