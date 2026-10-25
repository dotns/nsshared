//! Owning-family payload decoding of publication events; the generic envelope never
//! interprets payload bytes.

use crate::{
    account::publication::envelope::PublicationError,
    account::publication::envelope::PublicationEvent,
};
use nsshared_identity::keys::IdentityKey;
use nsshared_identity::realm::RealmId;

impl PublicationEvent<'_> {
    /// Maps nonempty profile kinds to their owning typed catalogue.
    /// Empty payloads and other kinds return None; decoding establishes no authority.
    /// Callers must compare independently accepted reporter or membership context.
    /// # Errors
    /// Refuses malformed profile payloads and reporter/recipient disagreement.
    pub fn decode_profile_payload(
        &self,
    ) -> Result<
        Option<crate::account::usage::ProfilePublicationPayload>,
        crate::account::AccountError,
    > {
        use crate::{
            account::usage::NodeControlProfilePublication,
            account::usage::ProfilePublicationPayload, account::usage::UsageProfilePublication,
        };
        let content = self.content();
        if content.payload.is_empty() {
            return Ok(None);
        }
        match (content.key.family, content.key.kind) {
            (9, "usage-profile") => {
                let value = UsageProfilePublication::decode(content.payload)?;
                value.validate_reporter(content.key.recipient)?;
                Ok(Some(ProfilePublicationPayload::Usage(value)))
            }
            (10, "node-control-profile") => Ok(Some(ProfilePublicationPayload::NodeControl(
                NodeControlProfilePublication::decode(content.payload)?,
            ))),
            _ => Ok(None),
        }
    }

    /// Decodes only provider grant kinds, comparing signed envelope facts.
    /// Empty withdrawal and unrelated kinds return None.
    /// # Errors
    /// Refuses wrong payload types, recipients, issuers, families or revisions.
    pub fn decode_grant_payload(
        &self,
    ) -> Result<Option<crate::account::grants::GrantPublication>, PublicationError> {
        let content = self.content();
        if !matches!(
            (content.key.family, content.key.kind),
            (3, "egress-grants") | (4, "exit-grants")
        ) || content.payload.is_empty()
        {
            return Ok(None);
        }
        let value = crate::account::grants::GrantPublication::decode(content.payload)
            .map_err(|_| PublicationError::Field)?;
        if value.family != content.key.family
            || value.issuer != content.key.issuer
            || value.recipient != content.key.recipient
            || value.revision != content.version
        {
            return Err(PublicationError::Field);
        }
        Ok(Some(value))
    }

    /// Decodes only the standalone client route kind, never provider grants.
    /// Empty withdrawal and unrelated kinds return None.
    /// # Errors
    /// Refuses malformed routes or disagreement with event recipient/revision.
    pub fn decode_subnet_payload(
        &self,
    ) -> Result<Option<crate::account::subnet::SubnetPublication>, PublicationError> {
        let content = self.content();
        if (content.key.family, content.key.kind) != (4, "subnet-routes")
            || content.payload.is_empty()
        {
            return Ok(None);
        }
        let value = crate::account::subnet::SubnetPublication::decode(content.payload)
            .map_err(|_| PublicationError::Field)?;
        if value.recipient != *content.key.recipient.as_bytes() || value.revision != content.version
        {
            return Err(PublicationError::Field);
        }
        Ok(Some(value))
    }

    /// Decodes only the provider inventory kind; decoding conveys no authority.
    /// Empty carrier withdrawals and unrelated kinds return None.
    /// # Errors
    /// Refuses malformed or noncanonical mapping payloads.
    pub fn decode_provider_mapping_payload(
        &self,
    ) -> Result<Option<crate::account::subnet::ProviderMappings>, PublicationError> {
        let content = self.content();
        if (content.key.family, content.key.kind) != (4, "provider-mappings")
            || content.payload.is_empty()
        {
            return Ok(None);
        }
        crate::account::subnet::ProviderMappings::decode(content.payload)
            .map(Some)
            .map_err(|_| PublicationError::Field)
    }

    /// Compares routing collections against independently accepted identity and membership.
    /// Source signatures and pending delivery still require the source decision API.
    /// Empty withdrawals retain the same recipient, Network and source-scope fences.
    /// # Errors
    /// Refuses unrelated kinds, mismatched context, wrong scopes or invalid payloads.
    pub fn validate_routing_context(
        &self,
        recipient: IdentityKey,
        membership: &crate::account::control::exchange::MembershipScope,
    ) -> Result<(), PublicationError> {
        let content = self.content();
        let scope = match (content.key.family, content.key.kind) {
            (3, "egress-grants") => "egress",
            (4, "exit-grants" | "subnet-routes" | "provider-mappings") => "nodes",
            _ => return Err(PublicationError::Field),
        };
        if content.key.recipient != recipient {
            return Err(PublicationError::Recipient);
        }
        if content.key.scope != scope
            || content.key.served_realm != RealmId::from_bytes(membership.network_id)
        {
            return Err(PublicationError::Scope);
        }
        self.decode_provider_mapping_payload()?;
        if let Some(value) = self.decode_subnet_payload()?
            && (value.recipient != *recipient.as_bytes()
                || value.nsd_id != membership.nsd_id
                || value.network_id != membership.network_id)
        {
            return Err(PublicationError::Scope);
        }
        if let Some(value) = self.decode_grant_payload()?
            && value.grants.iter().any(|grant| {
                grant.resource.nsd_id != membership.nsd_id
                    || grant.resource.network_id != membership.network_id
            })
        {
            return Err(PublicationError::Scope);
        }
        Ok(())
    }
}
