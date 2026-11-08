use super::{
    consumer_return_identity, digest, field, hosts_valid, nonzero, read_hosts, write_hosts,
};
use crate::account::{
    AccountError, MAX_BYTES,
    codec::{bounded, reader, require},
    control::{RouteAction, RouteOutcome, RouteReceipt},
    grants::{GrantDetails, ServiceGrant},
    node::NodeBinding,
    publication::SourceBinding,
};
use nsshared_codec::cbor::{CborReader, CborWriter};
use std::net::Ipv6Addr;

/// Equality-only token for one actual consumer or provider installation-owner lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitInstallationIncarnation(pub [u8; 16]);
impl ExitInstallationIncarnation {
    /// Encodes the nonzero lifetime token.
    /// # Errors
    /// Refuses the zero token.
    pub fn canonical(self) -> Result<Vec<u8>, AccountError> {
        nonzero(&self.0)?;
        let mut out = CborWriter::default();
        out.bytes(&self.0);
        Ok(out.into_bytes())
    }
    /// Decodes an exact nonzero lifetime token.
    /// # Errors
    /// Refuses wrong lengths, zero, noncanonical and trailing input.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, 32)?;
        let value = Self(input.fixed_bytes()?);
        input.finish()?;
        nonzero(&value.0)?;
        Ok(value)
    }
}

/// NSD-issued exact selection observation challenge; this supplies no packet authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitInstallContext {
    /// Nonzero unique challenge in this NSD application lifetime.
    pub challenge_id: [u8; 16],
    /// Nonzero NSD application lifetime, never restored from persistent history.
    pub nsd_incarnation: [u8; 16],
    /// Exact committed selection including its authenticated consumer source.
    pub receipt: RouteReceipt,
    /// Current consumer signing/WG record.
    pub consumer_node: NodeBinding,
    /// Actual consumer authentication-owner lifetime.
    pub consumer_incarnation: ExitInstallationIncarnation,
    /// Current provider source, checked independently of its home runtime fence.
    pub provider_source: SourceBinding,
    /// Current provider signing/WG record.
    pub provider_node: NodeBinding,
    /// Actual provider engine/admission-owner lifetime.
    pub provider_incarnation: ExitInstallationIncarnation,
    /// Exact issued selected grant, including expiry.
    pub grant: ServiceGrant,
    /// Actual issued grant publication version, not a per-grant generation.
    pub grant_version: u64,
    /// Exact issued grant publication payload digest.
    pub grant_publication_digest: [u8; 32],
    /// Exact consumer return /128 hosts, derived independently of a report.
    pub return_hosts: Vec<Ipv6Addr>,
    /// Exclusive authority-bounded validity in Unix milliseconds.
    pub valid_until_unix_ms: u64,
}
impl ExitInstallContext {
    fn validate(&self) -> Result<(), AccountError> {
        nonzero(&self.challenge_id)?;
        nonzero(&self.nsd_incarnation)?;
        self.receipt.canonical().map_err(field)?;
        self.consumer_node.validate()?;
        self.provider_node.validate()?;
        nonzero(&self.consumer_incarnation.0)?;
        nonzero(&self.provider_incarnation.0)?;
        self.provider_source.canonical().map_err(field)?;
        self.grant.canonical().map_err(field)?;
        nonzero(&self.grant.incarnation.0)?;
        let consumer = &self.receipt.command.binding.binding;
        self.receipt
            .command
            .binding
            .verify(consumer.nsd)
            .map_err(field)?;
        require(
            self.receipt.outcome == RouteOutcome::Selected
                && self.grant_version > 0
                && self.valid_until_unix_ms > 0
                && self.valid_until_unix_ms <= self.grant.expires_at_unix_ms,
        )?;
        for (source, node) in [
            (consumer, &self.consumer_node),
            (&self.provider_source, &self.provider_node),
        ] {
            require(
                source.nsd == consumer.nsd
                    && source.served_realm == consumer.served_realm
                    && source.scope == "nodes"
                    && source.profile == consumer.profile
                    && source.recipient == node.identity
                    && source.source_node == node.identity,
            )?;
        }
        require(
            consumer.recipient == self.grant.client
                && self.provider_source.recipient == self.grant.provider,
        )?;
        let GrantDetails::Exit(publication) = &self.grant.details else {
            return Err(AccountError::Field);
        };
        let [route] = publication.routes.as_slice() else {
            return Err(AccountError::Field);
        };
        require(
            self.grant.resource.nsd_id == publication.nsd_id
                && self.grant.resource.network_id == publication.network_id
                && self.grant.resource.network_id == *consumer.served_realm.as_bytes(),
        )?;
        let RouteAction::Select {
            provider,
            resource,
            scope,
        } = &self.receipt.command.action
        else {
            return Err(AccountError::Field);
        };
        require(
            *provider == self.grant.provider
                && *resource == self.grant.resource
                && *scope == route.selection,
        )?;
        let selected = publication.selected_routes().map_err(field)?;
        require(selected.len() == 1 && selected[0].coverage.tcp && selected[0].coverage.udp)?;
        hosts_valid(&self.return_hosts)?;
        require(
            self.return_hosts
                == [consumer_return_identity(
                    self.grant.client.as_bytes(),
                    route.mapped,
                )?],
        )
    }
    /// Encodes the complete canonical challenge.
    /// # Errors
    /// Refuses inconsistent endpoint, selection, grant, mapping or validity fences.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(14)
            .uint(1)
            .bytes(&self.challenge_id)
            .bytes(&self.nsd_incarnation)
            .bytes(&self.receipt.canonical().map_err(field)?);
        self.consumer_node.write(&mut out);
        out.bytes(&self.consumer_incarnation.0)
            .bytes(&self.provider_source.canonical().map_err(field)?);
        self.provider_node.write(&mut out);
        out.bytes(&self.provider_incarnation.0)
            .bytes(&self.grant.canonical().map_err(field)?)
            .uint(self.grant_version)
            .bytes(&self.grant_publication_digest);
        write_hosts(&mut out, &self.return_hosts);
        out.uint(self.valid_until_unix_ms);
        bounded(out.into_bytes())
    }
    /// Decodes an exact bounded challenge without inferring current authority.
    /// # Errors
    /// Refuses malformed, noncanonical or internally inconsistent fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 14)?;
        let value = Self {
            challenge_id: input.fixed_bytes()?,
            nsd_incarnation: input.fixed_bytes()?,
            receipt: RouteReceipt::decode(input.bytes_up_to(MAX_BYTES)?).map_err(field)?,
            consumer_node: NodeBinding::read(&mut input)?,
            consumer_incarnation: ExitInstallationIncarnation(input.fixed_bytes()?),
            provider_source: SourceBinding::decode(input.bytes_up_to(MAX_BYTES)?).map_err(field)?,
            provider_node: NodeBinding::read(&mut input)?,
            provider_incarnation: ExitInstallationIncarnation(input.fixed_bytes()?),
            grant: ServiceGrant::decode(input.bytes_up_to(MAX_BYTES)?).map_err(field)?,
            grant_version: input.uint()?,
            grant_publication_digest: input.fixed_bytes()?,
            return_hosts: read_hosts(&mut input)?,
            valid_until_unix_ms: input.uint()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Domain-separated SHA-256 of the exact challenge including every authority fence.
    /// # Errors
    /// Refuses an invalid challenge.
    pub fn digest(&self) -> Result<[u8; 32], AccountError> {
        Ok(digest(
            crate::account::domains::EXIT_CONTEXT_DIGEST_DOMAIN,
            &self.canonical()?,
        ))
    }
}
