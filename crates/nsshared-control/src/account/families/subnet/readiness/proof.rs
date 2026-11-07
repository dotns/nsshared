use super::{
    ExitInstallContext, ExitInstallationIncarnation, digest, field, hosts_valid, nonzero,
    read_hosts, write_hosts,
};
use crate::{
    account::{
        AccountError, MAX_BYTES,
        codec::{bounded, data_text, reader, require},
        grants::GrantDetails,
        subnet::SubnetPrefix,
    },
    service::ServiceRef,
};
use nsshared_codec::cbor::{CborReader, CborWriter};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Completed peer installation evidence; native guard custody remains with the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitPeerReceipt {
    /// Continuous installed-effect lifetime, independent of reconcile ticket counters.
    pub installation_id: [u8; 16],
    /// Provider local WG public key.
    pub local_wg: [u8; 32],
    /// Consumer WG public key owning exactly these return hosts.
    pub consumer_wg: [u8; 32],
    /// Exact /128 return routes; broad covering routes cannot substitute.
    pub return_hosts: Vec<Ipv6Addr>,
}
impl ExitPeerReceipt {
    /// Encodes an exact completed-peer observation.
    /// # Errors
    /// Refuses zero identity/keys or invalid host cardinality.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        nonzero(&self.installation_id)?;
        require(self.local_wg != [0; 32] && self.consumer_wg != [0; 32])?;
        hosts_valid(&self.return_hosts)?;
        let mut out = CborWriter::default();
        out.array(5)
            .uint(1)
            .bytes(&self.installation_id)
            .bytes(&self.local_wg)
            .bytes(&self.consumer_wg);
        write_hosts(&mut out, &self.return_hosts);
        bounded(out.into_bytes())
    }
    /// Decodes exact bounded peer evidence without asserting live native custody.
    /// # Errors
    /// Refuses malformed or invalid observations.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 5)?;
        let value = Self {
            installation_id: input.fixed_bytes()?,
            local_wg: input.fixed_bytes()?,
            consumer_wg: input.fixed_bytes()?,
            return_hosts: read_hosts(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Local Exit binding and actually adopted grant deadline observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitBindingReceipt {
    /// Generation scoped to the provider installation incarnation.
    pub generation: u64,
    /// Exact installed Exit resource.
    pub resource: ServiceRef,
    /// Exact real IPv4 route.
    pub real: SubnetPrefix,
    /// Positive native interface index.
    pub interface_index: u32,
    /// Validated native interface name.
    pub interface_name: String,
    /// Actual bound source IPv4 address.
    pub source_ipv4: Ipv4Addr,
    /// Deadline adopted by the live permission/Entry/accounting owners.
    pub adopted_until_unix_ms: u64,
}
impl ExitBindingReceipt {
    /// Encodes exact binding facts, never permission to install them.
    /// # Errors
    /// Refuses invalid counters, prefix, interface or source address.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.generation > 0 && self.interface_index > 0 && self.adopted_until_unix_ms > 0)?;
        data_text(&self.interface_name)?;
        self.real.validate().map_err(field)?;
        require(
            self.real.address.is_ipv4()
                && !self.source_ipv4.is_unspecified()
                && !self.source_ipv4.is_multicast()
                && !self.source_ipv4.is_broadcast(),
        )?;
        let mut out = CborWriter::default();
        out.array(8)
            .uint(1)
            .uint(self.generation)
            .bytes(&self.resource.canonical().map_err(field)?);
        self.real.write(&mut out);
        out.uint(u64::from(self.interface_index))
            .text(&self.interface_name)
            .bytes(&self.source_ipv4.octets())
            .uint(self.adopted_until_unix_ms);
        bounded(out.into_bytes())
    }
    /// Decodes exact local binding observations.
    /// # Errors
    /// Refuses malformed, noncanonical or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 8)?;
        let value = Self {
            generation: input.uint()?,
            resource: ServiceRef::decode(input.bytes_up_to(MAX_BYTES)?).map_err(field)?,
            real: SubnetPrefix::read(&mut input).map_err(field)?,
            interface_index: u32::try_from(input.uint()?).map_err(field)?,
            interface_name: input.text_up_to(256)?.into(),
            source_ipv4: Ipv4Addr::from(input.fixed_bytes::<4>()?),
            adopted_until_unix_ms: input.uint()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Installation state; reconcile progress alone cannot imply withdrawal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExitInstallStatus {
    /// Explicit loss of the matching installation.
    NotInstalled,
    /// Both completed owners were coherently observed with retained live guards.
    Installed {
        /// Exact completed peer evidence.
        peer: ExitPeerReceipt,
        /// Exact binding and adopted deadline evidence.
        binding: Box<ExitBindingReceipt>,
    },
}
impl ExitInstallStatus {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        match self {
            Self::NotInstalled => {
                out.array(1).uint(0);
            }
            Self::Installed { peer, binding } => {
                out.array(3)
                    .uint(1)
                    .bytes(&peer.canonical()?)
                    .bytes(&binding.canonical()?);
            }
        }
        Ok(())
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        let count = input.array_up_to(3)?;
        match (count, input.uint()?) {
            (1, 0) => Ok(Self::NotInstalled),
            (3, 1) => Ok(Self::Installed {
                peer: ExitPeerReceipt::decode(input.bytes_up_to(MAX_BYTES)?)?,
                binding: Box::new(ExitBindingReceipt::decode(input.bytes_up_to(MAX_BYTES)?)?),
            }),
            _ => Err(AccountError::Field),
        }
    }
}

/// Provider observation correlated to an already issued challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitInstallObservation {
    /// Exact challenge identity.
    pub challenge_id: [u8; 16],
    /// Digest of the full exact context, including NSD incarnation.
    pub context_digest: [u8; 32],
    /// Actual engine/admission-owner lifetime.
    pub provider_incarnation: ExitInstallationIncarnation,
    /// Positive monotonic observation counter within this provider/context lifetime.
    pub generation: u64,
    /// Complete joined evidence or explicit matching withdrawal.
    pub status: ExitInstallStatus,
}
impl ExitInstallObservation {
    /// Encodes exact canonical observations without asserting their acceptance.
    /// # Errors
    /// Refuses zero context/owner/generation or invalid proof fields.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        nonzero(&self.challenge_id)?;
        nonzero(&self.provider_incarnation.0)?;
        require(self.generation > 0)?;
        let mut out = CborWriter::default();
        out.array(6)
            .uint(1)
            .bytes(&self.challenge_id)
            .bytes(&self.context_digest)
            .bytes(&self.provider_incarnation.0)
            .uint(self.generation);
        self.status.write(&mut out)?;
        bounded(out.into_bytes())
    }
    /// Decodes exact bounded installation observations.
    /// # Errors
    /// Refuses malformed, invalid or noncanonical fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 6)?;
        let value = Self {
            challenge_id: input.fixed_bytes()?,
            context_digest: input.fixed_bytes()?,
            provider_incarnation: ExitInstallationIncarnation(input.fixed_bytes()?),
            generation: input.uint()?,
            status: ExitInstallStatus::read(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Domain-separated digest for exact request/response acceptance correlation.
    /// # Errors
    /// Refuses invalid observation fields.
    pub fn digest(&self) -> Result<[u8; 32], AccountError> {
        Ok(digest(
            crate::account::domains::EXIT_OBSERVATION_DIGEST_DOMAIN,
            &self.canonical()?,
        ))
    }
    /// Matches every observation field to independently captured current expectation.
    /// # Errors
    /// Refuses stale context, foreign owners, keys, routes, bindings or adopted deadlines.
    pub fn validate_for(
        &self,
        context: &ExitInstallContext,
        now_unix_ms: u64,
    ) -> Result<(), AccountError> {
        self.canonical()?;
        require(
            self.challenge_id == context.challenge_id
                && self.context_digest == context.digest()?
                && self.provider_incarnation == context.provider_incarnation
                && now_unix_ms < context.valid_until_unix_ms,
        )?;
        if let ExitInstallStatus::Installed { peer, binding } = &self.status {
            let GrantDetails::Exit(publication) = &context.grant.details else {
                return Err(AccountError::Field);
            };
            let [route] = publication.routes.as_slice() else {
                return Err(AccountError::Field);
            };
            require(
                peer.local_wg == context.provider_node.wg_key
                    && peer.consumer_wg == context.consumer_node.wg_key
                    && peer.return_hosts == context.return_hosts
                    && binding.resource == context.grant.resource
                    && binding.real == route.real
                    && binding.adopted_until_unix_ms == context.grant.expires_at_unix_ms,
            )?;
        }
        Ok(())
    }
    /// Enforces a retained generation floor; identical replay is idempotent.
    /// # Errors
    /// Refuses foreign context/owner, stale generations or equal-generation conflicts.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), AccountError> {
        self.canonical()?;
        previous.canonical()?;
        require(
            self.challenge_id == previous.challenge_id
                && self.context_digest == previous.context_digest
                && self.provider_incarnation == previous.provider_incarnation
                && (self.generation > previous.generation || self == previous),
        )
    }
}

/// NSD-confirmed joined observation, bounded by the exact issued authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitProviderConfirmation {
    /// Full context; a digest alone cannot be the consumer contract.
    pub context: ExitInstallContext,
    /// Exact accepted positive observation.
    pub observation: ExitInstallObservation,
    /// Exclusive confirmation deadline, no later than context validity.
    pub valid_until_unix_ms: u64,
}
impl ExitProviderConfirmation {
    /// Encodes only internally matched positive confirmations.
    /// # Errors
    /// Refuses negative, mismatched, invalid or overlong confirmations.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.observation.validate_for(&self.context, 0)?;
        require(
            matches!(self.observation.status, ExitInstallStatus::Installed { .. })
                && self.valid_until_unix_ms > 0
                && self.valid_until_unix_ms <= self.context.valid_until_unix_ms,
        )?;
        let mut out = CborWriter::default();
        out.array(4)
            .uint(1)
            .bytes(&self.context.canonical()?)
            .bytes(&self.observation.canonical()?)
            .uint(self.valid_until_unix_ms);
        bounded(out.into_bytes())
    }
    /// Decodes complete positive proof without accepting authority or currentness.
    /// # Errors
    /// Refuses malformed, mismatched or negative proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            context: ExitInstallContext::decode(input.bytes_up_to(MAX_BYTES)?)?,
            observation: ExitInstallObservation::decode(input.bytes_up_to(MAX_BYTES)?)?,
            valid_until_unix_ms: input.uint()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Checks exact independently captured context and exclusive validity.
    /// # Errors
    /// Refuses replacement selection/owner/grant or expired confirmation.
    pub fn validate_for(
        &self,
        expected: &ExitInstallContext,
        now_unix_ms: u64,
    ) -> Result<(), AccountError> {
        self.canonical()?;
        expected.canonical()?;
        require(self.context == *expected && now_unix_ms < self.valid_until_unix_ms)?;
        self.observation.validate_for(expected, now_unix_ms)
    }
}
