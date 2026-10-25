use crate::{
    account::AccountError, account::SCHEMA, account::codec::identity, account::codec::reader,
    account::codec::require, account::node::ReporterIncarnation, account::relay::IdentityClass,
    account::relay::ParticipantRosterGeneration, account::relay::ParticipantRosterScope,
    account::relay::RosterVersion, account::usage::UsageError,
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::identity::NodeId;

/// Direction relative to the fixed endpoints captured for this observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RelayDirection {
    /// DATA from source to destination.
    SourceToDestination,
    /// DATA from destination to source.
    DestinationToSource,
}

/// Historical classification result; no service-byte conversion is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayBilling {
    /// Both captured endpoints are ordinary Nodes.
    Billable,
    /// Either captured endpoint is a gateway; exclude a second service bill.
    GatewayExcluded,
}

/// Whole accepted encoded DATA observed once at the accepting ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayUsage {
    /// Fixed source endpoint NodeId.
    pub source: NodeId,
    /// Fixed destination endpoint NodeId.
    pub destination: NodeId,
    /// Source class captured at acceptance.
    pub source_class: IdentityClass,
    /// Destination class from the same admission generation.
    pub destination_class: IdentityClass,
    /// Original issuer and participant; participant is the reporter identity.
    pub scope: ParticipantRosterScope,
    /// Captured roster version, never a current-role lookup.
    pub epoch: RosterVersion,
    /// DATA direction relative to the captured endpoints.
    pub direction: RelayDirection,
    /// Independent reporter lifecycle.
    pub reporter: ReporterIncarnation,
    /// Whole accepted encoded DATA length, including its relay header.
    pub encoded_bytes: u64,
}

fn class(value: u64) -> Result<IdentityClass, AccountError> {
    match value {
        0 => Ok(IdentityClass::OrdinaryNode),
        1 => Ok(IdentityClass::GatewayNode),
        _ => Err(AccountError::Field),
    }
}

impl RelayUsage {
    /// Encodes captured attribution without consulting current ownership.
    ///
    /// # Errors
    /// Refuses zero epoch or an empty accepted DATA observation.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(self.epoch.0 > 0 && self.encoded_bytes > 0)?;
        let mut out = CborWriter::default();
        out.array(11)
            .uint(SCHEMA)
            .bytes(self.source.as_bytes())
            .bytes(self.destination.as_bytes())
            .uint(self.source_class as u64)
            .uint(self.destination_class as u64)
            .bytes(self.scope.issuer.as_bytes())
            .bytes(self.scope.recipient.as_bytes())
            .uint(self.epoch.0)
            .uint(self.direction as u64)
            .bytes(&self.reporter.0)
            .uint(self.encoded_bytes);
        Ok(out.into_bytes())
    }

    /// Decodes one exact canonical relay unit.
    ///
    /// # Errors
    /// Refuses invalid widths, classes, direction, epoch and trailing input.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 11)?;
        let source = NodeId::from_bytes(input.fixed_bytes()?);
        let destination = NodeId::from_bytes(input.fixed_bytes()?);
        let source_class = class(input.uint()?)?;
        let destination_class = class(input.uint()?)?;
        let scope = ParticipantRosterScope {
            issuer: identity(&mut input)?,
            recipient: identity(&mut input)?,
        };
        let epoch = RosterVersion(input.uint()?);
        let direction = match input.uint()? {
            0 => RelayDirection::SourceToDestination,
            1 => RelayDirection::DestinationToSource,
            _ => return Err(AccountError::Field),
        };
        let value = Self {
            source,
            destination,
            source_class,
            destination_class,
            scope,
            epoch,
            direction,
            reporter: ReporterIncarnation(input.fixed_bytes()?),
            encoded_bytes: input.uint()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }

    /// Compares the retained historical generation, even after its expiry.
    /// This performs no authentication or history lookup on the caller's behalf.
    ///
    /// # Errors
    /// Missing, ambiguous or mismatched history requires typed mapping repair.
    pub fn validate_history(
        &self,
        historical: Option<&ParticipantRosterGeneration>,
    ) -> Result<RelayBilling, UsageError> {
        self.canonical()?;
        let history = historical.ok_or(UsageError::UnknownMapping)?;
        if history.scope != self.scope || history.version != self.epoch {
            return Err(UsageError::UnknownMapping);
        }
        for (node, expected) in [
            (self.source, self.source_class),
            (self.destination, self.destination_class),
        ] {
            let mut matches = history
                .identities
                .iter()
                .filter(|entry| entry.identity.node_id() == node);
            if matches.next().is_none_or(|entry| entry.class != expected)
                || matches.next().is_some()
            {
                return Err(UsageError::UnknownMapping);
            }
        }
        Ok(
            if self.source_class == IdentityClass::GatewayNode
                || self.destination_class == IdentityClass::GatewayNode
            {
                RelayBilling::GatewayExcluded
            } else {
                RelayBilling::Billable
            },
        )
    }
}
