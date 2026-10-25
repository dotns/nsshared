use crate::{
    account::AccountError, account::SCHEMA, account::node::GrantIncarnation,
    account::node::ReporterIncarnation, account::reader,
};

use nsshared_codec::cbor::CborWriter;
use nsshared_identity::realm::RealmId;

/// Versioned service byte boundary. WireGuard overhead is never included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum ServiceBoundary {
    /// Egress/Exit payload bytes successfully completed by host writes or sends.
    CompletedHostWritesAndSends,
    /// Existing public-ingress byte boundary, preserved by its consumer.
    PublicIngress,
}

/// Direction relative to the authorized service client and provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum Direction {
    /// Client to service provider.
    ClientToProvider,
    /// Service provider to client.
    ProviderToClient,
}

/// Measured span vulnerable to loss before durable batch custody.
/// Unset must never be interpreted as measured zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchLossWindow {
    /// Measurement has not been supplied.
    Unset,
    /// Independently measured maximum vulnerable span.
    Measured {
        /// Measured duration in milliseconds; zero is meaningful.
        duration_ms: u64,
    },
}

/// Candidate service unit, independent of the later report envelope.
/// Every payer and incarnation is explicit; M6 owns service references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceUsage {
    /// Versioned completed-byte boundary.
    pub boundary: ServiceBoundary,
    /// Client/provider direction.
    pub direction: Direction,
    /// Explicit paying realm.
    pub payer_realm: RealmId,
    /// Paying realm-local UserId, unsigned big-endian ULID bytes.
    pub payer_subject: [u8; 16],
    /// Grant lifecycle captured when counting.
    pub grant: GrantIncarnation,
    /// Independent reporter lifecycle captured when counting.
    pub reporter: ReporterIncarnation,
    /// Completed bytes at the chosen boundary; partial writes count only completion.
    pub completed_bytes: u64,
    /// Unset until measured; not a guessed constant.
    pub batch_loss_window: BatchLossWindow,
}

impl ServiceUsage {
    /// Encodes the candidate unit and batch-loss measurement state.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = CborWriter::default();
        out.array(9)
            .uint(SCHEMA)
            .uint(self.boundary as u64)
            .uint(self.direction as u64)
            .bytes(self.payer_realm.as_bytes())
            .bytes(&self.payer_subject)
            .bytes(&self.grant.0)
            .bytes(&self.reporter.0)
            .uint(self.completed_bytes);
        match self.batch_loss_window {
            BatchLossWindow::Unset => {
                out.null();
            }
            BatchLossWindow::Measured { duration_ms } => {
                out.array(1).uint(duration_ms);
            }
        }
        out.into_bytes()
    }

    /// Decodes one exact canonical unit without rounding or interpreting unset values.
    ///
    /// # Errors
    /// Rejects malformed CBOR, unsupported units, directions and incorrect payer widths.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 9)?;
        let boundary = match input.uint()? {
            0 => ServiceBoundary::CompletedHostWritesAndSends,
            1 => ServiceBoundary::PublicIngress,
            _ => return Err(AccountError::Field),
        };
        let direction = match input.uint()? {
            0 => Direction::ClientToProvider,
            1 => Direction::ProviderToClient,
            _ => return Err(AccountError::Field),
        };
        let mut value = Self {
            boundary,
            direction,
            payer_realm: RealmId::from_bytes(input.fixed_bytes()?),
            payer_subject: input.fixed_bytes()?,
            grant: GrantIncarnation(input.fixed_bytes()?),
            reporter: ReporterIncarnation(input.fixed_bytes()?),
            completed_bytes: input.uint()?,
            batch_loss_window: BatchLossWindow::Unset,
        };
        if !input.take_null() {
            input.array(1)?;
            value.batch_loss_window = BatchLossWindow::Measured {
                duration_ms: input.uint()?,
            };
        }
        input.finish()?;
        Ok(value)
    }
}
