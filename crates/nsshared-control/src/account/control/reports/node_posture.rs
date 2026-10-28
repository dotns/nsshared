//! Complete device posture snapshots on an independent Node report operation.
use super::NodeRuntimeFence;
use crate::account::{
    AccountError,
    codec::{bounded, reader, require},
    control::MembershipScope,
};
use nsshared_codec::cbor::{CborReader, CborWriter};

/// Maximum UTF-8 bytes in each descriptive posture field.
pub const MAX_NODE_POSTURE_TEXT_BYTES: usize = 1024;
/// Maximum IP literals in a complete posture snapshot.
pub const MAX_NODE_POSTURE_IPS: usize = 256;
/// Maximum bytes in one IPv4 or IPv6 literal, including mixed notation.
pub const MAX_NODE_POSTURE_IP_BYTES: usize = 45;

/// Platform collector's disk-encryption observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskEncryptionStatus {
    /// Disk encryption was detected.
    Encrypted,
    /// Disk encryption was not enabled.
    Unencrypted,
    /// The collector could not determine encryption status.
    Unknown,
}
impl DiskEncryptionStatus {
    /// Exact wire value, also consumed by the posture store.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Unencrypted => "unencrypted",
            Self::Unknown => "unknown",
        }
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.text_up_to(11)? {
            "encrypted" => Ok(Self::Encrypted),
            "unencrypted" => Ok(Self::Unencrypted),
            "unknown" => Ok(Self::Unknown),
            _ => Err(AccountError::Field),
        }
    }
}

/// Complete platform facts; empty text or IP lists remain explicit values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePostureSnapshot {
    /// Operating system family.
    pub os: String,
    /// Operating system version.
    pub os_version: String,
    /// CPU architecture.
    pub arch: String,
    /// Reporter version, mapped to the posture store's client-version column.
    pub client_version: String,
    /// Collected host name.
    pub hostname: String,
    /// Collected disk-encryption status.
    pub disk_encryption: DiskEncryptionStatus,
    /// Collected process uptime in seconds.
    pub uptime_seconds: u64,
    /// Local IP literals, retaining supplied spelling, order and duplicates.
    pub local_ips: Vec<String>,
}
impl NodePostureSnapshot {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        let texts = [
            &self.os,
            &self.os_version,
            &self.arch,
            &self.client_version,
            &self.hostname,
        ];
        if texts
            .iter()
            .any(|text| text.len() > MAX_NODE_POSTURE_TEXT_BYTES)
            || self.local_ips.len() > MAX_NODE_POSTURE_IPS
            || self
                .local_ips
                .iter()
                .any(|ip| ip.len() > MAX_NODE_POSTURE_IP_BYTES)
        {
            return Err(AccountError::Bounds);
        }
        require(
            self.local_ips
                .iter()
                .all(|ip| ip.parse::<std::net::IpAddr>().is_ok()),
        )?;
        out.array(8);
        for text in texts {
            out.text(text);
        }
        out.text(self.disk_encryption.as_str())
            .uint(self.uptime_seconds)
            .array(self.local_ips.len());
        for ip in &self.local_ips {
            out.text(ip);
        }
        Ok(())
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(8)?;
        let os = input.text_up_to(MAX_NODE_POSTURE_TEXT_BYTES)?.into();
        let os_version = input.text_up_to(MAX_NODE_POSTURE_TEXT_BYTES)?.into();
        let arch = input.text_up_to(MAX_NODE_POSTURE_TEXT_BYTES)?.into();
        let client_version = input.text_up_to(MAX_NODE_POSTURE_TEXT_BYTES)?.into();
        let hostname = input.text_up_to(MAX_NODE_POSTURE_TEXT_BYTES)?.into();
        let disk_encryption = DiskEncryptionStatus::read(input)?;
        let uptime_seconds = input.uint()?;
        let count = input.array_up_to(MAX_NODE_POSTURE_IPS)?;
        let mut local_ips = Vec::with_capacity(count);
        for _ in 0..count {
            local_ips.push(input.text_up_to(MAX_NODE_POSTURE_IP_BYTES)?.into());
        }
        Ok(Self {
            os,
            os_version,
            arch,
            client_version,
            hostname,
            disk_encryption,
            uptime_seconds,
            local_ips,
        })
    }
}

/// Complete posture for one accepted membership and runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePostureRequest {
    /// Exact accepted membership from registration and source custody.
    pub scope: MembershipScope,
    /// Accepted service runtime, compared with current storage by the consumer.
    pub fence: NodeRuntimeFence,
    /// Unique pending identifier retained with this exact snapshot.
    pub request_id: [u8; 16],
    /// Complete platform-collected facts, never a partial update.
    pub snapshot: NodePostureSnapshot,
}
impl NodePostureRequest {
    /// Encodes a bounded canonical complete snapshot.
    /// # Errors
    /// Refuses invalid runtime fields, IP literals or excessive bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(5).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.request_id);
        self.snapshot.write(&mut out)?;
        bounded(out.into_bytes())
    }
    /// Decodes an exact canonical posture request.
    /// # Errors
    /// Refuses malformed, noncanonical, unknown or oversized fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 5)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            request_id: input.fixed_bytes()?,
            snapshot: NodePostureSnapshot::read(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Receipt emitted only after the exact pending snapshot has been committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePostureResponse {
    /// Echo of the accepted membership.
    pub scope: MembershipScope,
    /// Echo of the accepted runtime fence.
    pub fence: NodeRuntimeFence,
    /// Echo of the exact snapshot's pending identifier.
    pub request_id: [u8; 16],
}
impl NodePostureResponse {
    /// Encodes the correlated receipt.
    /// # Errors
    /// Refuses invalid runtime fields.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.scope.write(&mut out);
        self.fence.write(&mut out)?;
        out.bytes(&self.request_id);
        bounded(out.into_bytes())
    }
    /// Decodes an exact canonical posture receipt.
    /// # Errors
    /// Refuses malformed, noncanonical or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            fence: NodeRuntimeFence::read(&mut input)?,
            request_id: input.fixed_bytes()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Correlates all receipt fields with the retained exact request.
    /// # Errors
    /// Refuses invalid fields or any request id, membership or runtime mismatch.
    pub fn validate_for(&self, pending: &NodePostureRequest) -> Result<(), AccountError> {
        self.canonical()?;
        pending.canonical()?;
        require(
            self.scope == pending.scope
                && self.fence == pending.fence
                && self.request_id == pending.request_id,
        )
    }
}
