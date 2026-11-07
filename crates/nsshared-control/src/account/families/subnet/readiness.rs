//! Selection-scoped installation observations, never forwarding authority.
mod context;
mod proof;
mod publication;
mod return_identity;

pub use context::{ExitInstallContext, ExitInstallationIncarnation};
pub use proof::{
    ExitBindingReceipt, ExitInstallObservation, ExitInstallStatus, ExitPeerReceipt,
    ExitProviderConfirmation,
};
pub use publication::{ExitReadinessPublication, MAX_EXIT_CONFIRMATIONS};
pub use return_identity::consumer_return_identity;

use crate::account::{AccountError, codec::require};
use nsshared_codec::cbor::{CborReader, CborWriter};
use sha2::{Digest as _, Sha256};
use std::net::Ipv6Addr;

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}
pub(super) fn nonzero(value: &[u8; 16]) -> Result<(), AccountError> {
    require(*value != [0; 16])
}
pub(super) fn hosts_valid(hosts: &[Ipv6Addr]) -> Result<(), AccountError> {
    require(hosts.len() == 1 && !hosts[0].is_unspecified() && !hosts[0].is_multicast())
}
pub(super) fn write_hosts(out: &mut CborWriter, hosts: &[Ipv6Addr]) {
    out.array(hosts.len());
    for host in hosts {
        out.bytes(&host.octets());
    }
}
pub(super) fn read_hosts(input: &mut CborReader<'_>) -> Result<Vec<Ipv6Addr>, AccountError> {
    let count = input.array_up_to(1)?;
    (0..count)
        .map(|_| Ok(Ipv6Addr::from(input.fixed_bytes::<16>()?)))
        .collect()
}
pub(super) fn field<E>(_: E) -> AccountError {
    AccountError::Field
}
