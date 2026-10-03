//! Server TLS for `wss://{host:port}/quick/v2` (rendezvous §3, §5.4).
//!
//! The certificate either comes from PEM files or is generated self-signed for the
//! relay host name and its directory IPs, so a client that dials an entry's `ips` and
//! verifies `host` (rendezvous §5.4) accepts it once it trusts
//! [`ServerTls::certificate_pem`]. rustls runs with an explicit aws-lc-rs provider; no
//! process-wide default provider is installed.

use rustls::{
    ServerConfig,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use std::{net::IpAddr, path::Path, sync::Arc};
use thiserror::Error;

/// Why a TLS configuration could not be built.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The certificate or key PEM is unreadable or holds no usable item.
    #[error("invalid certificate or key PEM")]
    Pem(#[from] rustls::pki_types::pem::Error),
    /// Generating the self-signed certificate failed.
    #[error("self-signed certificate generation failed")]
    Generate(#[from] rcgen::Error),
    /// rustls rejected the certificate, key or protocol versions.
    #[error("TLS configuration rejected")]
    Rustls(#[from] rustls::Error),
}

/// A rustls server configuration with the certificate it presents.
#[derive(Clone, Debug)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    certificate_pem: String,
}

impl ServerTls {
    /// Generates a self-signed certificate naming `host` and every IP in `ips` as
    /// subject alternative names.
    ///
    /// # Errors
    ///
    /// [`TlsError::Generate`] for a name rcgen cannot encode, [`TlsError::Rustls`] when
    /// rustls rejects the result.
    pub fn self_signed(host: &str, ips: &[IpAddr]) -> Result<Self, TlsError> {
        let mut names = vec![host.to_owned()];
        names.extend(ips.iter().map(IpAddr::to_string));
        names.dedup();
        let certified = rcgen::generate_simple_self_signed(names)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let config = server_config(vec![certified.cert.der().clone()], key)?;
        Ok(Self {
            config,
            certificate_pem: certified.cert.pem(),
        })
    }

    /// Loads a PEM certificate chain and private key.
    ///
    /// # Errors
    ///
    /// [`TlsError::Pem`] for an unreadable or empty PEM, [`TlsError::Rustls`] when the
    /// key does not match the certificate.
    pub fn from_pem(certificate_pem: &str, key_pem: &str) -> Result<Self, TlsError> {
        let chain = CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        if chain.is_empty() {
            return Err(TlsError::Pem(rustls::pki_types::pem::Error::NoItemsFound));
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
        Ok(Self {
            config: server_config(chain, key)?,
            certificate_pem: certificate_pem.to_owned(),
        })
    }

    /// Loads [`from_pem`](Self::from_pem) input from files.
    ///
    /// # Errors
    ///
    /// [`TlsError::Pem`] when a file cannot be read, and the errors of
    /// [`from_pem`](Self::from_pem).
    pub fn from_pem_files(certificate: &Path, key: &Path) -> Result<Self, TlsError> {
        let read = |path: &Path| {
            std::fs::read_to_string(path)
                .map_err(|error| TlsError::Pem(rustls::pki_types::pem::Error::Io(error)))
        };
        Self::from_pem(&read(certificate)?, &read(key)?)
    }

    /// The rustls server configuration.
    #[must_use]
    pub fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// The presented certificate chain as PEM, for clients to trust.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }
}

fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::ServerTls;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn self_signed_round_trips_through_pem() {
        let generated =
            ServerTls::self_signed("localhost", &[IpAddr::V4(Ipv4Addr::LOCALHOST)]).unwrap();
        assert!(
            generated
                .certificate_pem()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(ServerTls::from_pem(generated.certificate_pem(), "").is_err());
    }
}
