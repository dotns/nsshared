//! The WSS server TLS configuration: a self-signed certificate or PEM files, always with
//! the explicit aws-lc-rs provider (quick-v2 §8.5).

use super::{Error, GeneratedCert, TlsSource};
use rustls::{
    ServerConfig,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
};
use std::sync::Arc;

/// The default extra names of a self-signed certificate besides the relay host.
const DEFAULT_NAMES: [&str; 2] = ["localhost", "127.0.0.1"];

/// Builds the server configuration and returns the generated certificate when self-signed.
pub(super) fn server_config(
    source: &TlsSource,
    relay_host: &str,
) -> Result<(Arc<ServerConfig>, Option<GeneratedCert>), Error> {
    let (chain, key, generated) = match source {
        TlsSource::SelfSigned { names } => {
            let names = self_signed_names(names, relay_host);
            let certified = rcgen::generate_simple_self_signed(names)?;
            let der = certified.cert.der().clone();
            let generated = GeneratedCert {
                der: der.to_vec(),
                pem: certified.cert.pem(),
            };
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.signing_key.serialize_der(),
            ));
            (vec![der], key, Some(generated))
        }
        TlsSource::Pem { cert, key } => {
            let chain = CertificateDer::pem_file_iter(cert)
                .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
                .map_err(|source| Error::Pem {
                    path: cert.clone(),
                    source,
                })?;
            let key = PrivateKeyDer::from_pem_file(key).map_err(|source| Error::Pem {
                path: key.clone(),
                source,
            })?;
            (chain, key, None)
        }
    };
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok((Arc::new(config), generated))
}

/// Returns `names`, or the defaults when empty, always including the relay host.
fn self_signed_names(names: &[String], relay_host: &str) -> Vec<String> {
    let mut all = vec![relay_host.to_owned()];
    let extra = if names.is_empty() {
        DEFAULT_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    } else {
        names.to_vec()
    };
    for name in extra {
        if !all.contains(&name) {
            all.push(name);
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_names_always_include_the_relay_host() {
        assert_eq!(
            self_signed_names(&[], "127.0.0.1"),
            vec!["127.0.0.1".to_owned(), "localhost".to_owned()]
        );
        assert_eq!(
            self_signed_names(&["relay.test".to_owned()], "::1"),
            vec!["::1".to_owned(), "relay.test".to_owned()]
        );
    }
}
