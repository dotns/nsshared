//! `nsshared-mock-relay`: runs a single-instance, in-memory relay v2 mock on UDP and WSS
//! until Ctrl-C. Not a production relay.

use clap::Parser;
use nsshared_mock_relay::{Limits, MockRelay, MockRelayConfig, TlsSource};
use nsshared_wire::{RelayId, WSS_CONNECTIONS_PER_IP};
use std::{error::Error, net::SocketAddr, path::PathBuf, process::ExitCode};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// Single-instance, in-memory relay v2 mock for tests (UDP + WSS on one port).
#[derive(Debug, Parser)]
#[command(name = "nsshared-mock-relay", version)]
struct Args {
    /// Relay identifier `host:port` nodes sign and list; default: the bound address.
    #[arg(long, value_parser = RelayId::parse)]
    relay_id: Option<RelayId>,
    /// Shared UDP and WSS listen address; port 0 picks one free port for both.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Separate UDP listen address instead of --listen.
    #[arg(long)]
    udp_listen: Option<SocketAddr>,
    /// Separate WSS (TCP) listen address instead of --listen.
    #[arg(long)]
    wss_listen: Option<SocketAddr>,
    /// PEM certificate chain for WSS; default: a self-signed certificate.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for --tls-cert.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Extra names of the self-signed certificate, comma separated; the relay identifier
    /// host is always included (default extras: localhost, 127.0.0.1).
    #[arg(long, value_delimiter = ',', conflicts_with = "tls_cert")]
    cert_names: Vec<String>,
    /// Writes the self-signed certificate as PEM to this path so ns can trust it.
    #[arg(long, conflicts_with_all = ["tls_cert", "no_wss"])]
    write_cert: Option<PathBuf>,
    /// Presence TTL in seconds, 30..=3600.
    #[arg(long, default_value_t = 90)]
    presence_ttl: u32,
    /// Disables the UDP carrier and the `udp` capability.
    #[arg(long, conflicts_with = "no_wss")]
    no_udp: bool,
    /// Disables the WSS carrier and the `wss` capability.
    #[arg(long)]
    no_wss: bool,
    /// Maximum confirmed sessions.
    #[arg(long, default_value_t = Limits::default().max_sessions)]
    max_sessions: usize,
    /// Maximum provisional registrations per source IP.
    #[arg(long, default_value_t = Limits::default().provisional_per_ip)]
    provisional_per_ip: usize,
    /// Maximum concurrent WSS connections per remote IP.
    #[arg(long, default_value_t = WSS_CONNECTIONS_PER_IP)]
    wss_connections_per_ip: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "mock relay failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let tls = match (args.tls_cert, args.tls_key) {
        (Some(cert), Some(key)) => TlsSource::Pem { cert, key },
        _ => TlsSource::SelfSigned {
            names: args.cert_names,
        },
    };
    let config = MockRelayConfig {
        relay_id: args.relay_id,
        listen: args.listen,
        udp_listen: args.udp_listen,
        wss_listen: args.wss_listen,
        udp: !args.no_udp,
        wss: !args.no_wss,
        tls,
        presence_ttl_s: args.presence_ttl,
        limits: Limits {
            max_sessions: args.max_sessions,
            provisional_per_ip: args.provisional_per_ip,
            ..Limits::default()
        },
        wss_connections_per_ip: args.wss_connections_per_ip,
    };
    let relay = MockRelay::start(config).await?;
    let cert_path = match (&args.write_cert, relay.generated_cert()) {
        (Some(path), Some(cert)) => {
            std::fs::write(path, &cert.pem)
                .map_err(|error| format!("write {}: {error}", path.display()))?;
            Some(path.display().to_string())
        }
        _ => None,
    };
    info!(
        relay_id = relay.relay_id().as_str(),
        udp = ?relay.udp_addr(),
        wss = ?relay.wss_addr(),
        cert = cert_path.as_deref().unwrap_or("-"),
        "mock relay listening"
    );
    let signal = tokio::signal::ctrl_c().await;
    info!("shutting down");
    relay.shutdown().await;
    Ok(signal?)
}
