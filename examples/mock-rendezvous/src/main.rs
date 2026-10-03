//! `nsshared-mock-rendezvous`: a single-instance `/rendezvous/v1` relay over TLS WebSocket
//! (rendezvous §3; quick-v2 §7).
//!
//! Prints the authority and the served directory JSON on startup and runs until
//! interrupted.

use nsshared_mock_rendezvous::{Config, RendezvousServer, TlsSource};
use nsshared_proto::rendezvous::directory::Directory;
use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

const USAGE: &str = "usage: nsshared-mock-rendezvous [--listen <ip:port>] [--host <tls name>]
    [--advertise-ip <ip>]... [--relay-id <u16>] [--code <2 letters>]
    [--cert <pem> --key <pem> | --write-cert <path>] [--directory <json file>]

  --listen        listen address (default 127.0.0.1:8443)
  --host          TLS host name of the relay entry (default localhost)
  --advertise-ip  directory IP of the relay entry, repeatable (default the listen IP)
  --relay-id      directory relay id (default 1)
  --code          directory code (default MK)
  --cert, --key   PEM certificate chain and key (default a self-signed certificate)
  --write-cert    write the presented certificate PEM to this path
  --directory     serve this directory JSON instead of the single-entry default";

/// Parsed command line.
struct Args {
    config: Config,
    write_cert: Option<PathBuf>,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut config = Config::default();
    let mut write_cert = None;
    let mut certificate = None;
    let mut key = None;
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            return Ok(None);
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let invalid = || format!("invalid {flag} value");
        match flag.as_str() {
            "--listen" => config.listen = value.parse::<SocketAddr>().map_err(|_| invalid())?,
            "--host" => config.host = value,
            "--advertise-ip" => config
                .advertise_ips
                .push(value.parse().map_err(|_| invalid())?),
            "--relay-id" => {
                config.relay_id = value.parse().map_err(|_| invalid())?;
            }
            "--code" => config.code = value,
            "--cert" => certificate = Some(PathBuf::from(value)),
            "--key" => key = Some(PathBuf::from(value)),
            "--write-cert" => write_cert = Some(PathBuf::from(value)),
            "--directory" => {
                let text = std::fs::read_to_string(&value)
                    .map_err(|error| format!("reading {value}: {error}"))?;
                let directory: Directory = serde_json::from_str(&text)
                    .map_err(|error| format!("invalid directory {value}: {error}"))?;
                config.directory = Some(directory);
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    config.tls = match (certificate, key) {
        (Some(certificate), Some(key)) => TlsSource::Pem { certificate, key },
        (None, None) => TlsSource::SelfSigned,
        _ => return Err("--cert and --key go together".to_owned()),
    };
    Ok(Some(Args { config, write_cert }))
}

async fn run(args: Args) -> Result<(), String> {
    let (server, listener) = RendezvousServer::bind(args.config)
        .await
        .map_err(|error| error.to_string())?;
    if let Some(path) = &args.write_cert {
        std::fs::write(path, server.certificate_pem())
            .map_err(|error| format!("writing {}: {error}", path.display()))?;
    }
    let directory = server.directory().map_err(|error| error.to_string())?;
    let directory = serde_json::to_string(&directory).map_err(|error| error.to_string())?;
    println!("authority {}", server.authority().as_str());
    println!("directory {directory}");
    let stopper = server.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            stopper.shutdown();
        }
    });
    server.serve(listener).await;
    Ok(())
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("nsshared-mock-rendezvous: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("nsshared-mock-rendezvous: runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("nsshared-mock-rendezvous: {message}");
            ExitCode::FAILURE
        }
    }
}
