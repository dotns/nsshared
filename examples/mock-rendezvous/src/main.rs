//! `nsshared-mock-rendezvous` binary: placeholder until the server lands.

use std::process::ExitCode;

/// Prints usage and exits non-zero; the TLS server is not wired up yet.
fn main() -> ExitCode {
    eprintln!("usage: nsshared-mock-rendezvous (server not implemented yet)");
    ExitCode::FAILURE
}
