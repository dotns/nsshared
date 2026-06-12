//! OAuth2 Device Authorization Grant (RFC 8628) client.
//!
//! Used for interactive registration: prints a user-visible code, then polls
//! until the user approves the device in a browser.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::Error;

#[derive(Debug, Serialize)]
struct DeviceCodeRequest {
    client_id: String,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

#[derive(Debug, Serialize)]
struct DeviceTokenRequest {
    device_code: String,
    grant_type: String,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Request a device code and poll until the user approves, returning the access token.
///
/// Prints human-readable instructions to stdout so the user knows which URL and
/// code to use.  Polls at the server-specified interval until approved or expired.
pub async fn request_device_code_and_poll(base_url: &str) -> Result<String, Error> {
    let http = reqwest::Client::new();

    // Step 1: request device + user codes.
    let code_resp: DeviceCodeResponse = http
        .post(format!("{base_url}/api/v1/device/code"))
        .json(&DeviceCodeRequest {
            client_id: "nsio-connector".to_string(),
        })
        .send()
        .await?
        .json()
        .await?;

    let complete_uri = code_resp
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&code_resp.verification_uri);

    println!();
    println!("======================================================================");
    println!("  Device Authorization Required");
    println!();
    println!("  Open the following URL in your browser:");
    println!("    {complete_uri}");
    println!();
    println!("  Enter code: {}", code_resp.user_code);
    println!("  (expires in {} seconds)", code_resp.expires_in);
    println!("======================================================================");
    println!();

    info!(
        user_code = %code_resp.user_code,
        verification_uri = %code_resp.verification_uri,
        "waiting for device authorization"
    );

    let interval = Duration::from_secs(code_resp.interval.max(1));
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(code_resp.expires_in.saturating_add(5));

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Auth("device code expired".to_string()));
        }

        tokio::time::sleep(interval).await;

        let poll_resp: DeviceTokenResponse = http
            .post(format!("{base_url}/api/v1/device/token"))
            .json(&DeviceTokenRequest {
                device_code: code_resp.device_code.clone(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            })
            .send()
            .await?
            .json()
            .await?;

        // Note: nested if kept separate for Rust <1.88 compatibility (let-chains).
        #[allow(clippy::collapsible_if)]
        if let Some(token) = poll_resp.access_token {
            if !token.is_empty() {
                info!("device authorization approved");
                return Ok(token);
            }
        }

        match poll_resp.error.as_deref() {
            Some("authorization_pending") | Some("slow_down") | None => {
                // Still waiting — keep polling.
            }
            Some("expired_token") => {
                return Err(Error::Auth("device code expired".to_string()));
            }
            Some("access_denied") => {
                return Err(Error::Auth(
                    "device authorization denied by user".to_string(),
                ));
            }
            Some(other) => {
                return Err(Error::Auth(format!("device flow error: {other}")));
            }
        }
    }
}
