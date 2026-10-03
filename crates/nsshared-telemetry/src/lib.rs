#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Telemetry conventions shared by NS and the components it talks to.
//!
//! - [`subscriber`]: `tracing` subscriber setup (text or JSON, an env filter
//!   with a default directive) as composable pieces, so a binary can add its
//!   own layers (for example an OpenTelemetry layer) next to them.
//! - [`redact`]: the sensitive field names and the [`Redacted`] wrapper.
//! - [`labels`]: metric label keys and values shared with NS.
//!
//! The crate carries no exporter and no OpenTelemetry dependency.
//!
//! ```no_run
//! use nsshared_telemetry::{LogFormat, SubscriberConfig};
//!
//! # fn main() -> Result<(), nsshared_telemetry::TelemetryError> {
//! nsshared_telemetry::init(&SubscriberConfig::new().format(LogFormat::Json))?;
//! # Ok(())
//! # }
//! ```

pub mod labels;
pub mod redact;
pub mod subscriber;

pub use redact::{REDACTED, Redacted, SENSITIVE_FIELDS, redacted};
pub use subscriber::{LogFormat, SubscriberConfig, TelemetryError, fmt_layer, init};
