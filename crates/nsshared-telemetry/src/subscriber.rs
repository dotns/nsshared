//! `tracing` subscriber setup.
//!
//! [`init`] installs `registry().with(filter).with(fmt layer)` as the global
//! default. Binaries that need more layers build the same stack from
//! [`SubscriberConfig::env_filter`] and [`fmt_layer`] and install it
//! themselves.

use std::{env, str::FromStr};

use thiserror::Error;
use tracing::Subscriber;
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::ParseError,
    fmt::MakeWriter,
    layer::SubscriberExt,
    registry::LookupSpan,
    util::{SubscriberInitExt, TryInitError},
};

/// The default environment variable holding the filter directives.
pub const DEFAULT_FILTER_VAR: &str = "RUST_LOG";

/// The default filter directive, used when the variable is unset or empty.
pub const DEFAULT_FILTER: &str = "info";

/// A telemetry setup failure.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The log format is neither `text` nor `json`.
    #[error("unknown log format {0:?}, expected \"text\" or \"json\"")]
    UnknownLogFormat(String),
    /// The filter variable holds a value that is not valid Unicode.
    #[error("{var} is not valid unicode")]
    NonUnicodeFilter {
        /// The variable name.
        var: String,
    },
    /// A filter directive does not parse.
    #[error("invalid filter directive in {origin}: {source}")]
    InvalidFilter {
        /// The variable name, or `default filter` for the configured default.
        origin: String,
        /// The parse failure.
        #[source]
        source: ParseError,
    },
    /// A global subscriber is already installed.
    #[error("cannot install the global subscriber: {0}")]
    Init(#[from] TryInitError),
}

/// The log line format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogFormat {
    /// Human-readable text lines.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

impl FromStr for LogFormat {
    type Err = TelemetryError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(TelemetryError::UnknownLogFormat(text.to_owned())),
        }
    }
}

/// Subscriber settings: the log format, the filter variable and the default
/// filter directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriberConfig {
    format: LogFormat,
    filter_var: String,
    default_filter: String,
}

impl Default for SubscriberConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            filter_var: DEFAULT_FILTER_VAR.to_owned(),
            default_filter: DEFAULT_FILTER.to_owned(),
        }
    }
}

impl SubscriberConfig {
    /// Text format, filter from `RUST_LOG`, default filter `info`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the log format.
    #[must_use]
    pub fn format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Sets the environment variable holding the filter directives.
    #[must_use]
    pub fn filter_var(mut self, var: impl Into<String>) -> Self {
        self.filter_var = var.into();
        self
    }

    /// Sets the directive used when the filter variable is unset or empty.
    #[must_use]
    pub fn default_filter(mut self, directive: impl Into<String>) -> Self {
        self.default_filter = directive.into();
        self
    }

    /// Returns the configured log format.
    #[must_use]
    pub const fn log_format(&self) -> LogFormat {
        self.format
    }

    /// Builds the filter from the filter variable, falling back to the
    /// default filter when the variable is unset or empty.
    pub fn env_filter(&self) -> Result<EnvFilter, TelemetryError> {
        match env::var_os(&self.filter_var) {
            None => self.env_filter_from(None),
            Some(value) => match value.to_str() {
                Some(value) => self.env_filter_from(Some(value)),
                None => Err(TelemetryError::NonUnicodeFilter {
                    var: self.filter_var.clone(),
                }),
            },
        }
    }

    /// Builds the filter from `value`, the content of the filter variable;
    /// `None` or an empty value selects the default filter.
    pub fn env_filter_from(&self, value: Option<&str>) -> Result<EnvFilter, TelemetryError> {
        let (directives, origin) = match value {
            Some(value) if !value.trim().is_empty() => (value, self.filter_var.as_str()),
            _ => (self.default_filter.as_str(), "default filter"),
        };
        EnvFilter::builder()
            .parse(directives)
            .map_err(|source| TelemetryError::InvalidFilter {
                origin: origin.to_owned(),
                source,
            })
    }
}

/// Returns the boxed fmt layer for `format`, writing to `writer`.
pub fn fmt_layer<S, W>(format: LogFormat, writer: W) -> Box<dyn Layer<S> + Send + Sync + 'static>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer = tracing_subscriber::fmt::layer().with_writer(writer);
    match format {
        LogFormat::Text => layer.boxed(),
        LogFormat::Json => layer.json().boxed(),
    }
}

/// Installs `registry().with(filter).with(fmt layer)` as the global default
/// subscriber, writing to stdout.
///
/// Fails when the filter does not parse or a global subscriber is already
/// installed (a second call always fails).
pub fn init(config: &SubscriberConfig) -> Result<(), TelemetryError> {
    tracing_subscriber::registry()
        .with(config.env_filter()?)
        .with(fmt_layer(config.format, std::io::stdout))
        .try_init()?;
    Ok(())
}
