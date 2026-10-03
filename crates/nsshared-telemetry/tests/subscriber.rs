//! Subscriber setup: filter defaults, filter errors, JSON output and `init`.

use std::{
    io,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use nsshared_telemetry::{LogFormat, SubscriberConfig, TelemetryError, fmt_layer, init, redacted};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt};

// Never set, so the tests do not race on RUST_LOG or on each other.
const UNSET_VAR: &str = "NSSHARED_TELEMETRY_TEST_UNSET_FILTER";

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn bytes(&self) -> MutexGuard<'_, Vec<u8>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }
}

impl io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'w> MakeWriter<'w> for Buffer {
    type Writer = Self;

    fn make_writer(&'w self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn log_format_parses_text_and_json() {
    assert_eq!("text".parse::<LogFormat>().unwrap(), LogFormat::Text);
    assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
    assert!(matches!(
        "yaml".parse::<LogFormat>(),
        Err(TelemetryError::UnknownLogFormat(text)) if text == "yaml"
    ));
}

#[test]
fn default_filter_applies_when_var_unset() {
    let config = SubscriberConfig::new()
        .filter_var(UNSET_VAR)
        .default_filter("warn");
    let filter = config.env_filter().unwrap();
    assert_eq!(filter.max_level_hint(), Some(LevelFilter::WARN));
}

#[test]
fn default_filter_applies_when_value_empty() {
    let config = SubscriberConfig::new().default_filter("error");
    for value in [None, Some(""), Some("  ")] {
        let filter = config.env_filter_from(value).unwrap();
        assert_eq!(filter.max_level_hint(), Some(LevelFilter::ERROR));
    }
    let filter = config.env_filter_from(Some("debug")).unwrap();
    assert_eq!(filter.max_level_hint(), Some(LevelFilter::DEBUG));
}

#[test]
fn invalid_directive_is_an_error() {
    let config = SubscriberConfig::new().filter_var(UNSET_VAR);
    assert!(matches!(
        config.env_filter_from(Some("nsshared=loud")),
        Err(TelemetryError::InvalidFilter { origin, .. }) if origin == UNSET_VAR
    ));
    let config = config.default_filter("nsshared=loud");
    assert!(matches!(
        config.env_filter(),
        Err(TelemetryError::InvalidFilter { origin, .. }) if origin == "default filter"
    ));
}

#[test]
fn json_format_writes_json_lines() {
    let buffer = Buffer::default();
    let filter = SubscriberConfig::new()
        .default_filter("info")
        .env_filter_from(None)
        .unwrap();
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer(LogFormat::Json, buffer.clone()));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(remote_ip = %redacted("192.0.2.7"), "peer connected");
        tracing::debug!("filtered out");
        tracing::warn!(count = 3, "second line");
    });

    let output = buffer.contents();
    assert!(!output.contains("192.0.2.7"));
    let lines: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["level"], "INFO");
    assert_eq!(lines[0]["fields"]["message"], "peer connected");
    assert_eq!(lines[0]["fields"]["remote_ip"], "[redacted]");
    assert_eq!(lines[1]["level"], "WARN");
    assert_eq!(lines[1]["fields"]["count"], 3);
}

#[test]
fn text_format_writes_plain_lines() {
    let buffer = Buffer::default();
    let subscriber =
        tracing_subscriber::registry().with(fmt_layer(LogFormat::Text, buffer.clone()));
    tracing::subscriber::with_default(subscriber, || tracing::info!("plain"));
    let output = buffer.contents();
    assert!(output.contains("INFO"));
    assert!(output.contains("plain"));
    assert!(serde_json::from_str::<serde_json::Value>(output.trim()).is_err());
}

#[test]
fn second_init_fails() {
    let config = SubscriberConfig::new().filter_var(UNSET_VAR);
    init(&config).unwrap();
    assert!(matches!(init(&config), Err(TelemetryError::Init(_))));
}
