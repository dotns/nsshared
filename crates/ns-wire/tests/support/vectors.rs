//! Parser for the generated `.vec` fixtures written by `tools/vectors/generate.py`.
//!
//! Header lines start with `#`, vectors are separated by one blank line and every other
//! line is `key = value`: bytes as lowercase hex, integers in decimal, text verbatim.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    dead_code,
    reason = "test fixture helpers; each test binary uses a subset"
)]

use std::{fs, path::PathBuf};

/// One vector: its ordered `key = value` lines, starting with `name`.
#[derive(Debug)]
pub struct Vector {
    lines: Vec<(String, String)>,
}

impl Vector {
    /// The `name` line.
    pub fn name(&self) -> &str {
        &self.lines[0].1
    }

    /// The single value of `key`; panics when it is missing or repeated.
    pub fn get(&self, key: &str) -> &str {
        match self.all(key).as_slice() {
            [value] => value,
            values => panic!(
                "{}: expected one `{key}`, found {}",
                self.name(),
                values.len()
            ),
        }
    }

    /// The single value of `key`, or `None` when it is absent.
    pub fn opt(&self, key: &str) -> Option<&str> {
        match self.all(key).as_slice() {
            [] => None,
            _ => Some(self.get(key)),
        }
    }

    /// Every value of `key` in file order.
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.lines
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The hex bytes of `key`.
    pub fn hex(&self, key: &str) -> Vec<u8> {
        decode_hex(self.get(key))
            .unwrap_or_else(|| panic!("{}: `{key}` is not lowercase hex", self.name()))
    }

    /// The hex bytes of `key` as a fixed-size array.
    pub fn hex_array<const N: usize>(&self, key: &str) -> [u8; N] {
        self.hex(key)
            .try_into()
            .unwrap_or_else(|_| panic!("{}: `{key}` is not {N} bytes", self.name()))
    }

    /// The decimal integer of `key`.
    pub fn u64(&self, key: &str) -> u64 {
        self.get(key)
            .parse()
            .unwrap_or_else(|_| panic!("{}: `{key}` is not a u64", self.name()))
    }

    /// True for a negative vector (`expect = reject`).
    pub fn is_reject(&self) -> bool {
        match self.opt("expect") {
            None => false,
            Some("reject") => true,
            Some(other) => panic!("{}: unknown expect `{other}`", self.name()),
        }
    }

    /// The `reason` of a negative vector.
    pub fn reason(&self) -> &str {
        self.get("reason")
    }
}

/// Decodes lowercase hex.
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// Parses fixture text into vectors, panicking on any malformed line.
pub fn parse(text: &str) -> Vec<Vector> {
    let mut vectors = Vec::new();
    let mut lines: Vec<(String, String)> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.starts_with('#') {
            assert!(
                vectors.is_empty() && lines.is_empty(),
                "line {}: comment after the header",
                number + 1
            );
            continue;
        }
        if line.is_empty() {
            if !lines.is_empty() {
                vectors.push(Vector {
                    lines: std::mem::take(&mut lines),
                });
            }
            continue;
        }
        let (key, value) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("line {}: not `key = value`", number + 1));
        assert!(
            !lines.is_empty() || key == "name",
            "line {}: a vector must start with `name`",
            number + 1
        );
        lines.push((key.to_owned(), value.to_owned()));
    }
    if !lines.is_empty() {
        vectors.push(Vector { lines });
    }
    vectors
}

/// Loads `tests/fixtures/vectors/<group>.vec` of this crate.
pub fn load(group: &str) -> Vec<Vector> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", "vectors"]
        .iter()
        .collect::<PathBuf>()
        .join(format!("{group}.vec"));
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("{}: {err}; run `just vectors`", path.display()));
    let vectors = parse(&text);
    assert!(!vectors.is_empty(), "{}: no vectors", path.display());
    vectors
}
