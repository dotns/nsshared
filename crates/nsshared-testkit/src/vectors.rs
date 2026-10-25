//! Reader for the generated `.vec` fixtures written by `tools/vectors/generate.py`.
//!
//! Header lines start with `#`, vectors are separated by one blank line and every other
//! line is `key = value`: bytes as lowercase hex, integers in decimal, text verbatim.

use std::collections::BTreeMap;

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
        crate::hex::decode(self.get(key))
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

    /// The `true` / `false` text of `key`.
    pub fn bool(&self, key: &str) -> bool {
        match self.get(key) {
            "true" => true,
            "false" => false,
            other => panic!("{}: `{key}` is not a bool: {other}", self.name()),
        }
    }

    /// The hex bytes of `key`, or empty when the line is absent (fixtures cannot hold an
    /// empty value).
    pub fn hex_or_empty(&self, key: &str) -> Vec<u8> {
        self.opt(key).map_or_else(Vec::new, |_| self.hex(key))
    }

    /// Every line as a map from key to value; a repeated key keeps its last value.
    pub fn fields(&self) -> BTreeMap<&str, &str> {
        self.lines
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
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

/// Parses fixture text into one key-to-value map per vector, borrowing the text; a
/// repeated key keeps its last value. Validation is that of [`parse`].
pub fn fields(text: &str) -> Vec<BTreeMap<&str, &str>> {
    blocks(text)
        .into_iter()
        .map(|lines| lines.into_iter().collect())
        .collect()
}

/// Parses fixture text into vectors, panicking on any malformed line.
pub fn parse(text: &str) -> Vec<Vector> {
    blocks(text)
        .into_iter()
        .map(|lines| Vector {
            lines: lines
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        })
        .collect()
}

/// Splits fixture text into the `key = value` lines of each vector.
fn blocks(text: &str) -> Vec<Vec<(&str, &str)>> {
    let mut vectors = Vec::new();
    let mut lines: Vec<(&str, &str)> = Vec::new();
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
                vectors.push(std::mem::take(&mut lines));
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
        lines.push((key, value));
    }
    if !lines.is_empty() {
        vectors.push(lines);
    }
    vectors
}
