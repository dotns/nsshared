//! M6 value profile: bounded deterministic CBOR with maps, decoded into a [`Value`] tree.

use std::collections::HashSet;

use thiserror::Error;

use super::{
    ArgumentError, FALSE, MAJOR_ARRAY, MAJOR_BYTES, MAJOR_MAP, MAJOR_SIMPLE, MAJOR_TEXT,
    MAJOR_UINT, NULL, TRUE, read_argument, write_head,
};

/// Maximum accepted wire item length.
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 16_384;

/// Values allowed on the service-control wire. Maps use ASCII text keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// Unsigned integer.
    UInt(u64),
    /// Boolean.
    Bool(bool),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text.
    Text(String),
    /// Null.
    Null,
    /// Fixed-length array.
    Array(Vec<Self>),
    /// Fixed-length map.
    Map(Vec<(String, Self)>),
}

/// Invalid or noncanonical CBOR input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ValueError {
    /// Item is truncated.
    #[error("truncated CBOR")]
    Truncated,
    /// Item is larger than the wire limit.
    #[error("CBOR size limit exceeded")]
    TooLarge,
    /// Container is too deep or has too many members.
    #[error("CBOR container limit exceeded")]
    ContainerLimit,
    /// The value is outside the permitted deterministic subset.
    #[error("unsupported CBOR value")]
    Unsupported,
    /// UTF-8 or map key is invalid.
    #[error("invalid CBOR text or map key")]
    InvalidText,
    /// Duplicate map key.
    #[error("duplicate CBOR map key")]
    DuplicateKey,
    /// Input is not the unique deterministic representation.
    #[error("noncanonical CBOR")]
    Noncanonical,
}

/// Encodes a value, sorting map keys by encoded key length and then bytes.
///
/// # Errors
/// Returns an error for duplicate or non-ASCII map keys, excessive size or depth.
pub fn encode_canonical(value: &Value) -> Result<Vec<u8>, ValueError> {
    let mut output = Vec::new();
    encode_item(value, &mut output, 0)?;
    if output.len() > MAX_WIRE_BYTES {
        return Err(ValueError::TooLarge);
    }
    Ok(output)
}

/// Decodes one canonical value and verifies that its original bytes are the unique encoding.
///
/// # Errors
/// Returns an error for malformed, noncanonical or unsupported input.
pub fn decode_canonical(input: &[u8]) -> Result<Value, ValueError> {
    if input.len() > MAX_WIRE_BYTES {
        return Err(ValueError::TooLarge);
    }
    let mut cursor = Cursor { input, offset: 0 };
    let value = cursor.item(0)?;
    if cursor.offset != input.len() || encode_canonical(&value)?.as_slice() != input {
        return Err(ValueError::Noncanonical);
    }
    Ok(value)
}

fn encode_item(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), ValueError> {
    if depth > MAX_DEPTH {
        return Err(ValueError::ContainerLimit);
    }
    match value {
        Value::UInt(value) => write_head(output, MAJOR_UINT, *value),
        Value::Bool(value) => output.push(if *value { TRUE } else { FALSE }),
        Value::Bytes(value) => {
            write_head(output, MAJOR_BYTES, value.len() as u64);
            output.extend_from_slice(value);
        }
        Value::Text(value) => {
            write_head(output, MAJOR_TEXT, value.len() as u64);
            output.extend_from_slice(value.as_bytes());
        }
        Value::Null => output.push(NULL),
        Value::Array(items) => {
            if items.len() > MAX_ITEMS {
                return Err(ValueError::ContainerLimit);
            }
            write_head(output, MAJOR_ARRAY, items.len() as u64);
            for item in items {
                encode_item(item, output, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            if entries.len() > MAX_ITEMS {
                return Err(ValueError::ContainerLimit);
            }
            let mut ordered = Vec::with_capacity(entries.len());
            let mut seen = HashSet::with_capacity(entries.len());
            for (key, value) in entries {
                if !key.is_ascii() {
                    return Err(ValueError::InvalidText);
                }
                if !seen.insert(key) {
                    return Err(ValueError::DuplicateKey);
                }
                let mut encoded_key = Vec::new();
                write_head(&mut encoded_key, MAJOR_TEXT, key.len() as u64);
                encoded_key.extend_from_slice(key.as_bytes());
                ordered.push((encoded_key, value));
            }
            ordered.sort_unstable_by(|(left, _), (right, _)| {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            });
            write_head(output, MAJOR_MAP, ordered.len() as u64);
            for (key, value) in ordered {
                output.extend_from_slice(&key);
                encode_item(value, output, depth + 1)?;
            }
        }
    }
    if output.len() > MAX_WIRE_BYTES {
        return Err(ValueError::TooLarge);
    }
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ValueError> {
        let end = self.offset.checked_add(count).ok_or(ValueError::TooLarge)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(ValueError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    /// Bounds a container reservation by the members the remaining input can hold,
    /// each taking at least `member_bytes`.
    fn capacity(&self, length: usize, member_bytes: usize) -> usize {
        length.min((self.input.len() - self.offset) / member_bytes)
    }

    /// Reads a head argument; non-shortest forms are refused later by re-encoding.
    fn argument(&mut self, additional: u8) -> Result<u64, ValueError> {
        let rest = self.input.get(self.offset..).unwrap_or_default();
        let (value, _, used) = read_argument(additional, rest).map_err(|error| match error {
            ArgumentError::Truncated => ValueError::Truncated,
            ArgumentError::Indefinite | ArgumentError::Reserved => ValueError::Unsupported,
        })?;
        self.offset += used;
        Ok(value)
    }

    fn item(&mut self, depth: usize) -> Result<Value, ValueError> {
        if depth > MAX_DEPTH {
            return Err(ValueError::ContainerLimit);
        }
        let first = self.take(1)?[0];
        let major = first >> 5;
        let additional = first & 31;
        if major == MAJOR_SIMPLE {
            return match first {
                FALSE => Ok(Value::Bool(false)),
                TRUE => Ok(Value::Bool(true)),
                NULL => Ok(Value::Null),
                _ => Err(ValueError::Unsupported),
            };
        }
        if !matches!(major, MAJOR_UINT | MAJOR_BYTES..=MAJOR_MAP) {
            return Err(ValueError::Unsupported);
        }
        let argument = self.argument(additional)?;
        if major == MAJOR_UINT {
            return Ok(Value::UInt(argument));
        }
        let length = usize::try_from(argument).map_err(|_| ValueError::TooLarge)?;
        match major {
            MAJOR_BYTES => {
                if length > MAX_WIRE_BYTES {
                    return Err(ValueError::TooLarge);
                }
                Ok(Value::Bytes(self.take(length)?.to_vec()))
            }
            MAJOR_TEXT => {
                if length > MAX_WIRE_BYTES {
                    return Err(ValueError::TooLarge);
                }
                let text =
                    std::str::from_utf8(self.take(length)?).map_err(|_| ValueError::InvalidText)?;
                Ok(Value::Text(text.to_owned()))
            }
            MAJOR_ARRAY => {
                if length > MAX_ITEMS {
                    return Err(ValueError::ContainerLimit);
                }
                let mut items = Vec::with_capacity(self.capacity(length, 1));
                for _ in 0..length {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            MAJOR_MAP => {
                if length > MAX_ITEMS {
                    return Err(ValueError::ContainerLimit);
                }
                let capacity = self.capacity(length, 2);
                let mut entries = Vec::with_capacity(capacity);
                let mut seen = HashSet::with_capacity(capacity);
                for _ in 0..length {
                    let Value::Text(key) = self.item(depth + 1)? else {
                        return Err(ValueError::InvalidText);
                    };
                    if !key.is_ascii() {
                        return Err(ValueError::InvalidText);
                    }
                    if !seen.insert(key.clone()) {
                        return Err(ValueError::DuplicateKey);
                    }
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(ValueError::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_bounded_by_the_remaining_input() {
        let input = [0x99, 0x40, 0x00, 0x01, 0x02];
        let mut cursor = Cursor {
            input: &input,
            offset: 0,
        };
        cursor.take(3).unwrap();
        assert_eq!(cursor.capacity(MAX_ITEMS, 1), 2);
        assert_eq!(cursor.capacity(MAX_ITEMS, 2), 1);
        assert_eq!(cursor.capacity(1, 1), 1);
    }
}
