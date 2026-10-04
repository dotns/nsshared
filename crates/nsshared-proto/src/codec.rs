//! Canonical CBOR reader and writer (quick-v2 §12.1).
//!
//! Only the deterministic subset of RFC 8949 §4.2.1 used by NS is accepted: definite-length
//! arrays, shortest-form unsigned integers, byte and UTF-8 text strings, `null` and booleans.
//! Floats, tags, maps, negative integers, other simple values, indefinite lengths,
//! non-shortest heads and trailing bytes are rejected.

use thiserror::Error;

const MAJOR_UINT: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;

/// A non-canonical or malformed CBOR input (quick-v2 §12.1).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CborError {
    /// The input exceeds the caller-supplied maximum size.
    #[error("input of {length} bytes exceeds the {maximum}-byte limit")]
    TooLarge {
        /// Input length in bytes.
        length: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
    /// The input ends inside an item.
    #[error("input is truncated")]
    Truncated,
    /// An item head is not encoded in its shortest form.
    #[error("non-shortest item head")]
    NonShortest,
    /// An indefinite-length item or a break code.
    #[error("indefinite length")]
    IndefiniteLength,
    /// An item head uses a reserved additional-information value (28-30).
    #[error("reserved additional information")]
    Reserved,
    /// A floating-point value.
    #[error("floating-point value")]
    Float,
    /// A tagged item.
    #[error("tagged item")]
    Tag,
    /// A map.
    #[error("map")]
    Map,
    /// A negative integer.
    #[error("negative integer")]
    NegativeInteger,
    /// A simple value other than `false`, `true` or `null`.
    #[error("unsupported simple value")]
    UnsupportedSimple,
    /// A well-formed item of a different type than the field requires.
    #[error("unexpected item type")]
    UnexpectedType,
    /// An array whose length differs from the required arity or bound.
    #[error("array of {actual} items, expected {expected}")]
    ArrayLength {
        /// Required arity, or the bound for variable-length arrays.
        expected: u64,
        /// Actual element count.
        actual: u64,
    },
    /// A byte or text string whose length differs from the required length or bound.
    #[error("string of {actual} bytes, expected {expected}")]
    StringLength {
        /// Required length, or the bound for variable-length strings.
        expected: u64,
        /// Actual length in bytes.
        actual: u64,
    },
    /// A text string that is not valid UTF-8.
    #[error("text string is not valid UTF-8")]
    InvalidUtf8,
    /// Bytes follow the top-level item.
    #[error("trailing bytes after the top-level item")]
    TrailingBytes,
}

/// A strict canonical CBOR reader over one top-level item (quick-v2 §12.1).
pub struct CborReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> CborReader<'a> {
    /// Starts reading `input` after enforcing the caller's maximum size.
    pub fn new(input: &'a [u8], maximum: usize) -> Result<Self, CborError> {
        if input.len() > maximum {
            return Err(CborError::TooLarge {
                length: input.len(),
                maximum,
            });
        }
        Ok(Self { input, position: 0 })
    }

    /// Reads an array head with exactly `expected` elements.
    pub fn array(&mut self, expected: u64) -> Result<(), CborError> {
        let actual = self.typed_head(MAJOR_ARRAY)?;
        if actual == expected {
            Ok(())
        } else {
            Err(CborError::ArrayLength { expected, actual })
        }
    }

    /// Reads an array head with at most `maximum` elements and returns the count.
    pub fn array_up_to(&mut self, maximum: usize) -> Result<usize, CborError> {
        let actual = self.typed_head(MAJOR_ARRAY)?;
        usize::try_from(actual)
            .ok()
            .filter(|count| *count <= maximum)
            .ok_or(CborError::ArrayLength {
                expected: maximum as u64,
                actual,
            })
    }

    /// Reads an unsigned integer.
    pub fn uint(&mut self) -> Result<u64, CborError> {
        self.typed_head(MAJOR_UINT)
    }

    /// Reads a byte string of exactly `N` bytes.
    pub fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let length = self.typed_head(MAJOR_BYTES)?;
        if length != N as u64 {
            return Err(CborError::StringLength {
                expected: N as u64,
                actual: length,
            });
        }
        let mut output = [0; N];
        output.copy_from_slice(self.slice(N)?);
        Ok(output)
    }

    /// Reads a byte string of at most `maximum` bytes.
    pub fn bytes_up_to(&mut self, maximum: usize) -> Result<&'a [u8], CborError> {
        let length = self.string_length(MAJOR_BYTES, maximum)?;
        self.slice(length)
    }

    /// Reads a UTF-8 text string of at most `maximum` bytes.
    pub fn text_up_to(&mut self, maximum: usize) -> Result<&'a str, CborError> {
        let length = self.string_length(MAJOR_TEXT, maximum)?;
        std::str::from_utf8(self.slice(length)?).map_err(|_| CborError::InvalidUtf8)
    }

    /// Reads `false` or `true`.
    pub fn boolean(&mut self) -> Result<bool, CborError> {
        match self.simple()? {
            FALSE => Ok(false),
            TRUE => Ok(true),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Reads `null`.
    pub fn null(&mut self) -> Result<(), CborError> {
        match self.simple()? {
            NULL => Ok(()),
            _ => Err(CborError::UnexpectedType),
        }
    }

    /// Consumes a `null` and returns true, or returns false without consuming anything.
    pub fn take_null(&mut self) -> bool {
        if self.input.get(self.position) == Some(&NULL) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    /// Returns the bytes consumed so far.
    pub fn consumed(&self) -> &'a [u8] {
        self.input.get(..self.position).unwrap_or_default()
    }

    /// Requires that the whole input has been consumed.
    pub fn finish(self) -> Result<(), CborError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(CborError::TrailingBytes)
        }
    }

    fn string_length(&mut self, major: u8, maximum: usize) -> Result<usize, CborError> {
        let actual = self.typed_head(major)?;
        usize::try_from(actual)
            .ok()
            .filter(|length| *length <= maximum)
            .ok_or(CborError::StringLength {
                expected: maximum as u64,
                actual,
            })
    }

    fn simple(&mut self) -> Result<u8, CborError> {
        let initial = self.peek()?;
        let (major, _) = self.head()?;
        if major == MAJOR_SIMPLE {
            Ok(initial)
        } else {
            Err(CborError::UnexpectedType)
        }
    }

    fn typed_head(&mut self, major: u8) -> Result<u64, CborError> {
        let (actual, value) = self.head()?;
        if actual == major {
            Ok(value)
        } else {
            Err(CborError::UnexpectedType)
        }
    }

    /// Reads one item head, rejecting every form outside the canonical subset.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.take()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            MAJOR_NEGATIVE => return Err(CborError::NegativeInteger),
            MAJOR_MAP => return Err(CborError::Map),
            MAJOR_TAG => return Err(CborError::Tag),
            MAJOR_SIMPLE => {
                return match initial {
                    FALSE | TRUE | NULL => Ok((major, 0)),
                    0xf9..=0xfb => Err(CborError::Float),
                    0xff => Err(CborError::IndefiniteLength),
                    0xfc..=0xfe => Err(CborError::Reserved),
                    _ => Err(CborError::UnsupportedSimple),
                };
            }
            _ => {}
        }
        let (value, minimum) = match additional {
            0..=23 => (u64::from(additional), 0),
            24 => (u64::from(self.take()?), 24),
            25 => (u64::from(u16::from_be_bytes(self.array_bytes()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.array_bytes()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.array_bytes()?), 0x1_0000_0000),
            31 => return Err(CborError::IndefiniteLength),
            _ => return Err(CborError::Reserved),
        };
        if value < minimum {
            return Err(CborError::NonShortest);
        }
        Ok((major, value))
    }

    fn array_bytes<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let mut output = [0; N];
        output.copy_from_slice(self.slice(N)?);
        Ok(output)
    }

    fn slice(&mut self, length: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CborError::Truncated)?;
        let slice = self
            .input
            .get(self.position..end)
            .ok_or(CborError::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    fn peek(&self) -> Result<u8, CborError> {
        self.input
            .get(self.position)
            .copied()
            .ok_or(CborError::Truncated)
    }

    fn take(&mut self) -> Result<u8, CborError> {
        let byte = self.peek()?;
        self.position += 1;
        Ok(byte)
    }
}

/// A writer producing exactly the canonical form accepted by [`CborReader`] (quick-v2 §12.1).
#[derive(Default)]
pub struct CborWriter {
    output: Vec<u8>,
}

impl CborWriter {
    /// Starts an empty writer with `capacity` reserved bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
        }
    }

    /// Writes an array head of `length` elements.
    pub fn array(&mut self, length: usize) -> &mut Self {
        self.head(MAJOR_ARRAY, length as u64)
    }

    /// Writes an unsigned integer.
    pub fn uint(&mut self, value: u64) -> &mut Self {
        self.head(MAJOR_UINT, value)
    }

    /// Writes a byte string.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(MAJOR_BYTES, value.len() as u64);
        self.output.extend_from_slice(value);
        self
    }

    /// Writes a text string.
    pub fn text(&mut self, value: &str) -> &mut Self {
        self.head(MAJOR_TEXT, value.len() as u64);
        self.output.extend_from_slice(value.as_bytes());
        self
    }

    /// Writes `false` or `true`.
    pub fn boolean(&mut self, value: bool) -> &mut Self {
        self.output.push(if value { TRUE } else { FALSE });
        self
    }

    /// Writes `null`.
    pub fn null(&mut self) -> &mut Self {
        self.output.push(NULL);
        self
    }

    /// Returns the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.output
    }

    fn head(&mut self, major: u8, value: u64) -> &mut Self {
        let major = major << 5;
        match value {
            0..=23 => self.output.push(major | value as u8),
            24..=0xff => self.output.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                self.output.push(major | 25);
                self.output.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.output.push(major | 26);
                self.output.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.output.push(major | 27);
                self.output.extend_from_slice(&value.to_be_bytes());
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(input: &[u8]) -> Result<(), CborError> {
        let mut reader = CborReader::new(input, 64)?;
        reader.array(6)?;
        let _ = reader.uint()?;
        let _ = reader.boolean()?;
        reader.null()?;
        let _ = reader.text_up_to(8)?;
        let _ = reader.bytes_up_to(8)?;
        assert!(reader.take_null());
        reader.finish()
    }

    #[test]
    fn writer_output_is_accepted_by_the_reader() {
        for value in [
            0,
            23,
            24,
            0xff,
            0x100,
            0xffff,
            0x1_0000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut writer = CborWriter::with_capacity(16);
            writer.uint(value);
            let encoded = writer.into_bytes();
            let mut reader = CborReader::new(&encoded, 16).unwrap();
            assert_eq!(reader.uint(), Ok(value));
            reader.finish().unwrap();
        }
        let mut writer = CborWriter::default();
        writer
            .array(6)
            .uint(7)
            .boolean(true)
            .null()
            .text("ok")
            .bytes(&[1, 2])
            .null();
        let encoded = writer.into_bytes();
        assert_eq!(
            encoded,
            [0x86, 0x07, 0xf5, 0xf6, 0x62, b'o', b'k', 0x42, 1, 2, 0xf6]
        );
        assert_eq!(read_all(&encoded), Ok(()));
    }

    #[test]
    fn refutation_simple_values() {
        let mut reader = CborReader::new(&[0xf6], 1).unwrap();
        assert_eq!(reader.boolean(), Err(CborError::UnexpectedType));
        let mut reader = CborReader::new(&[0xf5], 1).unwrap();
        assert_eq!(reader.null(), Err(CborError::UnexpectedType));
        let mut reader = CborReader::new(&[0xf7], 1).unwrap();
        assert_eq!(reader.null(), Err(CborError::UnsupportedSimple));
        let mut reader = CborReader::new(&[0xf8, 0x20], 2).unwrap();
        assert_eq!(reader.boolean(), Err(CborError::UnsupportedSimple));
        let mut reader = CborReader::new(&[0x01], 1).unwrap();
        assert_eq!(reader.boolean(), Err(CborError::UnexpectedType));
    }

    #[test]
    fn refutation_size_and_string_bounds() {
        assert!(matches!(
            CborReader::new(&[0; 3], 2),
            Err(CborError::TooLarge {
                length: 3,
                maximum: 2
            })
        ));
        let mut reader = CborReader::new(&[0x62, 0xff, 0xfe], 3).unwrap();
        assert_eq!(reader.text_up_to(2), Err(CborError::InvalidUtf8));
        let mut reader = CborReader::new(&[0x43, 1, 2, 3], 4).unwrap();
        assert_eq!(
            reader.bytes_up_to(2),
            Err(CborError::StringLength {
                expected: 2,
                actual: 3
            })
        );
    }
}
