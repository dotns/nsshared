use crate::{KeyBinding, NameRecord, Revocation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CborError;

pub(crate) struct CborReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> CborReader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) fn array(&mut self, expected: u64) -> Result<(), CborError> {
        if self.array_len()? == expected {
            Ok(())
        } else {
            Err(CborError)
        }
    }

    pub(crate) fn array_len(&mut self) -> Result<u64, CborError> {
        let (major, value) = self.head()?;
        if major == 4 {
            Ok(value)
        } else {
            Err(CborError)
        }
    }

    pub(crate) fn uint(&mut self) -> Result<u64, CborError> {
        let (major, value) = self.head()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(CborError)
        }
    }

    pub(crate) fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        let (major, length) = self.head()?;
        if major != 2 || length != N as u64 {
            return Err(CborError);
        }
        let end = self
            .position
            .checked_add(N)
            .filter(|end| *end <= self.input.len())
            .ok_or(CborError)?;
        let mut output = [0; N];
        output.copy_from_slice(&self.input[self.position..end]);
        self.position = end;
        Ok(output)
    }

    pub(crate) fn text(&mut self) -> Result<String, CborError> {
        self.text_with_maximum(usize::MAX)
    }

    pub(crate) fn text_with_maximum(&mut self, maximum: usize) -> Result<String, CborError> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(CborError);
        }
        let length = usize::try_from(length).map_err(|_| CborError)?;
        if length > maximum {
            return Err(CborError);
        }
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or(CborError)?;
        let text = std::str::from_utf8(&self.input[self.position..end])
            .map_err(|_| CborError)?
            .to_owned();
        self.position = end;
        Ok(text)
    }

    pub(crate) fn bytes_with_maximum(&mut self, maximum: usize) -> Result<Vec<u8>, CborError> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(CborError);
        }
        let length = usize::try_from(length).map_err(|_| CborError)?;
        if length > maximum {
            return Err(CborError);
        }
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or(CborError)?;
        let output = self.input[self.position..end].to_vec();
        self.position = end;
        Ok(output)
    }

    pub(crate) fn boolean(&mut self) -> Result<bool, CborError> {
        match self.take()? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(CborError),
        }
    }

    pub(crate) fn optional_uint(&mut self) -> Result<Option<u64>, CborError> {
        if self.peek() == Some(0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.uint().map(Some)
        }
    }

    pub(crate) fn optional_text(&mut self) -> Result<Option<String>, CborError> {
        if self.peek() == Some(0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.text().map(Some)
        }
    }

    pub(crate) fn optional_bytes32(&mut self) -> Result<Option<[u8; 32]>, CborError> {
        if self.peek() == Some(0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.fixed_bytes().map(Some)
        }
    }

    pub(crate) fn null(&mut self) -> Result<(), CborError> {
        if self.take()? == 0xf6 {
            Ok(())
        } else {
            Err(CborError)
        }
    }

    pub(crate) fn binding(&mut self) -> Result<KeyBinding, CborError> {
        let start = self.position;
        self.array(8)?;
        let _ = self.uint()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.uint()?;
        let _ = self.uint()?;
        let _ = self.uint()?;
        let _ = self.fixed_bytes::<64>()?;
        KeyBinding::decode(&self.input[start..self.position]).map_err(|_| CborError)
    }

    pub(crate) fn revocation(&mut self) -> Result<Revocation, CborError> {
        let start = self.position;
        self.array(6)?;
        let _ = self.uint()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.uint()?;
        let _ = self.uint()?;
        let _ = self.fixed_bytes::<64>()?;
        Revocation::decode(&self.input[start..self.position]).map_err(|_| CborError)
    }

    pub(crate) fn name_record(&mut self) -> Result<NameRecord, CborError> {
        let start = self.position;
        self.array(9)?;
        let _ = self.uint()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.fixed_bytes::<32>()?;
        let _ = self.text()?;
        let _ = self.uint()?;
        let _ = self.uint()?;
        let _ = self.uint()?;
        let _ = self.fixed_bytes::<64>()?;
        let _ = self.fixed_bytes::<64>()?;
        NameRecord::decode(&self.input[start..self.position]).map_err(|_| CborError)
    }

    pub(crate) fn finished(&self) -> bool {
        self.position == self.input.len()
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.take()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let (value, width) = match additional {
            value @ 0..=23 => (u64::from(value), 0),
            24 => (u64::from(self.take()?), 1),
            25 => (
                u64::from(u16::from_be_bytes([self.take()?, self.take()?])),
                2,
            ),
            26 => (
                u64::from(u32::from_be_bytes([
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                ])),
                4,
            ),
            27 => (
                u64::from_be_bytes([
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                    self.take()?,
                ]),
                8,
            ),
            _ => return Err(CborError),
        };
        let minimal = match width {
            0 => true,
            1 => value >= 24,
            2 => value > u64::from(u8::MAX),
            4 => value > u64::from(u16::MAX),
            8 => value > u64::from(u32::MAX),
            _ => false,
        };
        if minimal {
            Ok((major, value))
        } else {
            Err(CborError)
        }
    }

    fn take(&mut self) -> Result<u8, CborError> {
        let value = self.peek().ok_or(CborError)?;
        self.position += 1;
        Ok(value)
    }
}
