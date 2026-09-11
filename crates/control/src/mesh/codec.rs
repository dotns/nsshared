use std::collections::BTreeMap;

use ciborium::value::Value;

use super::{Error, MAX_CONTROL_FRAME};

pub(super) trait Field: Sized {
    fn to_value(&self) -> Value;
    fn from_value(value: Value) -> Result<Self, Error>;
    fn sign_into(&self, out: &mut Vec<u8>);
    fn missing() -> Result<Self, Error> {
        Err(Error::Payload("missing field"))
    }
}

impl Field for u64 {
    fn to_value(&self) -> Value {
        Value::Integer((*self).into())
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        match value {
            Value::Integer(value) => value
                .try_into()
                .map_err(|_| Error::Payload("unsigned integer")),
            _ => Err(Error::Payload("unsigned integer")),
        }
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }
}

impl Field for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        match value {
            Value::Bool(value) => Ok(value),
            _ => Err(Error::Payload("boolean")),
        }
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}

impl<const N: usize> Field for [u8; N] {
    fn to_value(&self) -> Value {
        Value::Bytes(self.to_vec())
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        match value {
            Value::Bytes(value) => value.try_into().map_err(|_| Error::Payload("byte width")),
            _ => Err(Error::Payload("byte string")),
        }
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl Field for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Bytes(self.clone())
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        match value {
            Value::Bytes(value) => Ok(value),
            _ => Err(Error::Payload("byte string")),
        }
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        // Encoded fields are bounded by MAX_CONTROL_FRAME before signing.
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        out.extend_from_slice(self);
    }
}

impl<T: Field> Field for Option<T> {
    fn to_value(&self) -> Value {
        self.as_ref().map_or(Value::Null, Field::to_value)
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        if matches!(value, Value::Null) {
            Ok(None)
        } else {
            T::from_value(value).map(Some)
        }
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                value.sign_into(out);
            }
        }
    }
}

impl Field for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        match value {
            Value::Text(value) => Ok(value),
            _ => Err(Error::Payload("UTF-8 string")),
        }
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.len() as u32).to_be_bytes());
        out.extend_from_slice(self.as_bytes());
    }
}

pub(super) fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    encode_with_limit(value, MAX_CONTROL_FRAME)
}

pub(super) fn encode_with_limit(value: &Value, limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|_| Error::Payload("CBOR encoding"))?;
    if out.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Value, Error> {
    decode_with_limit(bytes, MAX_CONTROL_FRAME)
}

pub(super) fn decode_with_limit(bytes: &[u8], limit: usize) -> Result<Value, Error> {
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    let mut input = bytes;
    let value: Value =
        ciborium::de::from_reader(&mut input).map_err(|_| Error::Payload("CBOR decoding"))?;
    if !input.is_empty() {
        return Err(Error::Payload("trailing bytes"));
    }
    // Ciborium emits definite lengths and shortest integers while preserving
    // map order, so this rejects indefinite/nonminimal forms without reparsing CBOR.
    if encode_with_limit(&value, limit)? != bytes {
        return Err(Error::Payload("noncanonical CBOR"));
    }
    validate_tree(&value, 0)?;
    Ok(value)
}

fn validate_tree(value: &Value, depth: usize) -> Result<(), Error> {
    if depth > 16 {
        return Err(Error::Payload("nesting limit"));
    }
    match value {
        Value::Map(entries) => {
            let mut seen = std::collections::BTreeSet::new();
            for (key, value) in entries {
                let key = u64::from_value(key.clone())?;
                if !seen.insert(key) {
                    return Err(Error::Payload("duplicate field"));
                }
                validate_tree(value, depth + 1)?;
            }
        }
        Value::Array(entries) => {
            for value in entries {
                validate_tree(value, depth + 1)?;
            }
        }
        Value::Tag(..) | Value::Float(_) => return Err(Error::Payload("unsupported CBOR value")),
        _ => {}
    }
    Ok(())
}

pub(super) fn fields(value: Value) -> Result<BTreeMap<u64, Value>, Error> {
    let Value::Map(entries) = value else {
        return Err(Error::Payload("integer map"));
    };
    let mut result = BTreeMap::new();
    for (key, value) in entries {
        if result.insert(u64::from_value(key)?, value).is_some() {
            return Err(Error::Payload("duplicate field"));
        }
    }
    if take::<u64>(&mut result, 0)? != 1 {
        return Err(Error::Payload("schema version"));
    }
    Ok(result)
}

pub(super) fn take<T: Field>(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<T, Error> {
    fields.remove(&key).map_or_else(T::missing, T::from_value)
}

macro_rules! payload {
    ($name:ident, $api:literal, { $( $number:literal => $field:ident : $ty:ty ),+ $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name { $(pub $field: $ty),+ }

        impl $name {
            pub const API: &'static str = $api;
            pub fn encode(&self) -> Result<Vec<u8>, super::Error> {
                self.validate()?;
                super::codec::encode(&super::codec::Field::to_value(self))
            }
            pub fn decode(bytes: &[u8]) -> Result<Self, super::Error> {
                super::codec::Field::from_value(super::codec::decode(bytes)?)
            }
        }

        impl super::codec::Field for $name {
            fn to_value(&self) -> ciborium::value::Value {
                ciborium::value::Value::Map(vec![
                    (0_u64.to_value(), 1_u64.to_value()),
                    $(($number.to_value(), self.$field.to_value())),+
                ])
            }
            fn from_value(value: ciborium::value::Value) -> Result<Self, super::Error> {
                let mut fields = super::codec::fields(value)?;
                let result = Self { $($field: super::codec::take(&mut fields, $number)?),+ };
                result.validate()?;
                Ok(result)
            }
            fn sign_into(&self, out: &mut Vec<u8>) {
                $(self.$field.sign_into(out);)+
            }
        }
    };
}
pub(super) use payload;
