//! Bounded deterministic CBOR subset used by service control; defined in `nsshared-codec`.

pub use nsshared_codec::cbor::value::{
    MAX_WIRE_BYTES, Value, ValueError as CborError, decode_canonical, encode_canonical,
};
