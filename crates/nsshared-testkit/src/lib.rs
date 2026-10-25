#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test support fails loudly on malformed fixtures"
)]

//! Test support for the NS shared crates; a development dependency only.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`vectors`](mod@vectors) | Reader for the generated `.vec` fixtures, with the [`vectors!`] and [`vector_fields!`] loaders |
//! | [`hex`] | Lowercase hex encoding and strict decoding |
//! | [`fixture`] | Seeded Ed25519 fixture authorities |

pub mod fixture;
pub mod hex;
pub mod vectors;

/// Parses the fixture `tests/vectors/<name>.vec` of the calling crate at compile time.
///
/// ```ignore
/// let cases = nsshared_testkit::vectors!("record");
/// ```
#[macro_export]
macro_rules! vectors {
    ($name:literal) => {
        $crate::vectors::parse(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/",
            $name,
            ".vec"
        )))
    };
}

/// Parses the fixture `tests/vectors/<name>.vec` of the calling crate into one
/// key-to-value map per vector, see [`vectors::fields`].
#[macro_export]
macro_rules! vector_fields {
    ($name:literal) => {
        $crate::vectors::fields(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/",
            $name,
            ".vec"
        )))
    };
}
