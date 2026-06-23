//! Deterministic AWS `SigV4`-style canonicalization for NSGW signed URLs.
//!
//! The signer (NSD admin endpoint) and the verifier (NSGW `ext_authz`) MUST
//! agree on the canonical request and the string-to-sign **byte for byte**, or a
//! freshly minted URL will fail verification. This module is the single source
//! of that construction: it is pure and deterministic and holds **no secret or
//! HMAC material** — only the public string both sides feed into HMAC-SHA256.
//!
//! Canonicalization follows `SigV4` verbatim — percent-encode then sort the
//! query (excluding the signature parameter), lowercase the host (dropping the
//! scheme's default port), sign the path as real bytes without normalization,
//! and treat the GET/HEAD payload as `UNSIGNED-PAYLOAD` — so the canonicalization
//! edge cases are solved the way AWS already solved them.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, percent_encode};
use sha2::{Digest as _, Sha256};

/// `SigV4` percent-encoding set: encode every byte except the RFC 3986 unreserved
/// characters `A-Za-z0-9-_.~`. `percent_encoding` emits uppercase hex (`%2F`),
/// matching the `SigV4` rule.
const SIGV4_UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Algorithm tag carried in [`ALGORITHM_PARAM`] and bound into the
/// string-to-sign; pins HMAC-SHA256 so a verifier never accepts another algo.
pub const ALGORITHM: &str = "NSGW-HMAC-SHA256";
/// Query parameter naming the signing algorithm.
pub const ALGORITHM_PARAM: &str = "X-Nsgw-Algorithm";
/// Query parameter naming the signing key id (selects the projected keyset).
pub const KID_PARAM: &str = "X-Nsgw-Kid";
/// Query parameter carrying the absolute Unix-seconds expiry deadline.
pub const EXPIRES_PARAM: &str = "X-Nsgw-Expires";
/// Query parameter carrying the hex signature; excluded from the canonical
/// query (a signature cannot sign itself).
pub const SIGNATURE_PARAM: &str = "X-Nsgw-Signature";
/// Trailing component of the string-to-sign scope (`<realm>/<route>/<this>`),
/// binding the signature to a specific realm and route.
pub const SCOPE_SERVICE: &str = "nsgw_signed_url";

/// Request facts a signed-URL signature binds. `query` is the raw query string
/// (the [`SIGNATURE_PARAM`], if present, is excluded during canonicalization);
/// `host` is raw and `scheme` drives the default-port rule; `path` is signed as
/// real bytes without normalization.
#[derive(Debug, Clone, Copy)]
pub struct SignedUrlScope<'a> {
    /// HTTP method (signed URLs are GET/HEAD).
    pub method: &'a str,
    /// URL scheme (`https`/`http`) for default-port handling on the host.
    pub scheme: &'a str,
    /// `Host`/`:authority` value, canonicalized before signing.
    pub host: &'a str,
    /// Request path, signed as real bytes (never normalized).
    pub path: &'a str,
    /// Raw query string; the signature parameter is excluded when canonicalized.
    pub query: &'a str,
    /// Realm the route resolved for; bound into the signed scope.
    pub realm_id: &'a str,
    /// Route the request matched; bound into the signed scope.
    pub route_id: &'a str,
    /// Absolute Unix-seconds expiry bound into the string-to-sign.
    pub expires_at: u64,
}

/// Percent-encode `value` with the `SigV4` unreserved set (uppercase hex).
#[must_use]
pub fn encode_sigv4(value: &[u8]) -> String {
    percent_encode(value, SIGV4_UNRESERVED).to_string()
}

/// Split a raw request target (`path?query`) into the path bytes — signed
/// verbatim, never normalized — and the query string. A target without `?` has
/// an empty query.
#[must_use]
pub fn split_request_target(path_and_query: &str) -> (&str, &str) {
    path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query))
}

/// Percent-decode each `name=value` pair of a query string into raw bytes,
/// preserving order and duplicates. `+` is NOT folded to a space — that is
/// form-encoding, not RFC 3986 / `SigV4`. A segment without `=` has an empty
/// value.
#[must_use]
pub fn decode_query_pairs(query: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let (name, value) = segment.split_once('=').unwrap_or((segment, ""));
            (
                percent_decode_str(name).collect(),
                percent_decode_str(value).collect(),
            )
        })
        .collect()
}

/// Build the `SigV4` canonical query string: percent-encode each decoded
/// name/value (uppercase hex), drop [`SIGNATURE_PARAM`], then sort by encoded
/// name and value. Duplicate names are kept, ordered by value.
#[must_use]
pub fn canonical_query_string(query: &str) -> String {
    let mut encoded: Vec<(String, String)> = decode_query_pairs(query)
        .into_iter()
        .filter(|(name, _)| name.as_slice() != SIGNATURE_PARAM.as_bytes())
        .map(|(name, value)| (encode_sigv4(&name), encode_sigv4(&value)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonicalize the host for signing: lowercase, and omit the default port for
/// the scheme (`443` for https, `80` for http). A non-default port is kept and
/// signed.
#[must_use]
pub fn canonical_host(host: &str, scheme: &str) -> String {
    let mut lowered = host.trim().to_ascii_lowercase();
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        ":80"
    } else {
        ":443"
    };
    if lowered.ends_with(default_port) {
        lowered.truncate(lowered.len() - default_port.len());
    }
    lowered
}

/// Assemble the `SigV4` canonical request. The only signed header is `host`, and
/// the GET/HEAD payload is `UNSIGNED-PAYLOAD`. The path is signed as real bytes.
#[must_use]
pub fn canonical_request(method: &str, path: &str, canonical_query: &str, host: &str) -> String {
    format!("{method}\n{path}\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD")
}

/// Assemble the string-to-sign for `scope`: the `SigV4` canonical request hashed
/// (lowercase-hex SHA-256, per `SigV4`) and bound to the algorithm, the URL
/// expiry, and the `<realm>/<route>/nsgw_signed_url` scope. Deterministic and
/// secret-free — the signer HMACs the result and the verifier recomputes and
/// constant-time compares it.
#[must_use]
pub fn string_to_sign(scope: &SignedUrlScope<'_>) -> String {
    let canonical_query = canonical_query_string(scope.query);
    let host = canonical_host(scope.host, scope.scheme);
    let canonical_request = canonical_request(scope.method, scope.path, &canonical_query, &host);
    let hashed = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    format!(
        "{ALGORITHM}\n{}\n{}/{}/{SCOPE_SERVICE}\n{hashed}",
        scope.expires_at, scope.realm_id, scope.route_id,
    )
}

/// Build the raw control query a signer emits and signs over: [`ALGORITHM_PARAM`],
/// [`KID_PARAM`], [`EXPIRES_PARAM`], then any `extra` signed parameters, each
/// percent-encoded ([`encode_sigv4`]) and joined with `&` in insertion order.
/// The signature parameter is appended only after signing. The verifier
/// re-sorts via [`canonical_query_string`], so insertion order is irrelevant to
/// verification — it only fixes the bytes the client sends back.
#[must_use]
pub fn signing_query(kid: &str, expires_at: u64, extra: &[(String, String)]) -> String {
    let mut params: Vec<(String, String)> = vec![
        (ALGORITHM_PARAM.to_owned(), ALGORITHM.to_owned()),
        (KID_PARAM.to_owned(), kid.to_owned()),
        (EXPIRES_PARAM.to_owned(), expires_at.to_string()),
    ];
    params.extend(extra.iter().cloned());
    params
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                encode_sigv4(name.as_bytes()),
                encode_sigv4(value.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Relocated from the INGRESS-062 verifier: these pin the shared
    // canonicalization rules now that both sides depend on them.

    #[test]
    fn canonical_query_string_encodes_sorts_and_excludes_signature() {
        let query = "X-Nsgw-Kid=sig-1&X-Nsgw-Expires=1781744400\
            &X-Nsgw-Algorithm=NSGW-HMAC-SHA256&X-Nsgw-Signature=abcd&b=2&a=1";
        assert_eq!(
            canonical_query_string(query),
            "X-Nsgw-Algorithm=NSGW-HMAC-SHA256&X-Nsgw-Expires=1781744400\
             &X-Nsgw-Kid=sig-1&a=1&b=2"
        );
    }

    #[test]
    fn canonical_query_string_uses_uppercase_hex_and_keeps_plus() {
        // `+` is a literal byte (not a space); `%20`/`%2F` survive as uppercase.
        assert_eq!(canonical_query_string("k=a+b%20c%2Fd"), "k=a%2Bb%20c%2Fd");
    }

    #[test]
    fn canonical_host_lowercases_and_strips_default_port() {
        assert_eq!(
            canonical_host("Files.Example.COM", "https"),
            "files.example.com"
        );
        assert_eq!(
            canonical_host("files.example.com:443", "https"),
            "files.example.com"
        );
        assert_eq!(
            canonical_host("files.example.com:8443", "https"),
            "files.example.com:8443"
        );
        assert_eq!(
            canonical_host("files.example.com:80", "http"),
            "files.example.com"
        );
        // 443 is non-default for http, so it stays signed.
        assert_eq!(
            canonical_host("files.example.com:443", "http"),
            "files.example.com:443"
        );
        // An empty scheme falls back to the https default-port rule.
        assert_eq!(canonical_host("files.example.com", ""), "files.example.com");
    }

    #[test]
    fn canonical_request_has_sigv4_shape() {
        assert_eq!(
            canonical_request(
                "GET",
                "/download/file.bin",
                "X-Nsgw-Kid=sig-1",
                "files.example.com"
            ),
            "GET\n/download/file.bin\nX-Nsgw-Kid=sig-1\nhost:files.example.com\n\nhost\nUNSIGNED-PAYLOAD"
        );
    }

    #[test]
    fn signing_query_orders_control_params_then_extra() {
        let extra = vec![("response-content-type".to_owned(), "text/plain".to_owned())];
        assert_eq!(
            signing_query("sig-1", 1_781_744_400, &extra),
            "X-Nsgw-Algorithm=NSGW-HMAC-SHA256&X-Nsgw-Kid=sig-1&X-Nsgw-Expires=1781744400\
             &response-content-type=text%2Fplain"
        );
    }

    fn scope_for<'a>(query: &'a str, route_id: &'a str) -> SignedUrlScope<'a> {
        SignedUrlScope {
            method: "GET",
            scheme: "https",
            host: "files.example.com",
            path: "/download/file.bin",
            query,
            realm_id: "realm-a",
            route_id,
            expires_at: 1_781_744_400,
        }
    }

    #[test]
    fn string_to_sign_has_algorithm_expiry_scope_and_hash_lines() {
        let query = signing_query("sig-1", 1_781_744_400, &[]);
        let sts = string_to_sign(&scope_for(&query, "route-a"));
        let mut lines = sts.split('\n');
        assert_eq!(lines.next(), Some(ALGORITHM));
        assert_eq!(lines.next(), Some("1781744400"));
        assert_eq!(lines.next(), Some("realm-a/route-a/nsgw_signed_url"));
        // The final line is the lowercase-hex SHA-256 of the canonical request.
        let hashed = lines.next().expect("hash line");
        assert_eq!(hashed.len(), 64);
        assert!(
            hashed
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn string_to_sign_is_independent_of_signed_query_param_order() {
        // The signer may emit extra params in any order; the verifier re-sorts,
        // so the string-to-sign — and thus the signature — is identical.
        let a = signing_query(
            "sig-1",
            1_781_744_400,
            &[
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned()),
            ],
        );
        let b = signing_query(
            "sig-1",
            1_781_744_400,
            &[
                ("b".to_owned(), "2".to_owned()),
                ("a".to_owned(), "1".to_owned()),
            ],
        );
        assert_ne!(a, b, "raw insertion order differs");
        assert_eq!(
            string_to_sign(&scope_for(&a, "route-a")),
            string_to_sign(&scope_for(&b, "route-a")),
            "canonicalization must erase param order"
        );
    }

    #[test]
    fn string_to_sign_binds_route_scope() {
        let query = signing_query("sig-1", 1_781_744_400, &[]);
        assert_ne!(
            string_to_sign(&scope_for(&query, "route-a")),
            string_to_sign(&scope_for(&query, "route-b")),
            "different routes must produce different strings-to-sign"
        );
    }
}
