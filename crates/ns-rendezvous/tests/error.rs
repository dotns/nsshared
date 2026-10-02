//! Error codes: rendezvous §7.

use ns_rendezvous::{
    error::{ErrorCode, UnknownErrorCode},
    transport::{Response, decode_response, encode_response},
};

const NAMES: [&str; 15] = [
    "invalid_message",
    "invalid_actor",
    "invalid_code",
    "unknown_relay",
    "invalid_directory",
    "unknown_mailbox",
    "not_permitted",
    "wrong_stage",
    "capacity",
    "queue_full",
    "rate_limited",
    "conflict",
    "randomness",
    "storage",
    "unavailable",
];

#[test]
fn exactly_the_fifteen_codes() {
    for (code, name) in ErrorCode::ALL.into_iter().zip(NAMES) {
        assert_eq!(code.as_str(), name);
        assert_eq!(name.parse(), Ok(code));
        let text = encode_response(&Response::Error(code)).unwrap();
        assert_eq!(text, format!(r#"{{"result":"error","value":"{name}"}}"#));
        assert_eq!(decode_response(&text), Ok(Response::Error(code)));
        // Display text never echoes input; it is fixed per code.
        assert!(!code.to_string().is_empty());
    }
    for bad in [
        "",
        "Unavailable",
        "encryption",
        "invalid-message",
        "unavailable ",
    ] {
        assert_eq!(bad.parse::<ErrorCode>(), Err(UnknownErrorCode), "{bad}");
    }
}

#[test]
fn only_unavailable_moves_to_the_next_member() {
    for code in ErrorCode::ALL {
        assert_eq!(code.retry_on_next_member(), code == ErrorCode::Unavailable);
    }
}
