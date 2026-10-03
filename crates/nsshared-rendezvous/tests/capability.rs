//! Capability tokens: rendezvous §3.1.

use nsshared_rendezvous::{
    capability::{
        self, Capabilities, Capability, CapabilityError, MAILBOX, REGION, REGISTRY, UDP, WSS,
    },
    error::ErrorCode,
    transport::decode_response,
};

#[test]
fn known_tokens() {
    let names: Vec<_> = [UDP, WSS, MAILBOX, REGION, REGISTRY]
        .iter()
        .map(|token| token.as_str().to_owned())
        .collect();
    assert_eq!(names, ["udp", "wss", "mailbox", "region", "registry"]);
    assert_eq!(Capability::parse("mailbox"), Ok(MAILBOX));
}

#[test]
fn token_syntax() {
    for good in ["a", "0", "registry.v1", "x-y.z9", &"a".repeat(32)] {
        assert!(Capability::parse(good).is_ok(), "{good}");
    }
    for bad in ["", "UDP", "udp ", "u_d_p", "ü", "a/b", &"a".repeat(33)] {
        assert_eq!(Capability::parse(bad), Err(CapabilityError::Token), "{bad}");
    }
}

#[test]
fn unknown_tokens_are_kept_and_ignored() {
    let list = Capabilities::new(vec![
        Capability::parse("future").unwrap(),
        UDP,
        Capability::parse("other.v9").unwrap(),
    ])
    .unwrap();
    assert!(list.contains(&UDP));
    assert!(!list.contains(&MAILBOX));
    assert!(list.contains(&Capability::parse("future").unwrap()));
    assert_eq!(list.as_slice().len(), 3);
}

#[test]
fn at_most_sixteen_tokens() {
    let tokens = |count: usize| -> Vec<Capability> {
        (0..count)
            .map(|index| Capability::parse(&format!("t{index}")).unwrap())
            .collect()
    };
    assert!(Capabilities::new(tokens(16)).is_ok());
    assert_eq!(Capabilities::new(tokens(17)), Err(CapabilityError::TooMany));
    assert_eq!(capability::MAX_CAPABILITIES, 16);
}

fn challenge(capabilities: &str) -> String {
    format!(
        r#"{{"result":"challenge","value":{{"nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","authority":"a.b:1","capabilities":{capabilities}}}}}"#
    )
}

#[test]
fn malformed_or_too_many_tokens_reject_the_message() {
    let sixteen: Vec<_> = (0..16).map(|index| format!("\"t{index}\"")).collect();
    let seventeen: Vec<_> = (0..17).map(|index| format!("\"t{index}\"")).collect();
    assert!(decode_response(&challenge(&format!("[{}]", sixteen.join(",")))).is_ok());
    assert!(decode_response(&challenge(r#"["mailbox","unknown-thing"]"#)).is_ok());
    for bad in [
        format!("[{}]", seventeen.join(",")),
        r#"["Mailbox"]"#.to_owned(),
        r#"[""]"#.to_owned(),
        r#"[1]"#.to_owned(),
        r#""udp""#.to_owned(),
        "null".to_owned(),
    ] {
        assert_eq!(
            decode_response(&challenge(&bad)),
            Err(ErrorCode::InvalidMessage),
            "{bad}"
        );
    }
}
