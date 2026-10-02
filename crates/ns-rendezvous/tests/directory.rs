//! Relay directory v2: rendezvous §5.4 and quick §4.1.

#![allow(clippy::unwrap_used, reason = "test fixture helpers")]

use ns_rendezvous::{
    capability::{self, Capabilities},
    directory::{CODE_LETTERS, Directory, DirectoryError, MAX_RELAYS, RelayEntry, check_update},
    error::ErrorCode,
    transport::{Response, decode_response},
};
use ns_wire::RelayId;
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn entry_with(
    id: u16,
    code: &str,
    host: &str,
    ips: &[&str],
    port: u16,
) -> Result<RelayEntry, DirectoryError> {
    RelayEntry::new(
        id,
        code.to_owned(),
        host.to_owned(),
        ips.iter().map(|text| ip(text)).collect(),
        port,
        Capabilities::new(vec![capability::UDP, capability::WSS]).unwrap(),
    )
}

fn entry(id: u16, code: &str) -> RelayEntry {
    entry_with(
        id,
        code,
        &format!("relay-{id}.relay.ns.io"),
        &["203.0.113.1"],
        443,
    )
    .unwrap()
}

fn base() -> Directory {
    Directory::new(3, vec![entry(1, "KT"), entry(2, "KM"), entry(3, "SG")]).unwrap()
}

#[test]
fn entry_fields_and_relay_id() {
    let relay = entry_with(
        7,
        "AB",
        "hkg-a1.relay.ns.io",
        &["203.0.113.9", "2001:db8::1"],
        51822,
    )
    .unwrap();
    assert_eq!(relay.id(), 7);
    assert_eq!(relay.code(), "AB");
    assert_eq!(relay.host(), "hkg-a1.relay.ns.io");
    assert_eq!(relay.ips(), [ip("203.0.113.9"), ip("2001:db8::1")]);
    assert_eq!(relay.port(), 51822);
    assert!(relay.capabilities().contains(&capability::WSS));
    assert_eq!(
        relay.relay_id(),
        RelayId::parse("hkg-a1.relay.ns.io:51822").unwrap()
    );
}

#[test]
fn entry_field_rules() {
    let ok = ["203.0.113.1"];
    assert_eq!(
        entry_with(0, "KT", "a.ns.io", &ok, 443),
        Err(DirectoryError::Id)
    );
    for code in ["", "K", "KTT", "kt", "KI", "OK", "K1", "ＫＴ"] {
        assert_eq!(
            entry_with(1, code, "a.ns.io", &ok, 443),
            Err(DirectoryError::Code),
            "{code}"
        );
    }
    assert_eq!(
        entry_with(1, "KT", "a.ns.io", &ok, 0),
        Err(DirectoryError::Port)
    );
    for host in [
        "",
        "A.ns.io",
        "a..ns.io",
        "-a.ns.io",
        "a_b.ns.io",
        "a.ns.io.",
        "203.0.113.1",
        "1234",
        "[2001:db8::1]",
        "a.ns.io:443",
        "a/b",
        &format!("{}.io", "a".repeat(64)),
    ] {
        assert_eq!(
            entry_with(1, "KT", host, &ok, 443),
            Err(DirectoryError::Host),
            "{host}"
        );
    }
    for ips in [
        &[][..],
        &[
            "203.0.113.1",
            "203.0.113.2",
            "203.0.113.3",
            "203.0.113.4",
            "203.0.113.5",
        ][..],
        &["203.0.113.1", "203.0.113.1"][..],
        &["0.0.0.0"][..],
        &["::"][..],
        &["224.0.0.1"][..],
        &["ff02::1"][..],
    ] {
        assert_eq!(
            entry_with(1, "KT", "a.ns.io", ips, 443),
            Err(DirectoryError::Ips),
            "{ips:?}"
        );
    }
    assert!(
        entry_with(
            1,
            "KT",
            "a.ns.io",
            &["203.0.113.1", "203.0.113.2", "::1", "2001:db8::2"],
            443
        )
        .is_ok()
    );
    // Every code letter is accepted; I and O never are.
    for letter in CODE_LETTERS {
        let code = String::from_utf8(vec![*letter, b'A']).unwrap();
        assert!(entry_with(1, &code, "a.ns.io", &ok, 443).is_ok());
    }
}

#[test]
fn directory_rules() {
    assert_eq!(
        Directory::new(0, vec![entry(1, "KT")]),
        Err(DirectoryError::Version)
    );
    assert_eq!(Directory::new(1, vec![]), Err(DirectoryError::Empty));
    assert_eq!(
        Directory::new(1, vec![entry(1, "KT"), entry(1, "KM")]),
        Err(DirectoryError::DuplicateId)
    );
    assert_eq!(
        Directory::new(1, vec![entry(1, "KT"), entry(2, "KT")]),
        Err(DirectoryError::DuplicateCode)
    );
    let same_host = entry_with(2, "KM", "relay-1.relay.ns.io", &["198.51.100.1"], 8443).unwrap();
    assert_eq!(
        Directory::new(1, vec![entry(1, "KT"), same_host]),
        Err(DirectoryError::DuplicateHost)
    );
    let directory = base();
    assert_eq!(directory.version(), 3);
    assert_eq!(directory.relays().len(), 3);
    assert_eq!(
        ErrorCode::from(DirectoryError::Version),
        ErrorCode::InvalidDirectory
    );
}

#[test]
fn at_most_576_relays() {
    let codes: Vec<String> = CODE_LETTERS
        .iter()
        .flat_map(|first| {
            CODE_LETTERS
                .iter()
                .map(move |second| String::from_utf8(vec![*first, *second]).unwrap())
        })
        .collect();
    assert_eq!(codes.len(), MAX_RELAYS);
    let relays: Vec<_> = codes
        .iter()
        .enumerate()
        .map(|(index, code)| entry(u16::try_from(index + 1).unwrap(), code))
        .collect();
    assert!(Directory::new(1, relays.clone()).is_ok());
    let mut too_many = relays;
    too_many.push(entry(1000, "KT"));
    assert_eq!(
        Directory::new(1, too_many),
        Err(DirectoryError::TooManyRelays)
    );
}

#[test]
fn update_rules() {
    let old = base();
    // Identical content at the same version is accepted.
    assert_eq!(check_update(&old, &old.clone()), Ok(()));
    // Lower versions are rejected, even when identical.
    let lower = Directory::new(2, old.relays().to_vec()).unwrap();
    assert_eq!(
        check_update(&old, &lower),
        Err(DirectoryError::VersionRegressed)
    );
    // Any change at the same version is rejected, including a reordering.
    let mut reordered = old.relays().to_vec();
    reordered.reverse();
    let reordered = Directory::new(3, reordered).unwrap();
    assert_eq!(
        check_update(&old, &reordered),
        Err(DirectoryError::ChangedWithoutVersion)
    );
    let mut moved = old.relays().to_vec();
    moved[0] = entry_with(1, "KT", "relay-1.relay.ns.io", &["198.51.100.7"], 443).unwrap();
    let moved_same = Directory::new(3, moved.clone()).unwrap();
    assert_eq!(
        check_update(&old, &moved_same),
        Err(DirectoryError::ChangedWithoutVersion)
    );
    // A higher version may change ips and capabilities and add entries.
    moved.push(entry(9, "AA"));
    let moved_higher = Directory::new(4, moved).unwrap();
    assert_eq!(check_update(&old, &moved_higher), Ok(()));
    // An id is never removed.
    let removed = Directory::new(4, vec![entry(1, "KT"), entry(2, "KM")]).unwrap();
    assert_eq!(check_update(&old, &removed), Err(DirectoryError::IdRemoved));
    // An id's code never changes.
    let recoded = Directory::new(4, vec![entry(1, "KT"), entry(2, "KN"), entry(3, "SG")]).unwrap();
    assert_eq!(
        check_update(&old, &recoded),
        Err(DirectoryError::CodeChanged)
    );
    // A new id never takes an existing code, nor the code of a retired (removed) id.
    let taken = Directory::new(
        4,
        vec![
            entry(1, "AB"),
            entry(2, "KM"),
            entry(3, "SG"),
            entry(4, "KT"),
        ],
    )
    .unwrap();
    assert_eq!(check_update(&old, &taken), Err(DirectoryError::CodeReused));
    let retired = Directory::new(4, vec![entry(1, "KT"), entry(2, "KM"), entry(4, "SG")]).unwrap();
    assert_eq!(
        check_update(&old, &retired),
        Err(DirectoryError::CodeReused)
    );
}

fn relay_json(fields: &str) -> String {
    format!(r#"{{"result":"directory","value":{{"version":1,"relays":[{{{fields}}}]}}}}"#)
}

#[test]
fn decoding_validates_every_rule() {
    let good = r#""id":1,"code":"KT","host":"a.ns.io","ips":["203.0.113.1","2001:db8::1"],"port":443,"capabilities":["udp","later"]"#;
    let Ok(Response::Directory(directory)) = decode_response(&relay_json(good)) else {
        panic!("directory did not decode");
    };
    assert_eq!(directory.relays()[0].ips()[1], ip("2001:db8::1"));
    for fields in [
        good.replace(r#""id":1"#, r#""id":0"#),
        good.replace(r#""id":1"#, r#""id":65536"#),
        good.replace(r#""code":"KT""#, r#""code":"kt""#),
        good.replace(r#""host":"a.ns.io""#, r#""host":"203.0.113.1""#),
        good.replace(r#""port":443"#, r#""port":0"#),
        good.replace(r#""port":443"#, r#""port":443.0"#),
        good.replace(r#""2001:db8::1""#, r#""2001:DB8::1""#),
        good.replace(r#""2001:db8::1""#, r#""2001:0db8::1""#),
        good.replace(r#""203.0.113.1""#, r#""203.0.113.01""#),
        good.replace(r#""203.0.113.1""#, r#""[2001:db8::2]""#),
        good.replace(r#""ips":["203.0.113.1","2001:db8::1"]"#, r#""ips":[]"#),
        good.replace(r#""later""#, r#""Later""#),
        good.replace(r#","port":443"#, ""),
        format!(r#"{good},"authority":"a.ns.io:443""#),
    ] {
        assert_eq!(
            decode_response(&relay_json(&fields)),
            Err(ErrorCode::InvalidMessage),
            "{fields}"
        );
    }
    for text in [
        r#"{"result":"directory","value":{"version":0,"relays":[]}}"#,
        r#"{"result":"directory","value":{"version":1,"relays":[]}}"#,
        r#"{"result":"directory","value":{"version":1,"relays":[],"extra":0}}"#,
    ] {
        assert_eq!(
            decode_response(text),
            Err(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    let duplicate = format!(
        r#"{{"result":"directory","value":{{"version":1,"relays":[{{{good}}},{{{}}}]}}}}"#,
        good.replace(r#""id":1"#, r#""id":2"#)
            .replace(r#""host":"a.ns.io""#, r#""host":"b.ns.io""#)
    );
    assert_eq!(decode_response(&duplicate), Err(ErrorCode::InvalidMessage));
}
