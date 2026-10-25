#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;

use nsshared_codec::{cbor::CborError, cbor::CborReader};
use nsshared_control::{
    account::AccountError, account::relay::IdentityClass, account::relay::ParticipantRosterError,
    account::relay::ParticipantRosterGeneration, account::relay::ParticipantRosterStatus,
    account::relay::SignedRoster, account::relay::participant_roster_status,
    account::relay::verify_participant_roster,
};
use nsshared_identity::keys::IdentityKey;

type Vector = BTreeMap<&'static str, &'static str>;

fn fixtures() -> Vec<Vector> {
    include_str!("fixtures/vectors/account.vec")
        .split("\n\n")
        .filter_map(|block| {
            let fields: BTreeMap<_, _> = block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect();
            (fields.get("kind") == Some(&"participant-roster")).then_some(fields)
        })
        .collect()
}

fn bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn identity(value: &str) -> IdentityKey {
    IdentityKey::from_bytes(&bytes(value).try_into().unwrap()).unwrap()
}

fn number(vector: &Vector, field: &str) -> u64 {
    vector[field].parse().unwrap()
}

fn decision(result: &Result<ParticipantRosterGeneration, ParticipantRosterError>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(ParticipantRosterError::Issuer) => "wrong-issuer",
        Err(ParticipantRosterError::Recipient) => "wrong-recipient",
        Err(ParticipantRosterError::Stale) => "stale-version",
        Err(ParticipantRosterError::FutureIssue) => "future-issue",
        Err(ParticipantRosterError::Expired) => "expired",
        Err(ParticipantRosterError::ShortLifetime) => "short-lifetime",
        Err(ParticipantRosterError::Signature) => "bad-signature",
        Err(ParticipantRosterError::MissingClass) => "missing-class",
        Err(ParticipantRosterError::DuplicateClass) => "duplicate-class",
        Err(ParticipantRosterError::UnknownClass) => "unknown-class",
        Err(ParticipantRosterError::DuplicateIdentity) => "duplicate-identity",
        Err(ParticipantRosterError::Contract(AccountError::Field)) => "invalid-field",
        Err(ParticipantRosterError::Contract(AccountError::Cbor(CborError::TrailingBytes))) => {
            "trailing-bytes"
        }
        Err(ParticipantRosterError::Contract(AccountError::Cbor(CborError::NonShortest))) => {
            "non-shortest"
        }
        other => panic!("unexpected participant roster decision: {other:?}"),
    }
}

fn check_generation(vector: &Vector, generation: &ParticipantRosterGeneration) {
    assert_eq!(
        generation.scope.issuer,
        identity(vector["generation_issuer"])
    );
    assert_eq!(
        generation.scope.recipient,
        identity(vector["generation_recipient"])
    );
    assert_eq!(generation.version.0, number(vector, "generation_version"));
    assert_eq!(
        generation.issued_at_unix_ms,
        number(vector, "generation_issued_ms")
    );
    assert_eq!(
        generation.valid_until_unix_ms,
        number(vector, "generation_deadline_ms")
    );
    let expected: Vec<_> = if vector["generation_mapping"] == "empty" {
        vec![]
    } else {
        vector["generation_mapping"]
            .split(',')
            .map(|entry| {
                let (key, class) = entry.split_once(':').unwrap();
                let class = match class {
                    "0" => IdentityClass::OrdinaryNode,
                    "1" => IdentityClass::GatewayNode,
                    other => panic!("unknown fixture class: {other}"),
                };
                (identity(key), class)
            })
            .collect()
    };
    let actual: Vec<_> = generation
        .identities
        .iter()
        .map(|entry| (entry.identity, entry.class))
        .collect();
    assert_eq!(actual, expected, "{}", vector["name"]);
    let status = participant_roster_status(
        generation,
        number(vector, "last_renewal_ms"),
        number(vector, "status_now_ms"),
    );
    assert_eq!(
        match status {
            ParticipantRosterStatus::Valid => "valid",
            ParticipantRosterStatus::Degraded => "degraded",
            ParticipantRosterStatus::Expired => "expired",
        },
        vector["status"],
        "{}",
        vector["name"]
    );
}

#[test]
fn participant_roster_vectors() {
    let vectors = fixtures();
    for name in [
        "accepted",
        "complete-empty",
        "revocation",
        "class-only-change",
        "wrong-issuer",
        "wrong-recipient",
        "stale-version",
        "equal-version",
        "future-issue",
        "before-expiry",
        "at-expiry",
        "before-degradation",
        "at-degradation",
        "renewed",
        "renewal-does-not-extend-expiry",
        "minimum-lifetime",
        "short-lifetime",
        "reversed-lifetime",
        "bad-signature",
        "missing-class",
        "duplicate-class",
        "unknown-class",
        "duplicate-identity",
        "unsorted-identities",
        "zero-version",
        "trailing",
        "nonminimal-carrier",
    ] {
        let name = format!("participant-roster-{name}");
        assert!(
            vectors.iter().any(|v| v["name"] == name),
            "missing independently signed participant lifecycle vectors: {name}"
        );
    }
    for vector in &vectors {
        // Read the independent canonical carrier even when its semantics are refused.
        let canonical = bytes(vector["canonical"]);
        let mut wire = CborReader::new(&canonical, nsshared_control::account::MAX_BYTES).unwrap();
        wire.array(2).unwrap();
        assert_eq!(
            wire.bytes_up_to(nsshared_control::account::MAX_BYTES)
                .unwrap(),
            bytes(vector["content"])
        );
        let _: [u8; 64] = wire.fixed_bytes().unwrap();
        wire.finish().unwrap();
        let issuer = identity(vector["issuer"]);
        let recipient = identity(vector["recipient"]);
        let previous = vector.get("previous").map(|input| {
            verify_participant_roster(
                &bytes(input),
                issuer,
                recipient,
                number(vector, "previous_last_version"),
                number(vector, "previous_now_ms"),
            )
            .unwrap()
        });
        if let Some(previous) = &previous {
            assert_eq!(previous.version.0, number(vector, "last_version"));
        }
        let input = bytes(vector["bytes"]);
        let result = verify_participant_roster(
            &input,
            issuer,
            recipient,
            number(vector, "last_version"),
            number(vector, "now_ms"),
        );
        assert_eq!(
            decision(&result),
            vector["decision"],
            "{}: {result:?}",
            vector["name"]
        );
        assert_eq!(result.is_ok(), vector["expect"] == "accept");
        if let Ok(generation) = &result {
            let signed = SignedRoster::decode(&input).unwrap();
            assert_eq!(signed.canonical().unwrap(), bytes(vector["canonical"]));
            assert_eq!(
                signed.content.canonical().unwrap(),
                bytes(vector["content"])
            );
            assert_eq!(
                signed
                    .verify_generation(
                        issuer,
                        recipient,
                        number(vector, "last_version"),
                        number(vector, "now_ms")
                    )
                    .unwrap(),
                *generation
            );
        }
        // A refusal leaves the previously authenticated complete generation intact.
        if let Some(generation) = result.as_ref().ok().or(previous.as_ref()) {
            check_generation(vector, generation);
        }
    }
}
