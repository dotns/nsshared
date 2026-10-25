#![allow(clippy::unwrap_used, clippy::panic)]

use nsshared_codec::cbor::CborError;
use nsshared_control::{
    account::AccountError, account::node::Enrollment, account::node::EnrollmentDecision,
    account::node::EnrollmentError, account::node::Lifecycle, account::node::RebindAuthorization,
    account::node::decide_enrollment,
};
use nsshared_identity::keys::IdentityKey;
use std::collections::{BTreeMap, BTreeSet};

type Vector = BTreeMap<&'static str, &'static str>;

fn fixtures() -> Vec<Vector> {
    include_str!("fixtures/vectors/account.vec")
        .split("\n\n")
        .filter_map(|block| {
            let fields: BTreeMap<_, _> = block
                .lines()
                .filter_map(|line| line.split_once(" = "))
                .collect();
            (fields.get("kind") == Some(&"enrollment")).then_some(fields)
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

fn check_identity(vector: &Vector, prefix: &str) -> IdentityKey {
    let identity = IdentityKey::from_bytes(
        &bytes(vector[format!("{prefix}identity").as_str()])
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        identity.node_id().to_string(),
        vector[format!("{prefix}node_id").as_str()],
        "{}: {prefix}NodeId",
        vector["name"]
    );
    assert_eq!(
        identity.node6().octets().as_slice(),
        bytes(vector[format!("{prefix}n6").as_str()]),
        "{}: {prefix}N6",
        vector["name"]
    );
    assert_eq!(
        identity.node4().octets().as_slice(),
        bytes(vector[format!("{prefix}n4").as_str()]),
        "{}: {prefix}N4",
        vector["name"]
    );
    identity
}

fn evaluate(vector: &Vector) -> Result<EnrollmentDecision, EnrollmentError> {
    // Check every identity, including bindings in publications refused before decoding.
    let presented_identity = check_identity(vector, "presented_");
    let accepted = vector.get("accepted").map(|input| {
        let accepted = Enrollment::decode(&bytes(input)).unwrap();
        assert_eq!(accepted.canonical().unwrap(), bytes(input));
        assert_eq!(
            accepted.binding.identity,
            check_identity(vector, "accepted_")
        );
        accepted
    });
    let presented = Enrollment::decode(&bytes(vector["bytes"]))?;
    assert_eq!(presented.binding.identity, presented_identity);
    assert_eq!(presented.canonical().unwrap(), bytes(vector["canonical"]));
    let lifecycle = vector
        .get("lifecycle")
        .map(|input| {
            let before_identity = check_identity(vector, "lifecycle_before_");
            let after_identity = check_identity(vector, "lifecycle_after_");
            let value = Lifecycle::decode(&bytes(input))?;
            assert_eq!(value.before.identity, before_identity);
            assert_eq!(value.after.identity, after_identity);
            assert_eq!(value.canonical().unwrap(), bytes(input));
            Ok::<_, AccountError>(value)
        })
        .transpose()?;
    let rebind = match vector["rebind"] {
        "authorized" => RebindAuthorization::Authorized,
        "denied" => RebindAuthorization::Denied,
        other => panic!("unknown rebind authorization: {other}"),
    };
    decide_enrollment(
        accepted.as_ref().map(|value| &value.binding),
        &presented,
        lifecycle.as_ref(),
        rebind,
    )
}

fn outcome(result: Result<EnrollmentDecision, EnrollmentError>) -> &'static str {
    match result {
        Ok(EnrollmentDecision::Initial) => "initial",
        Ok(EnrollmentDecision::Equal) => "equal",
        Ok(EnrollmentDecision::IdentityReplacement) => "identity-replacement",
        Ok(EnrollmentDecision::RecordRotation) => "record-rotation",
        Err(EnrollmentError::LowerVersion) => "lower-version",
        Err(EnrollmentError::LifecycleRequired) => "lifecycle-required",
        Err(EnrollmentError::LifecycleMismatch) => "lifecycle-mismatch",
        Err(EnrollmentError::RebindUnauthorized) => "rebind-unauthorized",
        Err(EnrollmentError::InvalidCapabilities) => "invalid-capabilities",
        Err(EnrollmentError::CapabilityBounds) => "capability-bounds",
        Err(EnrollmentError::Contract(AccountError::Field)) => "invalid-field",
        Err(EnrollmentError::Contract(AccountError::Cbor(CborError::NonShortest))) => {
            "non-shortest"
        }
        Err(EnrollmentError::Contract(AccountError::Cbor(CborError::TrailingBytes))) => {
            "trailing-bytes"
        }
        other => panic!("unexpected enrollment outcome: {other:?}"),
    }
}

#[test]
fn enrollment_identity_vectors() {
    let vectors = fixtures();
    for name in [
        "enrollment-accepted",
        "enrollment-identity-replacement",
        "enrollment-stable-i-rotation",
        "enrollment-rejected-staged-version-restart",
    ] {
        assert!(
            vectors.iter().any(|vector| vector["name"] == name),
            "missing independent consumer vector: {name}"
        );
    }
    for vector in &vectors {
        assert_eq!(
            outcome(evaluate(vector)),
            vector["decision"],
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn enrollment_consumer_vectors() {
    let vectors = fixtures();
    for (name, expected) in [
        ("identity-replacement", "identity-replacement"),
        ("stable-i-rotation", "record-rotation"),
        ("wrong-lifecycle-before", "lifecycle-mismatch"),
        ("wrong-lifecycle-after", "lifecycle-mismatch"),
        ("unauthorized-rebind", "rebind-unauthorized"),
    ] {
        let name = format!("enrollment-{name}-zero-placeholders");
        let vector = vectors
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("missing independent consumer vector: {name}"));
        let enrollment = Enrollment::decode(&bytes(vector["bytes"])).unwrap();
        assert!(enrollment.capabilities.is_empty(), "{name}");
        let lifecycle = Lifecycle::decode(&bytes(vector["lifecycle"])).unwrap();
        assert_eq!(lifecycle.grant.0, [0; 16], "{name}");
        assert_eq!(lifecycle.reporter.0, [0; 16], "{name}");
        assert_eq!(outcome(evaluate(vector)), expected, "{name}");
    }
}

#[test]
fn enrollment_contract_refusals() {
    let vectors = fixtures();
    let mut names = BTreeSet::new();
    for vector in &vectors {
        if matches!(
            vector["decision"],
            "initial" | "equal" | "identity-replacement" | "record-rotation"
        ) {
            continue;
        }
        let result = evaluate(vector);
        assert!(result.is_err(), "{}", vector["name"]);
        assert_eq!(outcome(result), vector["decision"], "{}", vector["name"]);
        names.insert(vector["name"]);
    }
    for name in [
        "enrollment-rejected-staged-version-restart",
        "enrollment-lower-version",
        "enrollment-unsorted-capabilities",
        "enrollment-duplicate-capabilities",
        "enrollment-too-many-capabilities",
        "enrollment-long-capability",
        "enrollment-nonminimal-array",
        "enrollment-nonminimal-schema",
        "enrollment-trailing",
    ] {
        assert!(names.contains(name), "missing refusal: {name}");
    }
}

#[test]
fn enrollment_validates_constructed_contracts() {
    let vectors = fixtures();
    let initial = vectors
        .iter()
        .find(|v| v["name"] == "enrollment-accepted")
        .unwrap();
    let enrollment = Enrollment::decode(&bytes(initial["bytes"])).unwrap();
    for capabilities in [
        vec!["z".into(), "a".into()],
        vec!["a".into(); 2],
        vec!["".into()],
        vec!["A".into()],
    ] {
        let invalid = Enrollment {
            capabilities,
            ..enrollment.clone()
        };
        assert!(matches!(
            invalid.canonical(),
            Err(EnrollmentError::InvalidCapabilities)
        ));
        assert!(matches!(
            decide_enrollment(None, &invalid, None, RebindAuthorization::Denied),
            Err(EnrollmentError::InvalidCapabilities)
        ));
    }
    for capabilities in [vec!["a".into(); 65], vec!["a".repeat(65)]] {
        let invalid = Enrollment {
            capabilities,
            ..enrollment.clone()
        };
        assert!(matches!(
            invalid.canonical(),
            Err(EnrollmentError::CapabilityBounds)
        ));
        assert!(matches!(
            decide_enrollment(None, &invalid, None, RebindAuthorization::Denied),
            Err(EnrollmentError::CapabilityBounds)
        ));
    }
    let rotation = vectors
        .iter()
        .find(|v| v["name"] == "enrollment-stable-i-rotation")
        .unwrap();
    let presented = Enrollment::decode(&bytes(rotation["bytes"])).unwrap();
    let mut lifecycle = Lifecycle::decode(&bytes(rotation["lifecycle"])).unwrap();
    lifecycle.after.generation = lifecycle.before.generation;
    assert!(matches!(
        decide_enrollment(
            Some(&enrollment.binding),
            &presented,
            Some(&lifecycle),
            RebindAuthorization::Authorized
        ),
        Err(EnrollmentError::Contract(AccountError::Field))
    ));
    let mut invalid_accepted = enrollment.binding.clone();
    invalid_accepted.identity_version.0 = 0;
    assert!(matches!(
        decide_enrollment(
            Some(&invalid_accepted),
            &enrollment,
            None,
            RebindAuthorization::Denied
        ),
        Err(EnrollmentError::Contract(AccountError::Field))
    ));
}
