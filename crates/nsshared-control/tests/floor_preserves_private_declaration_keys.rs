#![allow(clippy::unwrap_used)]
mod support;
use nsshared_control::{account::edge::EdgeServiceBody, account::edge::EdgeServiceRequest};

fn floor() -> EdgeServiceRequest {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/control-reports.vec"));
    let vector = vectors
        .iter()
        .find(|value| value.name() == "gateway.services_report-request")
        .unwrap();
    EdgeServiceRequest::decode(&vector.hex("bytes")).unwrap()
}

#[test]
fn floor_keeps_spaced_declaration_key() {
    let mut request = floor();
    assert!(request.canonical().is_ok());
    let EdgeServiceBody::Report(report) = &mut request.body else {
        unreachable!();
    };
    report.declarations[0].declaration_key = "web api".into();
    assert!(report.canonical().is_ok(), "unchanged M6 accepts this key");
    request.metadata[0].reference = "web api".into();
    let encoded = request.canonical();
    assert!(
        encoded.is_ok(),
        "floor must preserve a valid M6 declaration key: {encoded:?}"
    );
    assert_eq!(
        EdgeServiceRequest::decode(&encoded.unwrap()).unwrap(),
        request
    );
}

#[test]
fn floor_keeps_spaced_exit_reference() {
    let mut request = floor();
    assert!(request.canonical().is_ok());
    request.exit_profiles[0].reference = "exit west".into();
    let encoded = request.canonical();
    assert!(
        encoded.is_ok(),
        "nonempty control-free reference must be preserved: {encoded:?}"
    );
    assert_eq!(
        EdgeServiceRequest::decode(&encoded.unwrap()).unwrap(),
        request
    );
}

#[test]
fn floor_keeps_spaced_policy_label() {
    let mut request = floor();
    assert!(request.canonical().is_ok());
    request.metadata[0].policy_labels[0].0 = "team name".into();
    let encoded = request.canonical();
    assert!(
        encoded.is_ok(),
        "nonempty control-free label key must be preserved: {encoded:?}"
    );
    assert_eq!(
        EdgeServiceRequest::decode(&encoded.unwrap()).unwrap(),
        request
    );
}
