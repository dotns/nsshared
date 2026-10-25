#![allow(clippy::unwrap_used, clippy::panic)]
mod support;
use nsshared_control::{
    account::edge::EdgeServiceAckError, account::edge::EdgeServiceBody,
    account::edge::EdgeServiceRequest, account::edge::EdgeServiceResponse,
};

#[test]
fn floor_data_text_vectors() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/floor-text.vec"));
    for vector in &vectors {
        let bytes = vector.hex("bytes");
        let accepted = vector.get("expect") == "accept";
        match vector.get("kind") {
            "request" => {
                let result = EdgeServiceRequest::decode(&bytes);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", vector.name());
                if let Ok(request) = result {
                    assert_eq!(request.canonical().unwrap(), bytes, "{}", vector.name());
                    let EdgeServiceBody::Report(report) = &request.body else {
                        panic!("expected report");
                    };
                    assert_eq!(
                        report.declarations[0].declaration_key.as_bytes(),
                        vector.hex("service")
                    );
                    assert_eq!(
                        request.metadata[0].reference.as_bytes(),
                        vector.hex("service")
                    );
                    assert_eq!(
                        request.exit_profiles[0].reference.as_bytes(),
                        vector.hex("exit")
                    );
                    assert_eq!(
                        request.metadata[0].policy_labels[0].0.as_bytes(),
                        vector.hex("label")
                    );
                    assert_eq!(
                        request.exit_profiles[0].policy_labels[0].0.as_bytes(),
                        vector.hex("label")
                    );
                }
            }
            "response" => {
                let result = EdgeServiceResponse::decode(&bytes);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", vector.name());
                if let Ok(response) = result {
                    assert_eq!(response.canonical().unwrap(), bytes);
                }
            }
            "match" => {
                let request = EdgeServiceRequest::decode(&vector.hex("pending")).unwrap();
                let response = EdgeServiceResponse::decode(&bytes).unwrap();
                assert_eq!(response.canonical().unwrap(), bytes);
                let result = response.validate_request(&request);
                assert_eq!(result.is_ok(), accepted, "{}: {result:?}", vector.name());
                if accepted {
                    assert_eq!(response.accepted, vector.get("accepted") == "yes");
                } else {
                    assert!(
                        matches!(result, Err(EdgeServiceAckError::UnknownReference)),
                        "{}",
                        vector.name()
                    );
                }
            }
            _ => panic!("unknown floor vector"),
        }
    }
}
