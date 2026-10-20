//! Exact verified JWT strings are data, not whitespace-free subject labels.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use nsshared_proto::account::{JwtSubjectBinding, PolicySubject, SubjectAnchor, SubjectBinding};

fn binding(claim_value: &str) -> JwtSubjectBinding {
    JwtSubjectBinding {
        binding: SubjectBinding {
            realm: [1; 16],
            anchor: SubjectAnchor::Credential("credential-a".into()),
            subject: PolicySubject::Realm {
                realm: [1; 16],
                name: "external:app".into(),
            },
            enabled: true,
            expires_seconds: Some(200),
        },
        authority_ref: "authority-a".into(),
        claim_name: "department".into(),
        claim_value: claim_value.into(),
        scopes: vec![],
    }
}

#[test]
fn verified_department_claim_with_internal_space_round_trips_exactly() {
    let control = binding("Engineering");
    let bytes = control.canonical().unwrap();
    assert_eq!(JwtSubjectBinding::decode(&bytes).unwrap(), control);

    // The retained consumer compares verified string claims by exact equality.
    let value = binding("Platform Engineering");
    let bytes = value
        .canonical()
        .expect("an exact JWT claim value may contain an internal space");
    assert_eq!(JwtSubjectBinding::decode(&bytes).unwrap(), value);
}
