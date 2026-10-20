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

#[test]
fn claim_names_and_values_preserve_exact_data_with_utf8_byte_bounds() {
    for (name, value) in [
        (" department ".into(), "  Platform Engineering\t".into()),
        ("".into(), "".into()),
        ("claim\0\n\t".into(), "é/e\u{301}\0\r\n\t".into()),
        ("é".repeat(128), "é".repeat(128)),
    ] {
        let mut expected = binding(&value);
        expected.claim_name = name;
        let bytes = expected.canonical().unwrap();
        let decoded = JwtSubjectBinding::decode(&bytes).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.canonical().unwrap(), bytes);
    }
    for oversized in ["a".repeat(257), "é".repeat(129)] {
        let mut value = binding("Engineering");
        value.claim_name = oversized.clone();
        assert!(value.canonical().is_err());
        let mut value = binding(&oversized);
        assert!(value.canonical().is_err());
        value.claim_value = "Engineering".into();
        assert!(value.canonical().is_ok());
    }
}
