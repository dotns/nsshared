#![allow(clippy::unwrap_used, clippy::expect_used)]
use nsshared_control::{account::edge::AuthConfigResponse, account::edge::AuthKeySourceKind};

#[test]
fn fixed_jwks_source_preserves_query_parameters() {
    let vectors = nsshared_testkit::vectors!("account/edge/auth");
    let vector = vectors
        .iter()
        .find(|v| v.name() == "confidential_auth_generation")
        .unwrap();
    let mut response = AuthConfigResponse::decode(&vector.hex("bytes")).unwrap();
    let pending = response.request.clone();
    let source = &mut response.configuration.key_sources[0];
    source.kind = AuthKeySourceKind::Uri;
    source.value = Some("https://keys.example/jwks".into());
    response
        .validate_for(&pending, pending.realm, &pending.material)
        .unwrap();

    response.configuration.key_sources[0].value =
        Some("https://keys.example/jwks?tenant=realm".into());
    let raw = response
        .canonical()
        .expect("a fixed HTTPS JWKS URI can select its tenant by query");
    let decoded = AuthConfigResponse::decode(&raw).unwrap();
    assert_eq!(
        decoded.configuration.key_sources[0].value,
        response.configuration.key_sources[0].value
    );
    decoded
        .validate_for(&pending, pending.realm, &pending.material)
        .unwrap();
}
