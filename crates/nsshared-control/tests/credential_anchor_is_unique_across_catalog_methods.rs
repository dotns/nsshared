#![allow(clippy::unwrap_used)]
mod support;
use nsshared_control::account::edge::AuthConfigResponse;

#[test]
fn credential_anchor_is_unique_across_jwt_and_private_verifiers() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/confidential-auth.vec"));
    let vector = vectors
        .iter()
        .find(|v| v.name() == "confidential_auth_generation")
        .unwrap();
    let mut response = AuthConfigResponse::decode(&vector.hex("bytes")).unwrap();
    let pending = response.request.clone();
    response
        .validate_for(&pending, pending.realm, &pending.material)
        .unwrap();

    let configuration = &mut response.configuration;
    configuration.public_auth.jwt_bindings[0].binding =
        configuration.credentials[0].binding.clone();
    configuration.jwt_consumers[0].credential_ref = "api".into();
    assert!(
        response.canonical().is_err(),
        "one credential anchor identifies both an API-key verifier and a JWT binding"
    );
}
