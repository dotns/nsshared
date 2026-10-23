#![allow(clippy::unwrap_used, clippy::panic)]

mod support;

use nsshared_proto::{
    IdentityKey,
    account::{
        AdminScope, AdminTokenClaims, BootstrapError, EnvelopeDirection, EnvelopeExpectation,
        EnvelopePins, JwtSubjectBinding, PolicySubject, SignedAccountRequest,
        SignedSubjectHeaderPolicy, SignedUrlScope, SubjectBinding, SubjectPolicy,
    },
    encoding::CborReader,
};

#[test]
fn policy_claim_vectors() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/policy-claims.vec"));
    for vector in &vectors {
        let bytes = vector.hex("bytes");
        if vector.get("kind") == "url" {
            let mut input = CborReader::new(&bytes, bytes.len()).unwrap();
            input.array(5).unwrap();
            let scope = SignedUrlScope {
                method: input.text_up_to(256).unwrap(),
                scheme: input.text_up_to(256).unwrap(),
                host: input.text_up_to(256).unwrap(),
                path: input.text_up_to(256).unwrap(),
                query: input.text_up_to(256).unwrap(),
                realm: "realm-a",
                route: "route-a",
                expires_seconds: 200,
            };
            input.finish().unwrap();
            assert_eq!(
                scope.canonical_request().unwrap().as_bytes(),
                vector.hex("request")
            );
            assert_eq!(
                scope.signing_input().unwrap().as_bytes(),
                vector.hex("signing_input")
            );
            continue;
        }
        if vector.get("kind") == "request" {
            let result = SignedAccountRequest::decode(&bytes).and_then(|request| {
                let signer = IdentityKey::from_bytes(&vector.hex_array("signer")).unwrap();
                let pin = vector.get("pin").to_owned();
                let pins = EnvelopePins::intersect(&[pin], &[]).unwrap();
                request.envelope().verify(&EnvelopeExpectation {
                    pins: &pins,
                    direction: EnvelopeDirection::Request,
                    recipient: signer,
                    kind: "admin.inspect",
                    now_seconds: 100,
                    previous_acceptance_seconds: None,
                })?;
                assert_eq!(
                    request.envelope().signing_input().unwrap(),
                    vector.hex("signing_input")
                );
                request.canonical()
            });
            assert_eq!(
                result.is_ok(),
                vector.get("expect") == "accept",
                "{}: {result:?}",
                vector.name()
            );
            match vector.name() {
                "wrong-domain" => assert!(matches!(result, Err(BootstrapError::Signature))),
                "response-as-request" => assert!(matches!(result, Err(BootstrapError::Direction))),
                _ => {}
            }
            if let Ok(canonical) = result {
                assert_eq!(canonical, bytes);
            }
            continue;
        }
        let result = match vector.get("kind") {
            "subject" => PolicySubject::decode(&bytes).and_then(|v| v.canonical()),
            "binding" => SubjectBinding::decode(&bytes).and_then(|v| v.canonical()),
            "policy" => SubjectPolicy::decode(&bytes).and_then(|v| v.canonical()),
            "admin" => AdminTokenClaims::decode(&bytes).and_then(|v| v.canonical()),
            "jwt" => JwtSubjectBinding::decode(&bytes).and_then(|v| {
                if vector.get("expect") == "accept" {
                    assert_eq!(
                        v.claim_name,
                        serde_json::from_str::<String>(vector.get("claim_name_json")).unwrap(),
                        "{}",
                        vector.name()
                    );
                    assert_eq!(
                        v.claim_value,
                        serde_json::from_str::<String>(vector.get("claim_value_json")).unwrap(),
                        "{}",
                        vector.name()
                    );
                }
                v.canonical()
            }),
            "header" => SignedSubjectHeaderPolicy::decode(&bytes).and_then(|v| v.canonical()),
            other => panic!("unknown vector kind: {other}"),
        };
        assert_eq!(
            result.is_ok(),
            vector.get("expect") == "accept",
            "{}: {result:?}",
            vector.name()
        );
        if let Ok(canonical) = result {
            assert_eq!(canonical, bytes, "{}", vector.name());
        }
    }
    assert!(vectors.len() > 70);
}

#[test]
fn admin_scope_and_exact_principal_context() {
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/policy-claims.vec"));
    for (level, name) in ["read_only", "read_write", "super_admin"]
        .iter()
        .enumerate()
    {
        let scope: AdminScope = serde_json::from_str(&format!("\"{name}\"")).unwrap();
        assert_eq!(
            serde_json::to_string(&scope).unwrap(),
            format!("\"{name}\"")
        );
        let vector = vectors
            .iter()
            .find(|v| v.name() == format!("admin-scope-{level}"))
            .unwrap();
        let claims = AdminTokenClaims::decode(&vector.hex("bytes")).unwrap();
        assert_eq!(claims.scope, scope);
        for (required, expected) in [
            AdminScope::ReadOnly,
            AdminScope::ReadWrite,
            AdminScope::SuperAdmin,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(claims.require_scope(expected).is_ok(), level >= required);
            assert_eq!(
                claims
                    .validate_context(&claims.subject, claims.realm, expected, 199)
                    .is_ok(),
                level >= required
            );
        }
        assert!(
            claims
                .validate_context(&claims.subject, claims.realm, scope, 200)
                .is_err()
        );
        assert!(
            claims
                .validate_context(&claims.subject, Some([9; 16].into()), scope, 100)
                .is_err()
        );
        let other = PolicySubject::Realm {
            realm: [1; 16].into(),
            name: "external:other".into(),
        };
        assert!(
            claims
                .validate_context(&other, claims.realm, scope, 100)
                .is_err()
        );
    }
    for name in ["full", "read-only", "root", "", "READ_WRITE"] {
        assert!(serde_json::from_str::<AdminScope>(&format!("\"{name}\"")).is_err());
    }
}

#[test]
fn qualified_policy_and_binding_fields() {
    use nsshared_proto::account::{Payer, SubjectAnchor, TransportProtocol};
    let vectors = support::vectors::parse(include_str!("fixtures/vectors/policy-claims.vec"));
    let sample = |name: &str| {
        vectors
            .iter()
            .find(|v| v.name() == name)
            .unwrap()
            .hex("bytes")
    };
    let user = PolicySubject::decode(&sample("subject-user")).unwrap();
    assert_eq!(
        user,
        PolicySubject::User(Payer {
            realm: [1; 16].into(),
            subject: [3; 16]
        })
    );
    let binding = SubjectBinding::decode(&sample("binding-credential")).unwrap();
    assert_eq!(binding.realm.to_bytes(), [1; 16]);
    assert_eq!(
        binding.anchor,
        SubjectAnchor::Credential("credential-a".into())
    );
    assert_eq!(
        binding.subject,
        PolicySubject::Realm {
            realm: [1; 16].into(),
            name: "external:app".into()
        }
    );
    assert!(binding.enabled);
    assert_eq!(binding.expires_seconds, Some(200));
    let policy = SubjectPolicy::decode(&sample("policy-groups")).unwrap();
    assert_eq!(policy.realm.to_bytes(), [1; 16]);
    assert_eq!(policy.rules[0].protocol, Some(TransportProtocol::Tcp));
    assert_eq!(policy.rules[0].destinations, ["db:5432"]);
    assert_eq!(
        policy.rules[0].subjects,
        [nsshared_proto::account::SubjectSelector::Subject(
            policy.groups[0].group.clone()
        )]
    );
    assert!(policy.groups[0].members.contains(&user));
    let jwt = JwtSubjectBinding::decode(&sample("jwt-binding")).unwrap();
    assert_eq!(jwt.binding, binding);
    assert_eq!(
        (
            jwt.authority_ref.as_str(),
            jwt.claim_name.as_str(),
            jwt.claim_value.as_str()
        ),
        ("issuer-a", "sub", "client-a")
    );
    assert_eq!(jwt.scopes, ["read", "write"]);
    let header = SignedSubjectHeaderPolicy::decode(&sample("signed-header")).unwrap();
    assert!(header.enabled && header.strip_inbound);
    assert_eq!(header.header_name.as_deref(), Some("x-subject"));
    assert_eq!(header.signature_header_name.as_deref(), Some("x-signature"));
    assert_eq!(header.keyset_ref.as_deref(), Some("header-key"));
    assert_eq!(header.validity_seconds, Some(60));
}

#[test]
fn signed_url_refusals_and_scope_binding() {
    let base = SignedUrlScope {
        method: "GET",
        scheme: "https",
        host: "example.com",
        path: "/raw%2Fpath",
        query: "a=%2f&a=+",
        realm: "realm-a",
        route: "route-a",
        expires_seconds: 200,
    };
    let canonical = base.signing_input().unwrap();
    for changed in [
        SignedUrlScope {
            route: "route-b",
            ..base
        },
        SignedUrlScope {
            realm: "realm-b",
            ..base
        },
        SignedUrlScope {
            method: "HEAD",
            ..base
        },
        SignedUrlScope {
            expires_seconds: 201,
            ..base
        },
        SignedUrlScope {
            path: "/raw/path",
            ..base
        },
        SignedUrlScope {
            host: "example.com:8443",
            ..base
        },
    ] {
        assert_ne!(changed.signing_input().unwrap(), canonical);
    }
    for invalid in [
        SignedUrlScope {
            method: "POST",
            ..base
        },
        SignedUrlScope {
            scheme: "ftp",
            ..base
        },
        SignedUrlScope {
            query: "a=%",
            ..base
        },
        SignedUrlScope {
            query: "a=%xz",
            ..base
        },
        SignedUrlScope {
            path: "/a\nb",
            ..base
        },
        SignedUrlScope {
            realm: "realm other",
            ..base
        },
        SignedUrlScope {
            route: "route other",
            ..base
        },
        SignedUrlScope {
            realm: "realm/other",
            ..base
        },
        SignedUrlScope {
            route: "route/other",
            ..base
        },
    ] {
        assert!(invalid.signing_input().is_err());
    }
}
