//! Configured mailbox response capacity must cover the future lookup view.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "isolated TLS regression fixture"
)]

mod support;

use nsshared_rendezvous::{
    auth::Hello,
    error::ErrorCode,
    message::{Admission, Found, Kind, MailboxId, OpenRequest},
    transport::{Request, Response, encode_request, encode_response},
};
use support::{Mock, key, now, relaxed_limits};

fn spec() -> OpenRequest {
    OpenRequest {
        kind: Kind::parse("open-capacity").unwrap(),
        ttl: 90,
        admission: Admission::Owner,
        candidates: 4,
        intro: vec![7; 128],
    }
}

fn prospective_found_size() -> usize {
    let request = spec();
    encode_response(&Response::Found(Found {
        id: MailboxId([1; 16]),
        kind: request.kind,
        expires: now() + request.ttl,
        intro: request.intro,
    }))
    .unwrap()
    .len()
}

#[test]
fn canonical_encoders_expose_a_reachable_configured_capacity_window() {
    let open_size = encode_request(&Request::Open(spec())).unwrap().len();
    let found_size = prospective_found_size();
    println!("canonical open={open_size} prospective_found={found_size}");
    assert!(open_size < found_size);
    assert!(found_size < nsshared_rendezvous::transport::MAX_MESSAGE_BYTES);
}

async fn exercise(cap: usize) {
    let mock = Mock::start(nsshared_mock_rendezvous::Limits {
        message_bytes: cap,
        ..relaxed_limits()
    })
    .await;
    let mut client = mock.connect().await;
    let challenge_size = encode_response(&Response::Challenge(client.challenge.clone()))
        .unwrap()
        .len();
    let hello = Hello::sign(
        &key(21),
        &client.challenge.nonce,
        &client.challenge.authority,
    );
    let hello_size = encode_request(&Request::Hello(hello.clone()))
        .unwrap()
        .len();
    assert!(challenge_size <= cap);
    assert!(hello_size <= cap);
    assert_eq!(client.request(&Request::Hello(hello)).await, Response::Ok);
    let open = Request::Open(spec());
    let request_size = encode_request(&open).unwrap().len();
    assert!(request_size <= cap);
    let response = client.request(&open).await;
    assert!(encode_response(&response).unwrap().len() <= cap);
    match response {
        Response::Opened(opened) => {
            let found = client.lookup(&opened.digits).await.unwrap();
            assert_eq!(found.id, opened.id);
            assert_eq!(found.kind, spec().kind);
            assert_eq!(found.intro, spec().intro);
            assert_eq!(found.expires, opened.expires);
            let actual_found_size = encode_response(&Response::Found(found)).unwrap().len();
            println!(
                "authenticated_tls cap={cap} challenge={challenge_size} hello={hello_size} open={request_size} actual_found={actual_found_size}"
            );
            assert!(
                actual_found_size <= cap,
                "accepted Open produced an oversized lookup response"
            );
        }
        Response::Error(ErrorCode::Capacity) => assert!(cap < prospective_found_size()),
        other => panic!("unexpected Open response: {other:?}"),
    }
    mock.stop().await;
}

#[tokio::test]
async fn accepted_open_keeps_its_future_lookup_within_configured_capacity() {
    exercise(encode_request(&Request::Open(spec())).unwrap().len()).await;
}

#[tokio::test]
async fn exact_found_boundary_allows_authenticated_open_and_lookup() {
    exercise(prospective_found_size()).await;
}
