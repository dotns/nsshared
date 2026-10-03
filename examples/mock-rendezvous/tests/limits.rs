//! Limits and errors over the mock (rendezvous §3, §4, §5.2, §6, §7): message size,
//! malformed and unknown input, `hello` binding, stage, capacity, queue, rate and
//! pending-`recv` limits, and refused WebSocket upgrades.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use nsshared_mock_rendezvous::Limits;
use nsshared_rendezvous::{
    auth::Hello,
    error::ErrorCode,
    limits::{MAX_UNACKED_MESSAGES, MAX_WAIT_MS},
    message::{Admission, Digits, Kind, MailboxId, OpenRequest, RecvRequest},
    pairing::transfer_open_request,
    transport::{MAX_MESSAGE_BYTES, PATH, Request, Response, encode_request},
};
use support::{Client, Mock, key, relaxed_limits};
use tokio_tungstenite::tungstenite::{Message, http::StatusCode};

const DIRECTORY: &str = r#"{"operation":"directory","value":null}"#;

fn owner_open(candidates: u8) -> OpenRequest {
    OpenRequest {
        kind: Kind::parse("test").unwrap(),
        ttl: 300,
        admission: Admission::Owner,
        candidates,
        intro: Vec::new(),
    }
}

fn digits(text: &str) -> Digits {
    Digits::parse(text).unwrap()
}

/// A mailbox with `admission = first` opened by `owner_key` and joined by `peer_key`.
async fn admitted(
    mock: &Mock,
    owner_key: &SigningKey,
    peer_key: &SigningKey,
) -> (Client, Client, MailboxId) {
    let mut owner = mock.actor(owner_key).await;
    let opened = owner
        .open(transfer_open_request(300, Vec::new()).unwrap())
        .await;
    let mut peer = mock.actor(peer_key).await;
    peer.join(opened.id, Vec::new()).await.unwrap();
    (owner, peer, opened.id)
}

#[tokio::test]
async fn message_size_limit() {
    let mock = Mock::start(relaxed_limits()).await;
    let mut client = mock.connect().await;

    // Exactly the limit is accepted.
    let padded = format!("{DIRECTORY:<MAX_MESSAGE_BYTES$}");
    assert_eq!(padded.len(), MAX_MESSAGE_BYTES);
    assert!(matches!(client.raw(&padded).await, Response::Directory(_)));

    // One byte more closes the connection without an answer.
    client.send_text(format!("{padded} ")).await;
    match tokio::time::timeout(support::STEP, client.socket.next())
        .await
        .unwrap()
    {
        None | Some(Ok(Message::Close(_)) | Err(_)) => {}
        Some(other) => panic!("expected the connection to close, got {other:?}"),
    }
    mock.stop().await;
}

#[tokio::test]
async fn malformed_and_unknown_input() {
    let mock = Mock::start(relaxed_limits()).await;
    let mut client = mock.actor(&key(1)).await;
    for text in [
        "{",
        "not json",
        "[]",
        r#"{"operation":"directory"}"#,
        r#"{"operation":"directory","value":null,"extra":1}"#,
        r#"{"operation":"teleport","value":null}"#,
        r#"{"operation":"close","value":{"id":"AAAAAAAAAAAAAAAAAAAAAA","extra":1}}"#,
    ] {
        assert_eq!(
            client.raw(text).await,
            Response::Error(ErrorCode::InvalidMessage),
            "{text}"
        );
    }
    // The connection stays usable.
    assert!(matches!(
        client.raw(DIRECTORY).await,
        Response::Directory(_)
    ));

    // `wait_ms` above 20 000 is rejected on decode.
    let opened = client.open(owner_open(1)).await;
    let recv = encode_request(&Request::Recv(RecvRequest {
        id: opened.id,
        after: 0,
        wait_ms: MAX_WAIT_MS + 1,
    }))
    .unwrap();
    assert_eq!(
        client.raw(&recv).await,
        Response::Error(ErrorCode::InvalidMessage)
    );
    assert!(client.recv(opened.id, 0, 1).await.is_ok());

    // Unknown digits do not locate a mailbox.
    assert_eq!(
        client.lookup(&digits("00000000")).await,
        Err(ErrorCode::InvalidCode)
    );
    mock.stop().await;
}

#[tokio::test]
async fn hello_binding() {
    let mock = Mock::start(relaxed_limits()).await;

    // Mailbox operations before `hello`.
    let mut client = mock.connect().await;
    assert_eq!(
        client.error(&Request::Open(owner_open(1))).await,
        ErrorCode::InvalidActor
    );
    assert_eq!(
        client.lookup(&digits("12345678")).await,
        Err(ErrorCode::InvalidActor)
    );

    // A signature over another nonce does not bind.
    let stale = Hello::sign(&key(1), &[1; 32], &mock.authority());
    assert_eq!(
        client.error(&Request::Hello(stale)).await,
        ErrorCode::InvalidActor
    );

    // A good `hello` binds once; a repeated one is refused.
    client.hello(&key(1)).await;
    let again = Hello::sign(&key(2), &client.nonce(), &mock.authority());
    assert_eq!(
        client.error(&Request::Hello(again)).await,
        ErrorCode::InvalidActor
    );
    mock.stop().await;
}

#[tokio::test]
async fn stage_capacity_and_queue_limits() {
    let mock = Mock::start(Limits {
        mailboxes_per_actor: 1,
        ..relaxed_limits()
    })
    .await;

    // `send` while the mailbox is `open`.
    let mut owner = mock.actor(&key(1)).await;
    let opened = owner.open(owner_open(1)).await;
    assert_eq!(
        owner.send(opened.id, b"early".to_vec()).await,
        Err(ErrorCode::WrongStage)
    );

    // Live mailboxes per actor.
    assert_eq!(
        owner.error(&Request::Open(owner_open(1))).await,
        ErrorCode::Capacity
    );

    // Candidates per mailbox.
    let mut first = mock.actor(&key(2)).await;
    first.join(opened.id, Vec::new()).await.unwrap();
    let mut second = mock.actor(&key(3)).await;
    assert_eq!(
        second.join(opened.id, Vec::new()).await,
        Err(ErrorCode::Capacity)
    );
    // The waiting candidate is at its own per-actor limit too.
    let mut other_owner = mock.actor(&key(4)).await;
    let other = other_owner.open(owner_open(1)).await;
    assert_eq!(
        first.join(other.id, Vec::new()).await,
        Err(ErrorCode::Capacity)
    );

    // Unacknowledged messages per direction.
    let (mut sender, mut receiver, id) = admitted(&mock, &key(5), &key(6)).await;
    for seq in 1..=MAX_UNACKED_MESSAGES {
        assert_eq!(
            sender.send(id, vec![1]).await.unwrap().seq,
            u64::try_from(seq).unwrap()
        );
    }
    assert_eq!(sender.send(id, vec![1]).await, Err(ErrorCode::QueueFull));
    // Acknowledging frees the queue.
    let view = receiver.recv(id, 0, 0).await.unwrap();
    assert_eq!(view.messages.len(), MAX_UNACKED_MESSAGES);
    receiver
        .recv(id, u64::try_from(MAX_UNACKED_MESSAGES).unwrap(), 0)
        .await
        .unwrap();
    assert!(sender.send(id, vec![1]).await.is_ok());
    mock.stop().await;
}

#[tokio::test]
async fn open_and_lookup_rate_limits() {
    let mock = Mock::start(Limits {
        opens_per_ip_per_minute: 2,
        lookups_per_ip_per_minute: 2,
        ..relaxed_limits()
    })
    .await;
    let mut first = mock.actor(&key(1)).await;
    let mut second = mock.actor(&key(2)).await;

    first.open(owner_open(1)).await;
    first.open(owner_open(1)).await;
    // The limit is per source IP, not per connection.
    assert_eq!(
        second.error(&Request::Open(owner_open(1))).await,
        ErrorCode::RateLimited
    );

    let unknown = digits("00000000");
    assert_eq!(first.lookup(&unknown).await, Err(ErrorCode::InvalidCode));
    assert_eq!(first.lookup(&unknown).await, Err(ErrorCode::InvalidCode));
    assert_eq!(second.lookup(&unknown).await, Err(ErrorCode::RateLimited));
    mock.stop().await;
}

#[tokio::test]
async fn global_pending_recv_limit() {
    let mock = Mock::start(Limits {
        pending_recv: 1,
        ..relaxed_limits()
    })
    .await;
    let (mut owner, mut peer, id) = admitted(&mock, &key(1), &key(2)).await;

    // The owner's long poll takes the only pending slot; it retries if the peer's
    // probe held the slot at that moment.
    let polling = tokio::spawn(async move {
        loop {
            match owner.recv(id, 0, MAX_WAIT_MS).await {
                Err(ErrorCode::Capacity) => continue,
                view => return view,
            }
        }
    });
    // Probe with short polls until the slot is taken by the owner.
    loop {
        match peer.recv(id, 0, 1).await {
            Err(ErrorCode::Capacity) => break,
            view => assert!(view.unwrap().messages.is_empty()),
        }
    }

    // The peer's send wakes the owner, which releases the slot.
    peer.send(id, b"wake".to_vec()).await.unwrap();
    let view = tokio::time::timeout(support::STEP, polling)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(view.messages[0].data, b"wake");
    assert!(peer.recv(id, 0, 1).await.is_ok());
    mock.stop().await;
}

#[tokio::test]
async fn refused_upgrades() {
    let mock = Mock::start(relaxed_limits()).await;
    assert_eq!(mock.refused("/quick/v1", true).await, StatusCode::NOT_FOUND);
    assert_eq!(mock.refused("/", true).await, StatusCode::NOT_FOUND);
    assert_eq!(mock.refused(PATH, false).await, StatusCode::BAD_REQUEST);
    mock.stop().await;
}
