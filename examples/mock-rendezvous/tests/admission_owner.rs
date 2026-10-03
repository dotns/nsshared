//! `admission = owner` end to end over the mock (rendezvous §4, §5): two joiners, reject
//! and admit, a message waking a long poll, a reply, close, and an owner reconnecting on a
//! new connection. Intros and messages are opaque bytes, as the relay sees them.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use nsshared_proto::rendezvous::{
    error::ErrorCode,
    message::{Admission, AdmitRequest, Kind, OpenRequest, RejectRequest, Stage},
    transport::Request,
};
use std::time::Duration;
use support::{Mock, key, relaxed_limits};

#[tokio::test]
async fn owner_admission_end_to_end() {
    let mock = Mock::start(relaxed_limits()).await;
    let (actor_a, actor_b, actor_c) = (key(101), key(102), key(103));

    // The owner opens the mailbox with an opaque intro.
    let mut owner = mock.actor(&actor_a).await;
    let opened = owner
        .open(OpenRequest {
            kind: Kind::parse("test").unwrap(),
            ttl: 600,
            admission: Admission::Owner,
            candidates: 4,
            intro: b"offer".to_vec(),
        })
        .await;
    let id = opened.id;

    // Two joiners find the intro and join with their own.
    let mut joiner_b = mock.actor(&actor_b).await;
    let found = joiner_b.lookup(&opened.digits).await.unwrap();
    assert_eq!((found.id, found.kind.as_str()), (id, "test"));
    assert_eq!(found.intro, b"offer");
    joiner_b.join(id, b"answer-b".to_vec()).await.unwrap();
    let mut joiner_c = mock.actor(&actor_c).await;
    joiner_c.join(id, b"answer-c".to_vec()).await.unwrap();

    // The owner reconnects: a new connection, a new challenge, the same actor key.
    drop(owner);
    let mut owner = mock.connect().await;
    owner.hello(&actor_a).await;

    // The owner sees both candidates with their intros, rejects one and admits the other.
    let view = owner.recv(id, 0, 0).await.unwrap();
    assert_eq!(view.stage, Stage::Open);
    let actor_b_public = actor_b.verifying_key().to_bytes();
    let actor_c_public = actor_c.verifying_key().to_bytes();
    let waiting: Vec<_> = view
        .waiting
        .iter()
        .map(|waiting| (waiting.actor, waiting.intro.clone()))
        .collect();
    assert_eq!(
        waiting,
        [
            (actor_b_public, b"answer-b".to_vec()),
            (actor_c_public, b"answer-c".to_vec())
        ]
    );
    let reject = Request::Reject(RejectRequest {
        id,
        actor: actor_c_public,
    });
    assert!(support::ok(owner.request(&reject).await).is_ok());
    let admit = Request::Admit(AdmitRequest {
        id,
        actor: actor_b_public,
    });
    assert!(support::ok(owner.request(&admit).await).is_ok());

    // The rejected actor cannot join again.
    assert_eq!(
        joiner_c.join(id, b"answer-c".to_vec()).await,
        Err(ErrorCode::NotPermitted)
    );

    // The joiner's long poll is woken by the owner's message.
    let (polled, sent) = tokio::join!(joiner_b.recv(id, 0, 20_000), async {
        // Let the long poll reach the server first; it is answered either way.
        tokio::time::sleep(Duration::from_millis(100)).await;
        owner.send(id, b"accept".to_vec()).await
    });
    assert_eq!(sent.unwrap().seq, 1);
    let view = polled.unwrap();
    assert_eq!(view.stage, Stage::Admitted);
    assert_eq!(view.peer, Some(actor_b_public));
    assert_eq!(view.messages.len(), 1);
    assert_eq!(view.messages[0].data, b"accept");

    // The joiner replies and closes; the owner reads the reply and closes.
    let reply = joiner_b.send(id, b"complete".to_vec()).await.unwrap();
    assert_eq!(reply.seq, 1);
    joiner_b.close(id).await.unwrap();
    let view = owner.recv(id, 0, 20_000).await.unwrap();
    assert_eq!(view.stage, Stage::Closing);
    assert_eq!(view.messages[0].data, b"complete");
    owner.close(id).await.unwrap();

    // The mailbox is gone for both sides.
    assert_eq!(owner.recv(id, 0, 0).await, Err(ErrorCode::UnknownMailbox));
    assert_eq!(
        joiner_b.recv(id, 0, 0).await,
        Err(ErrorCode::UnknownMailbox)
    );
    assert_eq!(
        joiner_c.lookup(&opened.digits).await,
        Err(ErrorCode::InvalidCode)
    );
    mock.stop().await;
}
