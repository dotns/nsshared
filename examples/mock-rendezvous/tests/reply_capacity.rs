//! Full mailbox replies remain encodable after every newly accepted write.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "isolated TLS test fixtures"
)]

mod support;

use nsshared_rendezvous::{
    error::ErrorCode,
    message::{Admission, Kind, OpenRequest},
};
use support::{Mock, key, relaxed_limits};

fn spec(admission: Admission) -> OpenRequest {
    OpenRequest {
        kind: Kind::parse("reply-capacity").unwrap(),
        ttl: 600,
        admission,
        candidates: if admission == Admission::First { 1 } else { 4 },
        intro: vec![],
    }
}

#[tokio::test]
async fn oversized_candidate_write_is_refused_before_the_owner_view_breaks() {
    let mock = Mock::start(relaxed_limits()).await;
    let mut owner = mock.actor(&key(1)).await;
    let o = owner.open(spec(Admission::Owner)).await;
    let mut first = mock.actor(&key(2)).await;
    let mut second = mock.actor(&key(3)).await;
    let mut third = mock.actor(&key(4)).await;
    first.join(o.id, vec![2; 4096]).await.unwrap();
    second.join(o.id, vec![3; 4096]).await.unwrap();
    assert_eq!(
        third.join(o.id, vec![4; 4096]).await,
        Err(ErrorCode::Capacity)
    );
    let reply = owner.recv(o.id, 0, 0).await.unwrap();
    assert_eq!(reply.waiting.len(), 2);
    assert_eq!(reply.waiting[1].intro, vec![3; 4096]);
    first.close(o.id).await.unwrap();
    third.join(o.id, vec![4; 4096]).await.unwrap();
    assert_eq!(owner.recv(o.id, 0, 0).await.unwrap().waiting.len(), 2);
    mock.stop().await;
}

#[tokio::test]
async fn oversized_queued_write_refuses_then_retries_after_ack_without_sequence_loss() {
    let mock = Mock::start(relaxed_limits()).await;
    let mut owner = mock.actor(&key(11)).await;
    let o = owner.open(spec(Admission::First)).await;
    let mut peer = mock.actor(&key(12)).await;
    peer.join(o.id, vec![]).await.unwrap();
    assert_eq!(owner.send(o.id, vec![1; 8192]).await.unwrap().seq, 1);
    assert_eq!(
        owner.send(o.id, vec![2; 8192]).await,
        Err(ErrorCode::QueueFull)
    );
    let reply = peer.recv(o.id, 0, 0).await.unwrap();
    assert_eq!(reply.messages.len(), 1);
    assert_eq!(reply.messages[0].data, vec![1; 8192]);
    assert!(peer.recv(o.id, 1, 0).await.unwrap().messages.is_empty());
    assert_eq!(owner.send(o.id, vec![2; 8192]).await.unwrap().seq, 2);
    assert_eq!(
        peer.recv(o.id, 1, 0).await.unwrap().messages[0].data,
        vec![2; 8192]
    );
    mock.stop().await;
}
