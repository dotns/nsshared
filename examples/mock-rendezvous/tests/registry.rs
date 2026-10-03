//! Registry `publish` and `lookup_node` over the mock (quick-v2 §3.3, §7.2): hit, miss,
//! supersession, stale and conflicting generations, the conflict latch and the proof
//! binding to the connection's challenge.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

mod support;

use ed25519_dalek::SigningKey;
use nsshared_proto::rendezvous::{
    error::ErrorCode,
    message::{LookupNodeRequest, PublishRequest, RecordResult},
    registry,
    transport::{Request, Response},
};
use nsshared_proto::{NodeId, NodeRecord, NodeRecordFields, RelayId};
use support::{Client, Mock, key, now, relaxed_limits};

fn record(identity: &SigningKey, authority: &RelayId, generation: u64, wg: u8) -> NodeRecord {
    let now = now();
    NodeRecord::sign(
        identity,
        NodeRecordFields {
            wg_key: [wg; 32],
            generation,
            issued_at: now - 10,
            expires: now + 3600,
            relays: vec![authority.clone()],
        },
    )
    .unwrap()
}

fn publish_on(client: &Client, identity: &SigningKey, record: &NodeRecord) -> PublishRequest {
    registry::publish_request(
        identity,
        &client.nonce(),
        &client.challenge.authority,
        record,
        false,
    )
}

/// Publishes `record` and returns the stored expiry or the error.
async fn publish(
    client: &mut Client,
    identity: &SigningKey,
    record: &NodeRecord,
) -> Result<u64, ErrorCode> {
    let request = Request::Publish(publish_on(client, identity, record));
    match client.request(&request).await {
        Response::Published(published) => Ok(published.expires),
        Response::Error(code) => Err(code),
        other => panic!("expected published, got {other:?}"),
    }
}

async fn lookup_node(
    client: &mut Client,
    identity: &SigningKey,
) -> Result<RecordResult, ErrorCode> {
    let node_id = NodeId::derive(&identity.verifying_key().to_bytes());
    let request = Request::LookupNode(LookupNodeRequest {
        node_id: *node_id.as_bytes(),
    });
    match client.request(&request).await {
        Response::Record(result) => Ok(result),
        Response::Error(code) => Err(code),
        other => panic!("expected record, got {other:?}"),
    }
}

#[tokio::test]
async fn publish_lookup_and_ordering() {
    let mock = Mock::start(relaxed_limits()).await;
    let authority = mock.authority();
    let identity = key(1);
    // Registry operations need no `hello`.
    let mut client = mock.connect().await;

    // Miss before publishing.
    assert_eq!(
        lookup_node(&mut client, &identity).await,
        Ok(RecordResult { record: None })
    );

    // Publish, then hit.
    let gen1 = record(&identity, &authority, 1, 1);
    assert_eq!(
        publish(&mut client, &identity, &gen1).await,
        Ok(gen1.expires())
    );
    let found = lookup_node(&mut client, &identity).await.unwrap();
    let bytes = found.record.unwrap();
    let verified = registry::verify_lookup_result(&gen1.node_id(), &bytes, now()).unwrap();
    assert_eq!(verified, gen1);

    // A higher generation supersedes.
    let gen2 = record(&identity, &authority, 2, 2);
    publish(&mut client, &identity, &gen2).await.unwrap();
    let found = lookup_node(&mut client, &identity).await.unwrap();
    assert_eq!(found.record.as_deref(), Some(gen2.as_bytes()));

    // A lower generation is stale.
    assert_eq!(
        publish(&mut client, &identity, &gen1).await,
        Err(ErrorCode::Conflict)
    );
    assert_eq!(
        lookup_node(&mut client, &identity)
            .await
            .unwrap()
            .record
            .as_deref(),
        Some(gen2.as_bytes())
    );

    // Same generation, different K: conflict, latched for lookups.
    let rival = record(&identity, &authority, 2, 3);
    assert_eq!(
        publish(&mut client, &identity, &rival).await,
        Err(ErrorCode::Conflict)
    );
    assert_eq!(
        lookup_node(&mut client, &identity).await,
        Err(ErrorCode::Conflict)
    );
    // Even the original record is refused while latched.
    assert_eq!(
        publish(&mut client, &identity, &gen2).await,
        Err(ErrorCode::Conflict)
    );

    // A higher generation clears the latch.
    let gen3 = record(&identity, &authority, 3, 3);
    publish(&mut client, &identity, &gen3).await.unwrap();
    assert_eq!(
        lookup_node(&mut client, &identity)
            .await
            .unwrap()
            .record
            .as_deref(),
        Some(gen3.as_bytes())
    );
    mock.stop().await;
}

#[tokio::test]
async fn proof_is_bound_to_the_connection_nonce() {
    let mock = Mock::start(relaxed_limits()).await;
    let identity = key(1);
    let record = record(&identity, &mock.authority(), 1, 1);
    let mut first = mock.connect().await;
    let second = mock.connect().await;
    assert_ne!(first.nonce(), second.nonce());

    // Signed for the second connection's challenge, sent on the first.
    let foreign = Request::Publish(publish_on(&second, &identity, &record));
    assert_eq!(first.error(&foreign).await, ErrorCode::InvalidMessage);
    assert_eq!(
        lookup_node(&mut first, &identity).await,
        Ok(RecordResult { record: None })
    );

    // The same record with a proof over the first connection's nonce is accepted.
    assert!(publish(&mut first, &identity, &record).await.is_ok());
    mock.stop().await;
}
