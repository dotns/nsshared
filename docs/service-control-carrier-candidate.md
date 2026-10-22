# Candidate service control carrier

This is a pure candidate contract, with no transport, persistence, session state
or I/O. NSD adoption and independent real producer review remain outstanding.
The lifecycle reference is repository `ns`,
`docs/plan/20261017-m6-service-contract.md` at
`0e5adc17c9b05ae7fa351de00a5184a57b92e584`, sections 1–6 and 10.
Its historical ControlEnvelope/JSON carrier is replaced by this mapping.

## Unary operation

`account::control_exchange::SERVICE_CONTROL` is `service.control.v1`, on the
existing confidential `/api/v1/control` endpoint. The Node signs Request
BootstrapEnvelopes addressed to its authenticated NSD; NSD signs Responses
addressed to the Node. Existing B43 signature domains, trust pins, recipient,
clock, replay and size checks apply. Except for the receipt below, payload is
exactly `nsshared_service_control::Message::encode()` bytes, decoded only by
`Message::decode`. Outer operation and inner MessageBody kind are distinct.

| Node request body | Successful response |
| --- | --- |
| RuntimeFloor | RuntimeFloorResult |
| RuntimeBind | RuntimeBindResult |
| SessionOpen | SessionOpenResult |
| ReportHead | ReportHeadResult |
| ReportReplace | ReportAccepted |
| ListenerReady, LeaseRefresh | LeaseResult |
| LeaseAcquire | LeaseResult for its sole service |
| SnapshotAck, PortResult, PortQueryResult, ServiceRetryPort | Empty carrier receipt |

No other body is a Node unary request. Every response echoes the pending outer
nonce. A logical retry keeps M6 request_id, exact content and original lease
timing anchor, using a fresh outer nonce. PendingRequest retains the exact
validated message, NSD identity and nonce; consumers retain its association with
current contribution/source ownership before calling validate_unary_reply.

A receipt is an authenticated Response with exactly zero payload bytes, never
CBOR null, an empty Message, HTTP-only success or Error. It confirms carrier
acceptance only, never application, termination, readiness, lease authority or
completion of a retry allocation round. It is refused for other requests and on
streams. ServiceRetryPort refusal, including recovery-required, is failure.

Typed replies compare request_id, NSD/Network, subject, runtime pair, epoch and
session. Floor/bind results echo the supplied optional/runtime pair, carry the
current positive epoch consistently with their body and have no session. They
do not compare an unknown request epoch for equality. SessionOpenResult echoes
the requested session. ReportAccepted matches the submitted revision/digest.
Publisher LeaseResult matches service, listener revision/digest and refresh_seq;
consumer LeaseResult additionally matches consumer_seq and snapshot revision/digest.
On this carrier LeaseAcquire must contain exactly one service. Empty and batched
requests are refused without changing the underlying M6 list type; use separate
logical requests with distinct request_id and scope/runtime consumer_seq values.

Error is a separately returned failure, never success. It matches NSD/Network,
subject and request_id, echoes the supplied runtime pair, and has no session.
Non-bootstrap errors echo the request epoch; floor with a supplied runtime pair
and bind errors carry NSD's current positive epoch. The outer nonce and retained
pending context supply session ownership. Floor without a runtime pair cannot
receive a representable Error. Such failures, pre-decode failures and failures
without correlation facts are carrier failures; no runtime or epoch is fabricated.
Typed negative lease/port results retain their existing meanings.

## Subscription binding

PublicationSubscriptionRequest is exactly
`[1, subscriber_I, scopes, capabilities, public_ingress, boot_nonce,
attempt_counter, service_control]`.
This eight-element tuple is **breaking for existing consumers**; seven elements
are refused with no fallback. The appended slot is null or exactly
`[nsd_id, network_id, runtime_generation, runtime_id, authority_epoch,
session_seq, session_request_id]`. IDs are M6 16-byte strings; the three counters
are positive u64 values. Other seven fields retain all existing meanings.

The caller authenticates current contribution/source authority independently.
It persists a runtime, reserves a fresh session_seq and logical SessionOpen
request_id for each actual connection attempt, obtains admission, then sends
that exact accepted tuple. session_request_id is the accepted SessionOpen id,
not the envelope nonce or publication boot_nonce. Each stream binds one Network;
separate Networks use separate bound attempts. No binding permits no M6 delivery.
The authority compares the full tuple against its current persisted admitted
session and contribution before delivery. Ordinary publication authority and
versions remain independent; this slot grants no scope. Reconnect opens a new
session and retains replay observations and content floors.

## Stream events and reverse operations

SSE name is `service.control.v1`; data is URL-safe unpadded Base64 of a complete
signed BootstrapEnvelope. Response direction, operation, authenticated NSD
signer and mandatory Node recipient are checked. Payload is exactly one
SnapshotPush, PortCancel or PortQuery Message. No receipt or other body is
accepted. The event nonce is generated by NSD under existing replay rules;
there is no pending unary nonce correlation.

validate_stream_event compares NSD/Network, subject, runtime, epoch and session
against the accepted stream binding and exact authenticated authority/subject.
Consumers additionally compare retained current contribution/source ownership.
For SnapshotPush they compare persistent snapshot revisions/digests and apply
existing application/ready rules; a snapshot or ACK never grants a lease.

NSD retains each reverse operation's request_id and exact proposal under the
current session. Node compares it against persisted proposal/ownership state,
durably handles cancel or reads query state, then sends a unary PortResult for
cancel or PortQueryResult for query, using a fresh Node outer nonce.
validate_reverse_result compares the retained operation with every answer
proposal field and its request_id, NSD/Network, subject, runtime, epoch and
session. Its empty receipt echoes this new unary nonce. Unsolicited PortResult
uses a Node-produced request_id and requires the consumer's known proposal.
Cancel delivery and receipt are never termination proof: the consumer checks
the durable terminal floor and pinned lifecycle rules. Contribution withdrawal
or replacement fences pending requests and streams; P06 source epochs/generations
are never substituted for M6 epochs/generations. Original report ownership and
bytes remain unchanged.

## Pure API and evidence

`account::service_control` exposes ServiceControlBinding, PendingRequest,
UnaryReply, validate_unary_request, validate_unary_reply, validate_stream_event
and validate_reverse_result. Authentication, clocks, replay observations and
accepted stream facts are caller supplied. The independent Python producer and
`contribution_network_sessions` consumer test exercise exact bytes for two
Networks, receipts, failures/bootstrap results, singleton leases and reverse
operations, with encoding, bounds, cross-Network and stale-session refusals.
Fixture acceptance is candidate evidence, never NSD interoperability agreement.
