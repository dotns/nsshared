# nsshared-rendezvous spec coverage

Specification-to-code table for the `nsshared-rendezvous` crate (NS rendezvous v2,
`/quick/v2`: mailbox, registry, pairing and region forwarding messages,
migration milestone M1), and the description of the independent vector
generator `tools/vectors`.

## Notes

- **Docs pin.** Every reference is to docs commit `957de97a79f7`; line ranges
  are those of that commit. Read a section with
  `git -C <docs checkout> show 957de97a79f7:website/src/content/docs/<path>`.
- **Paths.** Code paths are relative to `crates/nsshared-rendezvous/src`, test paths
  to `crates/nsshared-rendezvous/tests`. `file.rs::name` names an item or a test
  function. Items of the `nsshared-wire` crate are written `nsshared_wire::Name`; its own
  coverage is [nsshared-wire spec coverage](nsshared-wire.md).
- **Scope.** `ns/rendezvous.md` §3-§7, §9.1, §9.2 and §11, and the
  rendezvous-facing parts of `ns/quick-v2.md` (§2.3, §3.2, §7, §8.5 types
  10-12, §10.2, §12). Every other quick-v2 section is covered by nsshared-wire.
- **Status values.** `implemented`; `out of scope: <owner>` for behaviour this
  pure library (no I/O, clocks, randomness, storage, timers or connection
  state; callers pass `now`, ids, digits, nonces and keys) leaves to a caller;
  `deferred: <reason>`. Owners: **nsgw relay** (migration M2: the `/quick/v2`
  broker, its storage, sweeps and rate limits, region forwarding and registry
  replication), **nsplane client** (the node-side rendezvous client and the
  pairing and transfer endpoint protocols).
- **Regenerate / verify.** Rows are maintained by hand against the pinned
  docs. To check that every referenced test and source file exists, run from
  the repository root:

  ```sh
  grep -oE 'tests/[a-z_]+\.rs::[a-z0-9_]+' docs/spec-coverage/nsshared-rendezvous.md | sort -u |
    while IFS=: read -r file _ name; do
      grep -qE "fn ${name}\(" "crates/nsshared-rendezvous/${file}" || echo "missing ${file}::${name}"
    done
  grep -oE 'src/[a-z_/]+\.rs' docs/spec-coverage/nsshared-rendezvous.md | sort -u |
    while read -r file; do [ -f "crates/nsshared-rendezvous/${file}" ] || echo "missing ${file}"; done
  ```

  When the docs pin moves, diff the pinned sections
  (`git -C <docs> diff 957de97a79f7 <new> -- website/src/content/docs/ns/`)
  and update the affected rows and line ranges.

## Decisions

Transport decisions fixed for the crate scaffold (D1-D10), recorded in the
code docs of `src/transport.rs`, `src/auth.rs` and `src/message.rs`:

1. **D1 bytes.** Every byte string is unpadded base64url, decoded strictly
   (padding and non-zero trailing bits rejected).
   `src/transport.rs::decode_base64url`.
2. **D2 payload-less messages.** The `directory` operation and the `ok` result
   carry `"value": null`; both envelope keys are always present.
   `src/transport.rs::Request`, `src/transport.rs::Response`.
3. **D3 errors.** An error response is `{"result": "error", "value": "<code>"}`.
   `src/error.rs::ErrorCode`.
4. **D4 challenge.** The broker's first message is
   `{"result": "challenge", "value": {nonce, authority, capabilities}}`, not
   an answer to a request. `src/auth.rs::Challenge`.
5. **D5 lookup.** The `lookup` value is the 8 digits as a JSON string, leading
   zeros kept. `src/message.rs::Digits`.
6. **D6 node ID.** `lookup_node.node_id` is the 12 raw bytes in base64url
   (rendezvous §3 byte rule), not base32 text.
   `src/message.rs::LookupNodeRequest`.
7. **D7 records.** `publish.record` and `record.record` are canonical NodeRecord
   CBOR bytes; `published.expires` is u64 Unix seconds.
   `src/message.rs::PublishRequest`, `src/message.rs::RecordResult`.
8. **D8 integers.** JSON integers are parsed exactly as u64; floats and
   negatives are rejected. `src/message.rs`.
9. **D9 hello.** The signed message is `"ns-quick-actor-v2\0" ‖ nonce ‖
   authority` UTF-8 bytes, with no length prefixes. `src/auth.rs::Hello`.
10. **D10 hello exemptions.** The rendezvous §4 word "lookup" in the
    no-`hello` list means `lookup_node` (§5.2 table); the mailbox `lookup`
    requires `hello`. `src/transport.rs::Operation::requires_hello`.

Encoding choice: JSON output is compact and follows the spec field order, so
the fixtures are stable (`tests/transport.rs::encodings_are_compact_and_in_spec_field_order`).

Decisions of the module tasks (R2-R5) and of the NodeRecord validity task (S1):

11. **Rejected set (R2).** Only rejected candidates enter the rejected-actor set
    (rendezvous §5.3 records rejected candidates); an evicted peer is not
    added. Clearing a queue on eviction keeps its sequence counter, so a stale
    `after` never acknowledges a later message. `src/phase.rs::Mailbox::reject`.
12. **Not responsible (R3).** A `publish` for a node ID outside this relay's
    lenient responsibility (among the first four HRW relays) is
    `invalid_message`: rendezvous §7 has no more specific code.
    `src/registry.rs::check_responsible`.
13. **Publish while conflicted (R3).** While a conflict is latched, a publish
    below a higher `gen` (a §3.3 refresh or an unchanged record) is also
    `conflict`; a rejected publish changes neither the record nor `dns`.
    `src/registry.rs::RegistryEntry::apply_publish`.
14. **Pairing name bound (R4).** `name` in Invite and Join is UTF-8 of at most
    64 bytes; quick-v2 §10.2 gives no bound. Encoded Invite and Join must fit
    the 4 KiB `intro` limit, pairing messages the 8 KiB `data` limit.
    `src/pairing.rs::MAX_NAME_BYTES`.
15. **Region bodies 10-12 (R5, Y1, Y2).** Types 10-12 are control-connection
    only (Y2); frames of types 10 and 11 on the control connection may reach
    20480 bytes, every other frame stays at 4096 (Y1). RENDEZVOUS_REQUEST is
    `[request_id u64, owner_epoch u64, client_addr [ip, port], challenge_nonce
    bytes32, actor bytes32 | null, request text]`, RENDEZVOUS_RESPONSE is
    `[request_id u64, owner_epoch u64, response text]` with owner-epoch
    fencing to `unavailable`, and REGISTRY_RECORD is `[record, dns bool,
    challenge_nonce bytes32, proof bytes64]`, applied on the receiver as a
    local `publish`. `hello` and `directory` are never forwarded. The full
    proposed quick-v2 §8.5 text is in the module docs of `src/region.rs`.
16. **Service period (S1).** A NodeRecord with `expires - issued_at > 604800`
    is invalid (quick-v2 §3.2, bound from §3.1 and §12.3);
    `nsshared_wire::NodeRecord::decode` rejects it, so `registry::verify_publish`,
    the pairing payload decoders and REGISTRY_RECORD reject it too.

## ns/rendezvous.md

| Spec reference | Requirement | Code | Tests | Status |
| --- | --- | --- | --- | --- |
| ns/rendezvous.md §3 (28) | `wss://{authority}/quick/v2`, subprotocol `ns-quick-v2`; TLS as v1 | `src/transport.rs::PATH`, `src/transport.rs::SUBPROTOCOL` | `tests/transport.rs::constants` | constants implemented; WebSocket and TLS: out of scope: nsgw relay, nsplane client |
| ns/rendezvous.md §3 (29) | One JSON message per text message, at most 16 KiB checked before parsing; byte strings unpadded base64url (D1) | `src/transport.rs::MAX_MESSAGE_BYTES`, `src/transport.rs::decode_request`, `src/transport.rs::decode_response`, `src/transport.rs::encode_base64url`, `src/transport.rs::decode_base64url`, `src/transport.rs::Base64Error` | `tests/transport.rs::oversize_messages_are_rejected_before_parsing`, `tests/transport.rs::byte_strings_are_strict_unpadded_base64url`, `tests/vectors_mailbox.rs::rejected_messages_match_vectors` | implemented |
| ns/rendezvous.md §3 (30) | `{"operation", "value"}` requests and `{"result", "value"}` responses, snake_case names, unknown fields rejected (D2, D3, D8) | `src/transport.rs::Request`, `src/transport.rs::Response`, `src/transport.rs::Operation`, `src/transport.rs::encode_request`, `src/transport.rs::encode_response`, `src/transport.rs::UnknownName` | `tests/transport.rs::every_request_round_trips`, `tests/transport.rs::every_response_round_trips`, `tests/transport.rs::encodings_are_compact_and_in_spec_field_order`, `tests/transport.rs::envelope_keys_are_required_and_unknown_keys_rejected`, `tests/transport.rs::payload_fields_are_required_and_unknown_fields_rejected`, `tests/transport.rs::structs_are_objects_and_names_are_strings`, `tests/transport.rs::out_of_range_values_are_rejected`, `tests/vectors_mailbox.rs::valid_requests_match_vectors`, `tests/vectors_mailbox.rs::valid_responses_match_vectors` | implemented; in-order processing, one response per request: out of scope: nsgw relay |
| ns/rendezvous.md §3 (31) | Broker sends `challenge {nonce, authority, capabilities}` first (D4); nonce not all zero; client disconnects on an unexpected authority | `src/auth.rs::Challenge` (`check_authority`), `src/auth.rs::AuthError::AuthorityMismatch`, `src/transport.rs::Response::Challenge` | `tests/auth.rs::challenge_authority_must_match`, `tests/auth.rs::challenge_decoding_validates_nonce_and_authority`, `tests/vectors_mailbox.rs::valid_responses_match_vectors` | checks implemented; sending first and disconnecting: out of scope: nsgw relay, nsplane client |
| ns/rendezvous.md §3.1 (35) | One token set in directory entries, the `challenge` and the relay packet handshake reply | `src/directory.rs::RelayEntry::capabilities`, `src/auth.rs::Challenge` | `tests/capability.rs::challenge`, `tests/directory.rs::entry_fields_and_relay_id` | implemented; relay packet reply: see nsshared-wire §8.2 rows |
| ns/rendezvous.md §3.1 (37-43) | Tokens `udp`, `wss`, `mailbox`, `region`, `registry` | `src/capability.rs::UDP`, `src/capability.rs::WSS`, `src/capability.rs::MAILBOX`, `src/capability.rs::REGION`, `src/capability.rs::REGISTRY` | `tests/capability.rs::known_tokens` | implemented |
| ns/rendezvous.md §3.1 (45) | `[a-z0-9.-]{1,32}`, at most 16, unknown tokens ignored | `src/capability.rs::Capability::parse`, `src/capability.rs::Capabilities` (`new`, `contains`), `src/capability.rs::MAX_CAPABILITY_BYTES`, `src/capability.rs::MAX_CAPABILITIES`, `src/capability.rs::CapabilityError` | `tests/capability.rs::token_syntax`, `tests/capability.rs::unknown_tokens_are_kept_and_ignored`, `tests/capability.rs::at_most_sixteen_tokens`, `tests/capability.rs::malformed_or_too_many_tokens_reject_the_message` | implemented |
| ns/rendezvous.md §3.1 (46) | Token vocabulary lives in nsshared, shared by relay and node | `src/capability.rs` | `tests/capability.rs::known_tokens` | implemented |
| ns/rendezvous.md §3.1 (47) | Capabilities never authorize; the connected announcement wins over the directory hint | none | none | out of scope: nsgw relay, nsplane client |
| ns/rendezvous.md §4 (51) | Every request except `directory`, `publish` and `lookup_node` runs as an actor after `hello` (D10) | `src/transport.rs::Operation::requires_hello` | `tests/transport.rs::only_directory_publish_and_lookup_node_skip_hello` | implemented; refusing requests before `hello`: out of scope: nsgw relay |
| ns/rendezvous.md §4 (53-58) | `hello {actor, signature}`, signature over `"ns-quick-actor-v2\0" ‖ nonce ‖ authority` (D9) | `src/auth.rs::Hello` (`sign`, `verify`), `src/auth.rs::ACTOR_CONTEXT`, `src/transport.rs::Request::Hello` | `tests/auth.rs::hello_signs_context_nonce_and_authority`, `tests/vectors_hello.rs::hello_signatures_match_vectors` | implemented |
| ns/rendezvous.md §4 (60) | Strict Ed25519 verification; one `hello` per connection; later requests belong to the actor | `src/auth.rs::Hello::verify`, `src/auth.rs::AuthError::InvalidSignature` (`invalid_actor`) | `tests/auth.rs::hello_rejects_wrong_nonce_authority_actor_and_signature`, `tests/vectors_hello.rs::rejected_hellos_match_vectors` | verification implemented; connection binding and the single `hello`: out of scope: nsgw relay |
| ns/rendezvous.md §4 (61) | Actor keys are fresh per mailbox and never a device identity | none | none | out of scope: nsplane client |
| ns/rendezvous.md §4 (62) | Reconnect on any member with a new challenge and the same actor; no `resume` | `src/phase.rs::Mailbox` (transitions take the actor, not a connection) | none | state model implemented; reconnecting: out of scope: nsplane client, nsgw relay |
| ns/rendezvous.md §5.1 (68-84) | Mailbox model: 16-byte id, `kind` `[a-z0-9-]{1,32}`, owner, admission, candidates 1-4 (1 for `first`), `expires <= now + 900`, 8 digits, intro, waiting, peer, rejects, two queues, stage | `src/phase.rs::Mailbox`, `src/phase.rs::Actor`, `src/message.rs::MailboxId`, `src/message.rs::Kind`, `src/message.rs::Admission`, `src/message.rs::Stage`, `src/message.rs::Digits` (`Hash` for a broker lookup index), `src/message.rs::Waiting`, `src/limits.rs::MAILBOX_ID_BYTES`, `src/limits.rs::DIGITS_LEN` | `tests/phase.rs::open_validates_the_request`, `tests/transport.rs::lookup_digits_and_kind_are_validated`, `tests/phase.rs::expires_never_changes`, `tests/phase.rs::digits_key_a_lookup_index_by_value` | implemented; generating ids and digits: out of scope: nsgw relay |
| ns/rendezvous.md §5.2 (88-101) | Request and result table: `directory`, `publish`, `lookup_node`, `hello`, `open`, `lookup` (D5), `join`, `admit`, `reject`, `send`, `recv`, `close` | `src/transport.rs::Request`, `src/transport.rs::Response`, `src/message.rs::OpenRequest`, `src/message.rs::JoinRequest`, `src/message.rs::AdmitRequest`, `src/message.rs::RejectRequest`, `src/message.rs::SendRequest`, `src/message.rs::RecvRequest`, `src/message.rs::CloseRequest`, `src/message.rs::Opened`, `src/message.rs::Found`, `src/message.rs::Sent`, `src/message.rs::MailboxView`, `src/message.rs::MailboxMessage` | `tests/transport.rs::every_request_round_trips`, `tests/transport.rs::every_response_round_trips`, `tests/transport.rs::lookup_digits_and_kind_are_validated`, `tests/vectors_mailbox.rs::valid_requests_match_vectors`, `tests/vectors_mailbox.rs::valid_responses_match_vectors` | implemented |
| ns/rendezvous.md §5.2 (103) | `ttl` 1-900 s; `intro` at most 4 KiB, `data` at most 8 KiB | `src/limits.rs::MIN_TTL_SECONDS`, `src/limits.rs::MAX_TTL_SECONDS`, `src/limits.rs::MAX_INTRO_BYTES`, `src/limits.rs::MAX_DATA_BYTES`, `src/message.rs::OpenRequest`, `src/message.rs::SendRequest` | `tests/transport.rs::out_of_range_values_are_rejected`, `tests/phase.rs::open_validates_the_request`, `tests/vectors_mailbox.rs::rejected_messages_match_vectors` | implemented |
| ns/rendezvous.md §5.2 (104) | `recv` returns `waiting` only to the owner and only messages to the requester with `seq > after`; `after` acknowledges and deletes | `src/phase.rs::Mailbox::recv`, `src/message.rs::MailboxView` | `tests/phase.rs::recv_views_by_role`, `tests/phase.rs::closing_drains_then_removes_on_acknowledgement` | implemented |
| ns/rendezvous.md §5.2 (105) | `wait_ms` 0-20000; any change wakes a pending `recv` at once | `src/limits.rs::MAX_WAIT_MS`, `src/message.rs::RecvRequest`, `src/phase.rs::Outcome` (`wake`) | `tests/transport.rs::out_of_range_values_are_rejected`, `tests/phase.rs::admit_makes_the_peer_and_drops_the_others` | validation and wake lists implemented; long-poll timing: out of scope: nsgw relay |
| ns/rendezvous.md §5.3 (111) | `open`: stage `open`, non-colliding 8 digits | `src/phase.rs::Mailbox::open` | `tests/phase.rs::open_validates_the_request` | implemented; digit allocation and retry: out of scope: nsgw relay |
| ns/rendezvous.md §5.3 (112) | `join` with `admission = owner`: added to `waiting`, `capacity` when full, owner cannot join | `src/phase.rs::Mailbox::join` | `tests/phase.rs::join_with_owner_admission`, `tests/phase.rs::join_outside_open_is_wrong_stage` | implemented |
| ns/rendezvous.md §5.3 (113) | `join` with `admission = first`: becomes the peer, stage `admitted`, digits removed | `src/phase.rs::Mailbox::join`, `src/phase.rs::IndexChange` | `tests/phase.rs::join_with_first_admission` | implemented |
| ns/rendezvous.md §5.3 (114) | `admit`: candidate becomes the peer, stage `admitted`, digits and other candidates removed | `src/phase.rs::Mailbox::admit` | `tests/phase.rs::admit_makes_the_peer_and_drops_the_others` | implemented |
| ns/rendezvous.md §5.3 (115) | `reject` of a candidate removes it; the actor can never join again before expiry (decision 11) | `src/phase.rs::Mailbox::reject`, `src/phase.rs::Mailbox::rejected` | `tests/phase.rs::reject_records_a_candidate`, `tests/phase.rs::rejected_set_is_bounded` | implemented |
| ns/rendezvous.md §5.3 (116) | `reject` of the peer: queues cleared, peer cleared, back to `open` with the same digits, `rejects + 1`, closed at 3 | `src/phase.rs::Mailbox::reject`, `src/limits.rs::MAX_PEER_REJECTS` | `tests/phase.rs::reject_evicts_the_peer_and_restores_the_digits`, `tests/phase.rs::third_eviction_closes_the_mailbox`, `tests/phase.rs::reject_of_a_closing_peer_is_wrong_stage` | implemented |
| ns/rendezvous.md §5.3 (117) | `send` only in `admitted`; `seq` per direction from 1 | `src/phase.rs::Mailbox::send` | `tests/phase.rs::send_is_admitted_only_and_counts_per_direction` | implemented |
| ns/rendezvous.md §5.3 (118) | Owner or peer `close`: stage `closing`, no new `send`, the other side drains; removed on acknowledgement, the other side's `close` or after 30 s | `src/phase.rs::Mailbox::close`, `src/phase.rs::Mailbox::removal_due`, `src/limits.rs::CLOSING_GRACE_SECONDS` | `tests/phase.rs::owner_close_of_an_open_mailbox_removes_it`, `tests/phase.rs::closing_drains_then_removes_on_acknowledgement`, `tests/phase.rs::closing_with_an_empty_queue_shows_closing_once`, `tests/phase.rs::closing_removes_when_the_other_side_closes`, `tests/phase.rs::closing_removes_after_the_grace_period` | implemented |
| ns/rendezvous.md §5.3 (119) | Candidate `close` removes only itself | `src/phase.rs::Mailbox::close` | `tests/phase.rs::candidate_close_removes_only_itself` | implemented |
| ns/rendezvous.md §5.3 (120) | Owner or peer inactive for 180 s removes the mailbox, checked every 10 s | `src/phase.rs::Mailbox::removal_due`, `src/limits.rs::INACTIVITY_SECONDS`, `src/limits.rs::SWEEP_INTERVAL_SECONDS` | `tests/phase.rs::inactivity_removes_the_mailbox` | rule implemented; sweeping: out of scope: nsgw relay |
| ns/rendezvous.md §5.3 (121) | Absolute expiry removes within 10 s; lifetime never above 15 minutes, not even across restarts | `src/phase.rs::Mailbox::removal_due` | `tests/phase.rs::absolute_expiry_removes_the_mailbox`, `tests/phase.rs::expires_never_changes` | rule implemented; sweeping and restart handling: out of scope: nsgw relay |
| ns/rendezvous.md §5.3 (123) | Lookups, candidates and rejected guesses never extend a mailbox or invalidate others | `src/phase.rs::Mailbox::lookup_view`, `src/phase.rs::Mailbox` (no transition changes `expires`) | `tests/phase.rs::expires_never_changes` | implemented |
| ns/rendezvous.md §5.3 (124) | Mailbox state in private storage, apart from the permanent safety marks | none | none | out of scope: nsgw relay |
| ns/rendezvous.md §5.3 (125) | One rendezvous owner per owner epoch in a region; members forward requests; pending `recv` held by the owner; a fence change answers `unavailable` (decision 15) | `src/region.rs::RendezvousRequest`, `src/region.rs::RendezvousResponse` (`unavailable`, `client_response`), `src/region.rs::check_owner_epoch`, `src/error.rs::ErrorCode::retry_on_next_member` | `tests/region.rs::request_round_trips_with_ipv4_and_null_actor`, `tests/region.rs::request_round_trips_with_ipv6_and_actor`, `tests/region.rs::refutation_request_hello_and_directory_are_never_forwarded`, `tests/region.rs::response_owner_epoch_fencing`, `tests/error.rs::only_unavailable_moves_to_the_next_member`, `tests/vectors_region.rs::valid_bodies_match_vectors` | forwarding bodies and fencing decisions implemented; owner election, forwarding and holding `recv`: out of scope: nsgw relay |
| ns/rendezvous.md §5.4 (131-141) | `Directory {version >= 1, relays}` (at most 576); `RelayEntry {id != 0, code, host, ips 1-4, port, capabilities}` | `src/directory.rs::Directory` (`new`), `src/directory.rs::RelayEntry` (`new`), `src/directory.rs::MAX_RELAYS`, `src/directory.rs::MAX_RELAY_IPS`, `src/directory.rs::CODE_LETTERS`, `src/directory.rs::DirectoryError` | `tests/directory.rs::entry_fields_and_relay_id`, `tests/directory.rs::entry_field_rules`, `tests/directory.rs::directory_rules`, `tests/directory.rs::at_most_576_relays`, `tests/directory.rs::decoding_validates_every_rule` | implemented |
| ns/rendezvous.md §5.4 (143) | Relay identity is `host:port` | `src/directory.rs::RelayEntry::relay_id` | `tests/directory.rs::entry_fields_and_relay_id` | implemented |
| ns/rendezvous.md §5.4 (144) | Connect to `ips` and `port`, SNI and certificate check with `host`, optional DNS refresh | none | none | out of scope: nsplane client |
| ns/rendezvous.md §5.4 (145) | `id`, `code`, `host` unique; ids and codes permanent; updates add entries or change `ips` / `capabilities` with a higher version; equal versions identical; short code letters per quick §4 | `src/directory.rs::Directory::new`, `src/directory.rs::check_update`, `src/directory.rs::CODE_LETTERS` | `tests/directory.rs::directory_rules`, `tests/directory.rs::update_rules` | implemented; unknown-prefix refresh: out of scope: nsplane client |
| ns/rendezvous.md §5.4 (146) | Built-in directory uses `*.relay.ns.io` names | none | none | out of scope: nsplane client |
| ns/rendezvous.md §6 (152-153) | 10000 stored mailboxes; 3 active mailboxes per actor | `src/phase.rs::check_stored_mailboxes`, `src/phase.rs::check_actor_mailboxes`, `src/phase.rs::check_stored_mailboxes_within`, `src/phase.rs::check_actor_mailboxes_within` (configured limits), `src/limits.rs::MAX_MAILBOXES`, `src/limits.rs::MAX_MAILBOXES_PER_ACTOR` | `tests/phase.rs::broker_limits`, `tests/phase.rs::broker_limits_within_a_configured_limit` | checks implemented; counting: out of scope: nsgw relay |
| ns/rendezvous.md §6 (154-156) | 4 candidates, 16 rejected actors, 3 peer rejects per mailbox | `src/limits.rs::MAX_CANDIDATES`, `src/limits.rs::MAX_REJECTED_ACTORS`, `src/limits.rs::MAX_PEER_REJECTS` | `tests/phase.rs::join_with_owner_admission`, `tests/phase.rs::rejected_set_is_bounded`, `tests/phase.rs::third_eviction_closes_the_mailbox` | implemented |
| ns/rendezvous.md §6 (157) | `intro` / `data` 4 KiB / 8 KiB | see §5.2 (103) row | see §5.2 (103) row | implemented |
| ns/rendezvous.md §6 (158-159) | Per direction 16 unacknowledged messages / 64 KiB; per mailbox 256 messages / 512 KiB cumulative | `src/phase.rs::Mailbox::send`, `src/limits.rs::MAX_UNACKED_MESSAGES`, `src/limits.rs::MAX_UNACKED_BYTES`, `src/limits.rs::MAX_MAILBOX_MESSAGES`, `src/limits.rs::MAX_MAILBOX_BYTES` | `tests/phase.rs::unacknowledged_message_limit_per_direction`, `tests/phase.rs::unacknowledged_byte_limit_per_direction`, `tests/phase.rs::cumulative_message_limit_per_mailbox`, `tests/phase.rs::cumulative_byte_limit_per_mailbox` | implemented |
| ns/rendezvous.md §6 (160-161) | 64 MiB queued bytes globally; pending `recv` 1 per connection, 4096 globally | `src/phase.rs::check_queued_bytes`, `src/phase.rs::check_pending_recv`, `src/phase.rs::check_queued_bytes_within`, `src/phase.rs::check_pending_recv_within` (configured limits), `src/phase.rs::Mailbox::queued_bytes`, `src/limits.rs::MAX_QUEUED_BYTES`, `src/limits.rs::MAX_PENDING_RECV_PER_CONNECTION`, `src/limits.rs::MAX_PENDING_RECV` | `tests/phase.rs::broker_limits`, `tests/phase.rs::broker_limits_within_a_configured_limit` | checks implemented; counting: out of scope: nsgw relay |
| ns/rendezvous.md §6 (162) | Message size 16 KiB | `src/limits.rs::MAX_MESSAGE_BYTES`, `src/transport.rs::MAX_MESSAGE_BYTES` | `tests/transport.rs::oversize_messages_are_rejected_before_parsing` | implemented |
| ns/rendezvous.md §6 (163-165) | Lookup, open and per-connection request rates | `src/limits.rs::LOOKUPS_PER_IP_PER_MINUTE`, `src/limits.rs::LOOKUPS_PER_SECOND`, `src/limits.rs::OPENS_PER_IP_PER_MINUTE`, `src/limits.rs::OPENS_PER_SECOND`, `src/limits.rs::REQUESTS_PER_CONNECTION_PER_SECOND` | none | constants implemented (no direct test); enforcement: out of scope: nsgw relay |
| ns/rendezvous.md §6 (167) | Every limit is a relay configuration item; the table gives production defaults | `src/limits.rs` (module docs) | none | defaults implemented; configuration: out of scope: nsgw relay |
| ns/rendezvous.md §7 (171) | Exactly 15 error codes | `src/error.rs::ErrorCode` (`ALL`, `as_str`, `FromStr`), `src/error.rs::UnknownErrorCode` | `tests/error.rs::exactly_the_fifteen_codes` | implemented |
| ns/rendezvous.md §7 (173) | Errors never carry digits, payloads or untrusted input; only transport failures and `unavailable` move to the next region member | `src/error.rs::ErrorCode` (a code is the whole error), `src/error.rs::ErrorCode::retry_on_next_member` | `tests/error.rs::only_unavailable_moves_to_the_next_member` | implemented; retrying: out of scope: nsplane client |
| ns/rendezvous.md §9.1 (189-195) | Pairing on the mailbox: `open {admission: owner, candidates: 4, intro: Invite}`, `join {intro: Join}`, ACCEPT and COMPLETE through `send` | `src/pairing.rs::pairing_open_request`, `src/pairing.rs::KIND_PAIRING`, `src/pairing.rs::PAIRING_CANDIDATES` | `tests/pairing.rs::pairing_open_request_maps_rendezvous_9_1` | mailbox mapping implemented; payloads: see quick-v2 §10.2 rows; the step sequence: out of scope: nsplane client |
| ns/rendezvous.md §9.1 (197) | v1 `Hello`, `SealedToken` and pairing tokens removed | none (no such types) | none | implemented |
| ns/rendezvous.md §9.2 (201-207) | File transfer: `open {admission: first, candidates: 1, intro: CPace Ya}`; CPace, `TransferHello`, `reject` on a wrong password | `src/pairing.rs::transfer_open_request`, `src/pairing.rs::KIND_TRANSFER` | `tests/pairing.rs::transfer_open_request_maps_rendezvous_9_2` | mailbox mapping implemented; CPace and the transfer protocol: out of scope: nsplane client |
| ns/rendezvous.md §11 (221) | Path and subprotocol `/quick/v2`, `ns-quick-v2` | see §3 (28) row | see §3 (28) row | implemented |
| ns/rendezvous.md §11 (222) | One `hello` per connection with an ephemeral actor key instead of per-request proofs | see §4 rows | see §4 rows | implemented |
| ns/rendezvous.md §11 (223-225) | Application-neutral operations, two acknowledged queues, `recv` long poll instead of v1 invite / select / deliver / poll | see §5.2 and §5.3 rows | see §5.2 and §5.3 rows | implemented |
| ns/rendezvous.md §11 (226) | Byte strings as base64url instead of JSON arrays | see §3 (29) row | see §3 (29) row | implemented |
| ns/rendezvous.md §11 (227-228) | Capability announcements; directory `host`, `ips`, `port`, `capabilities` | see §3.1 and §5.4 rows | see §3.1 and §5.4 rows | implemented |

## ns/quick-v2.md

| Spec reference | Requirement | Code | Tests | Status |
| --- | --- | --- | --- | --- |
| ns/quick-v2.md §2.3 (69-79) | Demo identity seeds `SHA-256(label)` | none in this crate; the generator derives every seed the same way (`tools/vectors/nsvec/derive.py`) | none in this crate | implemented in nsshared-wire (see its §2.3 row) and in the generator |
| ns/quick-v2.md §3.2 (105-107) | Records are valid only with a service period of at most 604800 s (decision 16); relays do not answer with expired records | `nsshared_wire::NodeRecord::decode` through `src/registry.rs::verify_publish`, `src/pairing.rs::Invite::decode`, `src/pairing.rs::Join::decode`, `src/region.rs::RegistryRecord::decode_body`; expiry: `src/registry.rs::lookup`, `src/registry.rs::RegistryEntry::apply_publish` | `tests/registry.rs::service_period_above_seven_days_is_rejected`, `tests/registry.rs::invalid_or_expired_records_are_rejected`, `tests/pairing.rs::decode_rejects_a_record_with_an_overlong_service_period`, `tests/pairing.rs::verify_rejects_an_expired_record`, `tests/region.rs::refutation_registry_record_invalid_nested_record`, `tests/vectors_registry.rs::rejected_publishes_match_vectors` | implemented |
| ns/quick-v2.md §7.1 (185) | Registry domain = directory entries announcing `registry`, or the single configured relay | `src/registry.rs::registry_domain`, `src/registry.rs::single_relay_domain` | `tests/registry.rs::registry_domain_keeps_only_registry_entries`, `tests/registry.rs::small_domains` | implemented |
| ns/quick-v2.md §7.1 (186) | HRW weight `BLAKE2s(out = 8, key = "ns-registry-shard-v2")(node_id ‖ id_be16)`, descending, ties by `id` ascending, first two | `src/registry.rs::shard_weight`, `src/registry.rs::shard_order`, `src/registry.rs::shard_relays`, `src/registry.rs::SHARD_LABEL` | `tests/registry.rs::shard_weight_is_keyed_blake2s_of_node_id_and_be16_id`, `tests/registry.rs::shard_order_sorts_by_weight_descending`, `tests/vectors_registry.rs::shard_order_matches_vectors` | implemented |
| ns/quick-v2.md §7.1 (187) | A directory change moves few shards; republish after it; lookups ask the first two, then the third and fourth | `src/registry.rs::lookup_relays` | `tests/registry.rs::adding_one_entry_moves_only_shards_that_now_include_it`, `tests/registry.rs::small_domains` | ordering implemented; republishing and lookup order: out of scope: nsplane client |
| ns/quick-v2.md §7.1 (188) | Region shard relays replicate records in REGISTRY_RECORD under §3.3 (decision 15) | `src/region.rs::RegistryRecord` (`new`, `apply`, `encode_body`, `decode_body`, `encode_frame`, `decode_frame`) | `tests/region.rs::registry_record_round_trips`, `tests/region.rs::refutation_registry_record_shape`, `tests/region.rs::registry_record_applies_through_the_registry_entry`, `tests/region.rs::registry_record_dns_follows_the_winning_record`, `tests/region.rs::registry_record_conflict_is_latched_locally`, `tests/region.rs::refutation_registry_record_apply`, `tests/vectors_region.rs::valid_bodies_match_vectors` | body and apply implemented; sending to every member: out of scope: nsgw relay |
| ns/quick-v2.md §7.2 (192-197) | `publish {record, dns, proof}` → `published {expires}`, `lookup_node {node_id}` → `record {record}` or `null`, no `hello` (D6, D7) | `src/message.rs::PublishRequest`, `src/message.rs::Published`, `src/message.rs::LookupNodeRequest`, `src/message.rs::RecordResult`, `src/transport.rs::Operation::requires_hello` | `tests/transport.rs::every_request_round_trips`, `tests/transport.rs::every_response_round_trips`, `tests/transport.rs::only_directory_publish_and_lookup_node_skip_hello`, `tests/vectors_mailbox.rs::valid_requests_match_vectors` | implemented; offering them only with `registry`: out of scope: nsgw relay |
| ns/quick-v2.md §7.2 (199) | `proof = Ed25519_I("ns/registry-publish/v2" ‖ nonce ‖ authority ‖ SHA-256(record) ‖ dns_u8)` | `src/registry.rs::publish_proof_message`, `src/registry.rs::create_publish_proof`, `src/registry.rs::publish_request`, `src/registry.rs::PUBLISH_CONTEXT` | `tests/registry.rs::proof_message_layout`, `tests/registry.rs::proof_round_trip`, `tests/registry.rs::proof_fails_for_any_changed_input`, `tests/vectors_registry.rs::publish_proofs_match_vectors` | implemented |
| ns/quick-v2.md §7.2 (200) | Relay checks validity, expiry, proof and lenient responsibility, then §3.3; `conflict` or `invalid_message` (decisions 12, 13) | `src/registry.rs::verify_publish`, `src/registry.rs::VerifiedPublish`, `src/registry.rs::is_responsible`, `src/registry.rs::check_responsible`, `src/registry.rs::RegistryEntry::apply_publish` | `tests/registry.rs::any_flipped_record_byte_is_rejected`, `tests/registry.rs::invalid_or_expired_records_are_rejected`, `tests/registry.rs::first_publish_is_accepted`, `tests/registry.rs::higher_generation_is_accepted_and_lower_rejected`, `tests/registry.rs::same_generation_refresh_replaces_the_record`, `tests/registry.rs::conflict_latches_until_a_higher_generation`, `tests/registry.rs::apply_rejects_foreign_or_expired_publishes`, `tests/vectors_registry.rs::rejected_publishes_match_vectors` | implemented |
| ns/quick-v2.md §7.2 (201) | `dns` follows the most recent accepted publish | `src/registry.rs::RegistryEntry::dns` | `tests/registry.rs::dns_follows_the_latest_accepted_publish` | choice implemented; DNS publication: out of scope: nsgw relay |
| ns/quick-v2.md §7.2 (202) | `lookup_node`: full 12-byte ID, unexpired records only, `conflict` while latched, no enumeration | `src/registry.rs::lookup`, `src/message.rs::LookupNodeRequest` | `tests/registry.rs::lookup_semantics` | implemented |
| ns/quick-v2.md §7.2 (203) | Records deleted within 10 s after `expires` | `src/registry.rs::RegistryEntry::deletion_due`, `src/registry.rs::DELETION_GRACE_SECONDS` | `tests/registry.rs::deletion_grace`, `tests/registry.rs::deleted_state_accepts_a_fresh_record` | rule implemented; deleting: out of scope: nsgw relay |
| ns/quick-v2.md §7.3 (207-212) | When nodes publish and look up | none | none | out of scope: nsplane client |
| ns/quick-v2.md §7.4 (216-220) | 10⁷ records, `capacity` when full; publish and `lookup_node` rates | `src/registry.rs::MAX_RECORDS`, `src/registry.rs::PUBLISHES_PER_IP_PER_MINUTE`, `src/registry.rs::PUBLISH_INTERVAL_PER_IDENTITY_SECONDS`, `src/registry.rs::PUBLISHES_PER_SECOND`, `src/registry.rs::LOOKUP_NODES_PER_IP_PER_MINUTE`, `src/registry.rs::LOOKUP_NODES_PER_SECOND` | `tests/registry.rs::constants_match_the_spec` | constants implemented; enforcement: out of scope: nsgw relay |
| ns/quick-v2.md §7.5 (224) | Clients check `BLAKE2s-96(I) = node ID`, validity and expiry of a lookup result | `src/registry.rs::verify_lookup_result`, `src/registry.rs::LookupError` | `tests/registry.rs::client_verifies_lookup_results` | implemented |
| ns/quick-v2.md §8.5 (301) | RENDEZVOUS_REQUEST / RENDEZVOUS_RESPONSE bodies (control only, up to 20480 bytes) and REGISTRY_RECORD body (control only, 4096) (decision 15) | `src/region.rs::RendezvousRequest`, `src/region.rs::ClientAddr`, `src/region.rs::RendezvousResponse`, `src/region.rs::RegistryRecord`, `src/region.rs::RegionBodyError` | `tests/region.rs::request_frames_above_4096_bytes_on_control_only`, `tests/region.rs::request_publish_carries_the_proof_nonce`, `tests/region.rs::refutation_request_zero_id_and_zero_nonce`, `tests/region.rs::refutation_request_wrong_arity_and_trailing_bytes`, `tests/region.rs::refutation_request_client_addr`, `tests/region.rs::refutation_request_actor_shape`, `tests/region.rs::refutation_request_oversize_json`, `tests/region.rs::refutation_request_invalid_json`, `tests/region.rs::refutation_request_frame_type_and_channel_size`, `tests/region.rs::response_round_trips`, `tests/region.rs::response_frames_above_4096_bytes`, `tests/region.rs::refutation_response_rules`, `tests/region.rs::refutation_response_shape`, `tests/vectors_region.rs::valid_bodies_match_vectors`, `tests/vectors_region.rs::rejected_bodies_match_vectors` | implemented |
| ns/quick-v2.md §10.2 (346-347) | Invite `[ver = 2, record_a, e_a, authority, expires, name, sig_a]`, signed under `ns/pairing-invite/v2` (decision 14) | `src/pairing.rs::Invite` (`create`, `decode`), `src/pairing.rs::INVITE_CONTEXT`, `src/pairing.rs::PAIRING_VERSION`, `src/pairing.rs::MAX_NAME_BYTES` | `tests/pairing.rs::invite_round_trips_and_matches_an_independent_encoding`, `tests/pairing.rs::invite_without_name_round_trips`, `tests/pairing.rs::names_are_bounded`, `tests/pairing.rs::decode_rejects_an_invalid_authority_or_record`, `tests/vectors_pairing.rs::pairing_sessions_match_vectors` | implemented |
| ns/quick-v2.md §10.2 (348-349) | Join `[ver = 2, record_b, e_b, mailbox_id, invite_hash, name, sig_b]`, signed under `ns/pairing-join/v2` | `src/pairing.rs::Join` (`create`, `decode`), `src/pairing.rs::JOIN_CONTEXT` | `tests/pairing.rs::join_round_trips_and_verifies`, `tests/vectors_pairing.rs::pairing_sessions_match_vectors` | implemented |
| ns/quick-v2.md §10.2 (350-352) | Message `[ver = 2, type, body]`: ACCEPT `[join_hash, sig]` under `ns/pairing-accept/v2`, COMPLETE `[]` | `src/pairing.rs::PairingMessage` (`accept`, `encode`, `decode`), `src/pairing.rs::MESSAGE_ACCEPT`, `src/pairing.rs::MESSAGE_COMPLETE`, `src/pairing.rs::ACCEPT_CONTEXT` | `tests/pairing.rs::messages_round_trip`, `tests/pairing.rs::decode_rejects_unknown_message_types`, `tests/vectors_pairing.rs::pairing_sessions_match_vectors` | implemented |
| ns/quick-v2.md §10.2 (353) | `invite_hash` / `join_hash` = SHA-256 of the complete encodings | `src/pairing.rs::Invite::hash`, `src/pairing.rs::Join::hash` | `tests/pairing.rs::join_round_trips_and_verifies`, `tests/vectors_pairing.rs::pairing_sessions_match_vectors` | implemented |
| ns/quick-v2.md §10.2 (354, 357) | `psk = HKDF-SHA256(X25519(e_a, e_b), info = "ns/pairing-psk/v2" ‖ I_a ‖ I_b ‖ invite_hash ‖ join_hash)`; all-zero DH rejected; ephemerals fresh per pairing | `src/pairing.rs::pairing_psk`, `src/pairing.rs::PSK_CONTEXT`, `src/crypto.rs` (`hkdf_sha256`, `x25519`) | `tests/pairing.rs::both_sides_derive_the_same_psk`, `tests/pairing.rs::psk_rejects_an_all_zero_dh_result`, `tests/vectors_pairing.rs::pairing_sessions_match_vectors`; `src/crypto.rs` unit tests `hkdf_rfc5869_test_cases_1_and_3`, `x25519_rfc7748_section_6_1`, `x25519_rejects_a_small_order_public_key` | derivation implemented; generating and discarding ephemerals: out of scope: nsplane client |
| ns/quick-v2.md §10.2 (359) | Step 1: `open {kind: "pairing", admission: owner, candidates: 4, ttl, intro: Invite}`, `ttl` default 600, at most 900 | `src/pairing.rs::pairing_open_request`, `src/pairing.rs::DEFAULT_PAIRING_TTL_SECONDS`, `src/pairing.rs::MAX_PAIRING_TTL_SECONDS` | `tests/pairing.rs::pairing_open_request_maps_rendezvous_9_1`, `tests/pairing.rs::constants_match_the_spec` | implemented; short codes: out of scope: nsplane client |
| ns/quick-v2.md §10.2 (360) | Step 2: joiner checks signature, record, signer = `record_a.I`, `authority` = dialed relay, `now < expires`; `Removed` and address-group checks | `src/pairing.rs::Invite::verify`, `nsshared_wire::check_address_conflict` (caller) | `tests/pairing.rs::invite_verify_rejects_a_tampered_signature`, `tests/pairing.rs::invite_verify_rejects_a_signer_other_than_the_record`, `tests/pairing.rs::invite_verify_rejects_another_relay`, `tests/pairing.rs::invite_verify_rejects_expiry`, `tests/pairing.rs::verify_rejects_an_expired_record`, `tests/vectors_pairing.rs::rejected_pairing_payloads_match_vectors` | payload checks implemented; `Removed`, address-group check and confirmation: out of scope: nsplane client |
| ns/quick-v2.md §10.2 (361) | Step 3: `join {id, intro: Join}` | `src/message.rs::JoinRequest`, `src/pairing.rs::Join::create` | `tests/pairing.rs::join_round_trips_and_verifies` | implemented |
| ns/quick-v2.md §10.2 (362) | Step 4: inviter checks signature, record, `mailbox_id`, `invite_hash`; `admit` one, `reject` the rest, send ACCEPT | `src/pairing.rs::Join::verify`, `src/pairing.rs::PairingMessage::accept` | `tests/pairing.rs::join_verify_rejects_a_tampered_signature`, `tests/pairing.rs::join_verify_rejects_a_signer_other_than_the_record`, `tests/pairing.rs::join_verify_rejects_another_mailbox`, `tests/pairing.rs::join_verify_rejects_another_invite_hash`, `tests/vectors_pairing.rs::rejected_pairing_payloads_match_vectors` | payload checks implemented; `Removed`, address-group check and selection: out of scope: nsplane client |
| ns/quick-v2.md §10.2 (363-365) | Steps 5-7: install after ACCEPT, prepare within 5 s, COMPLETE and `close` | `src/pairing.rs::verify_accept` | `tests/pairing.rs::accept_verifies_for_the_joiner`, `tests/pairing.rs::accept_rejects_another_join_hash`, `tests/pairing.rs::accept_rejects_a_tampered_or_foreign_signature`, `tests/pairing.rs::verify_accept_rejects_complete` | ACCEPT check implemented; installing, preparing and closing: out of scope: nsplane client |
| ns/quick-v2.md §10.2 (367) | The relay cannot forge Invite, Join or ACCEPT | `src/pairing.rs::Invite::verify`, `src/pairing.rs::Join::verify`, `src/pairing.rs::verify_accept` | see the steps 2, 4 and 5-7 rows | implemented |
| ns/quick-v2.md §12.1 (411) | Canonical CBOR mailbox payloads and region bodies; non-canonical input and trailing bytes rejected before signatures | `src/pairing.rs::PairingError`, `src/region.rs::RegionBodyError` (both on `nsshared_wire::CborReader` / `nsshared_wire::CborWriter`) | `tests/pairing.rs::decode_rejects_trailing_bytes`, `tests/pairing.rs::decode_rejects_unknown_versions`, `tests/pairing.rs::decode_rejects_wrong_array_lengths`, `tests/pairing.rs::decode_rejects_oversize_payloads`, `tests/region.rs::refutation_request_wrong_arity_and_trailing_bytes`, `tests/region.rs::refutation_registry_record_shape`, `tests/vectors_pairing.rs::rejected_pairing_payloads_match_vectors`, `tests/vectors_region.rs::rejected_bodies_match_vectors` | implemented |
| ns/quick-v2.md §12.2 (415) | Pure Ed25519 with strict verification | `src/crypto.rs` (`verify_strict`) | `tests/auth.rs::hello_rejects_wrong_nonce_authority_actor_and_signature`, `tests/registry.rs::proof_fails_for_any_changed_input`, `tests/pairing.rs::accept_rejects_a_tampered_or_foreign_signature`; `src/crypto.rs` unit test `verify_strict_accepts_only_valid_signatures` | implemented |
| ns/quick-v2.md §12.2 (420, 424-425) | Contexts `ns/registry-publish/v2`, `ns/pairing-invite/v2`, `ns/pairing-join/v2`, `ns/pairing-accept/v2`, `ns/pairing-psk/v2` | `src/registry.rs::PUBLISH_CONTEXT`, `src/pairing.rs::INVITE_CONTEXT`, `src/pairing.rs::JOIN_CONTEXT`, `src/pairing.rs::ACCEPT_CONTEXT`, `src/pairing.rs::PSK_CONTEXT` | `tests/registry.rs::constants_match_the_spec`, `tests/pairing.rs::constants_match_the_spec`, `tests/vectors_registry.rs::publish_proofs_match_vectors`, `tests/vectors_pairing.rs::pairing_sessions_match_vectors` | implemented |
| ns/quick-v2.md §12.3 (432) | Record service period at most 604800 s (decision 16) | see §3.2 row | see §3.2 row | implemented |
| ns/quick-v2.md §12.3 (440) | Registry shard replicas 2, lookups ask at most 4 | `src/registry.rs::shard_relays`, `src/registry.rs::lookup_relays` (`nsshared_wire::REGISTRY_SHARD_REPLICAS`, `nsshared_wire::REGISTRY_LOOKUP_MAX`) | `tests/registry.rs::small_domains`, `tests/vectors_registry.rs::shard_order_matches_vectors` | implemented |
| ns/quick-v2.md §12.3 (441) | Pairing mailbox TTL default 600 s, at most 900 s | `src/pairing.rs::DEFAULT_PAIRING_TTL_SECONDS`, `src/pairing.rs::MAX_PAIRING_TTL_SECONDS` | `tests/pairing.rs::constants_match_the_spec` | implemented |

## Vectors

`tools/vectors` is an independent conformance vector generator for both
crates. It implements the specification text with the Python standard library
only (pure Ed25519 with strict verification, X25519, SHA-256, keyed BLAKE2s,
HKDF-SHA256 and the canonical CBOR subset of quick-v2 §12.1) and never builds,
calls or reads the output of the Rust crates, so the fixtures cross-check the
implementation.

- **Layout.** `tools/vectors/generate.py` is the entry point;
  `tools/vectors/nsvec` holds the primitives, `nsvec/selftest.py` (every
  primitive is checked against RFC 8032, RFC 7748, RFC 5869 and RFC 8949
  vectors before any fixture is written) and `nsvec/producers`, one module per
  fixture file with `CRATE`, `GROUP`, `TITLE`, `SECTIONS` and `vectors()`.
- **Fixtures.** Each producer writes
  `crates/<crate>/tests/fixtures/vectors/<group>.vec`. nsshared-wire: `identities`,
  `lan6`, `alias4`, `node_records`, `relay_packets`, `control_messages`,
  `region_frames` (consumed by the nsshared-wire `vectors_*` tests). nsshared-rendezvous:
  `hello`, `registry`, `pairing`, `mailbox_json`, `region_bodies` (consumed by
  `tests/vectors_hello.rs`, `tests/vectors_registry.rs`,
  `tests/vectors_pairing.rs`, `tests/vectors_mailbox.rs` and
  `tests/vectors_region.rs` through `tests/support/vectors.rs`).
- **Format.** A `.vec` file starts with `#` header lines naming the title, the
  generator, the docs pin and the spec sections. Vectors are separated by one
  blank line; each line is `key = value`, with bytes as lowercase hex,
  integers in decimal and text verbatim to the end of the line. Every vector
  starts with `name = ...`; negative vectors carry `expect = reject` and
  `reason = ...`. Fixtures are generated, never edited by hand.
- **Commands.** `just vectors` runs the self-test and rewrites every fixture.
  `just vectors-check` runs the self-test and fails on any missing, extra or
  differing fixture; it is part of `just qa`.
