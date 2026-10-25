# 20261022-2237-service-control-carrier Service control carrier

- **status**: completed
- **createdAt**: 2026-10-22 22:37
- **approvedAt**: 2026-10-22 22:37
- **relatedTask**: 20261022-2237-service-control-carrier

## Context

PublicationSubscriptionRequest currently has seven fields. BootstrapEnvelope already authenticates opaque payloads; Message owns the exact M6 codec. No candidate correlation or reverse-operation validator exists.

## Proposal

Define the candidate wire mapping and independent Python vectors first. Add a pure carrier module with authenticated request decoding, retained pending request comparison, explicit empty receipts and failures, singleton leases, bound stream event decoding and reverse proposal comparison. Append a typed optional session tuple to subscriptions and reject the old arity.

## Risks

The subscription tuple is an incompatible candidate change. Empty receipts establish carrier acceptance only. Source contribution ownership, persistence, revision floors and deadlines remain consumer obligations.

## Scope

Proto contracts and tests, independent vector producers and canonical documentation. The service-control crate is unchanged.

## Alternatives

A parallel M6 schema or runtime client would duplicate existing contracts. Reuse the Message codec and caller-supplied authentication facts instead.

## Validation

Independent vectors cover two Networks, bootstrap/error shapes, receipts, singleton leases, reverse operations and strict encoding/context refusals. Run formatting and lint, focused vectors and repository self-check.

## Acceptance results

- Independent Python fixtures cover 148 carrier cases across two Networks and
  46 subscription cases, including exact M6 round trips, legal unary pairs,
  bootstrap and Error shapes, signed empty receipts, singleton leases, three
  event kinds, reverse answers and context/encoding refusals.
- Failing first: publication_subscription_vectors and its signed-carrier test
  refused the new tuple with `ArrayLength { expected: 7, actual: 8 }` before the
  decoder change. The final subscription tests accept eight fields and refuse
  the old seven-field shape.
- Initial carrier fixture failures were corrected in the independent producer:
  ServiceRef is a three-element array, snapshot scope puts the subject first
  and has no schema member, and service.retry-port is not session-bearing.
  The shared Message decoder and M6 crate were unchanged.
- The dependent realm identity subscription fixtures were regenerated at the
  new arity so their malformed-realm refusals still exercise realm validation.
- Formatting, workspace lint, focused vector tests and generator verification
  passed. The final `just self-check feat/l8-account-profile` on implementation
  commit `52075779946dfe1327c341cd6d7a3830fa5b1ad2` passed: 516 tests, zero
  failures or skips, 28 generated fixture files current, semantic compatibility,
  doctests and documentation checks clean. Later changes only complete these
  plan and acceptance records.
- Local review covered the complete carrier, subscription delta, producers,
  tests and adoption documentation with no outstanding findings. The contract
  remains pure and the service-control crate has no diff.
- NSD carrier adoption and independent real producer review remain outstanding;
  fixture evidence does not establish live interoperability. The subscription
  format change is explicitly breaking for existing consumers.

## Session identifier validation

Investigation: ServiceControlBinding reads fixed-size IDs but validates only its
three positive counters. The unchanged M6 envelope rejects all-zero runtime_id
and request_id, while allowing zero NSD and Network identifiers. Subscription
construction, decoding and authenticated ingress share this missing predicate;
stream validation also receives directly constructed bindings.

Approved correction: require nonzero runtime_id and session_request_id in the
central binding validator. Retain exact byte widths, counter rules and zero
NSD/Network behavior. Preserve the existing regression controls and assertions,
extend independent raw/signed vectors and direct construction/stream checks,
then run standalone formatting/lint and the complete self-check. Audit every
new carrier identifier reader and its route to the existing M6 codec.

### Identifier audit

- ServiceControlBinding::validate now enforces both nonzero identifiers and all
  three positive counters. read checks exact 16-byte fields then validates;
  write is private and reached only after subscription canonical validation.
- PublicationSubscriptionRequest::validate/canonical/read/decode/from_envelope
  all reach the central binding validation. boot_nonce keeps its existing
  independent nonzero rule; subscriber and scope keys use IdentityKey validation.
- validate_stream_event decodes through Message and validates the supplied
  binding before comparing it, including a directly constructed binding whose
  session_request_id is not present in an individual event.
- validate_unary_request and validate_unary_reply decode with Message; pending
  requests can only be built from validated authenticated requests. same_context
  compares validated fields and adds no alternative identifier reader.
- validate_reverse_result calls Message::encode for both constructed arguments
  before comparison. Nested lease/proposal identifiers remain in the shared
  Message codec. The M6 raw envelope decoder and encoder both use their existing
  nonzero runtime/request checks and do not prohibit zero NSD/Network IDs.
- No additional same-class defect was confirmed, in or outside the edited scope.
  The original regression's valid controls and both original assertions remain.

### Session identifier acceptance

The preserved tests bound_subscription_rejects_zero_runtime_identifier and
bound_subscription_rejects_zero_session_request_identifier both failed before
the correction because decoding accepted all-zero identifiers. Both original
valid fixture controls and original decode/construction assertions remain.
The additional constructed-value test checks both nonzero constraints and
accepted zero NSD/Network identifiers. Independent signed subscription fixtures
exercise authenticated ingress, and stream checks reject invalid manually
constructed bindings. Unary fixtures confirm the unchanged Message decoder
rejects zero runtime/request identifiers and accepts zero NSD/Network IDs.

Standalone formatting and workspace lint passed before the focused six tests,
which all passed. Complete `just self-check feat/l8-account-profile` on
`19bd717572d6f1eafd13ce7b63e19b7379271329` passed: 521 tests, zero failures or
skips, 29 fixture files current, compatibility, doctests and documentation clean.
There are now 152 carrier and 64 subscription vectors. No M6 schema or unrelated
identifier contract changed, and no additional confirmed audit finding remains.
