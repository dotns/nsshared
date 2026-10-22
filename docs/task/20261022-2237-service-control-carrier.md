# 20261022-2237-service-control-carrier Service control carrier

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-22 22:37

## Description

Deliver the pure candidate M6 carrier, exact unary and stream correlation, eight-field subscription, independent vectors and adoption documentation without changing M6 bytes.

## ActiveForm

Implementing authenticated service control contracts and vectors.

## Dependencies

Existing BootstrapEnvelope and Message contracts.

## Notes

Investigation and approved implementation approach are recorded in [the plan](../plan/20261022-2237-service-control-carrier.md). Specification and independent producer precede implementation.

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
