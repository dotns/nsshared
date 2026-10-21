# Source-bound publications and Node route commands

Status: pure candidate definitions and labelled fixture authority. NSD producer
review, producer vectors and ns/NSD interoperability remain outstanding.
All arrays below are exact canonical CBOR with minimal integers, definite lengths,
no extra fields and no trailing bytes. Integers are unsigned u64 unless stated.
Bindings and complete command/receipt/response payloads are bounded by 16,384
encoded bytes. Identity fields are complete validated 32-byte Ed25519 public keys. Realm text is
canonical RealmId. All opaque identities below are nonzero 16-byte values. Scope
text is nonempty, at most 256 UTF-8 bytes, without control characters.

## Source authority

`SourceBinding = [1, nsd, recipient, realm, scope, profile, source_node,
contribution, source_epoch, source_generation]`. Both counters are positive.
The sole new profile is the literal `explicit-gateway-profile`. NSD assigns it
through authenticated enrollment; a caller cannot grant itself a profile.
NSD's durable committed enrollment/contribution state allocates contribution and
advances generation on replacement or retirement even when I, K and addresses do
not change. Neither NodeBinding.generation nor M6 authority_epoch supplies this
fact; their bytes and meaning remain unchanged. Exact equality, including issuer,
recipient, realm, scope, profile, source, contribution, epoch and generation, is
required when comparing accepted authority. Local attachment generation is never
encoded as NSD source generation.

`SignedSourceBinding = [bstr(SourceBinding), signature64]`, signature input:
`"ns.account.source-binding.v1\0" || SourceBinding bytes`.
Successful registration carries `[1, scope, bstr(Enrollment), profile, decision,
bstr(SignedSourceBinding)]`; successful authentication carries
`[1, token, bstr(SignedSourceBinding)]`. All accepted enrollment decisions,
including Equal, require the binding. Refusals remain unchanged. These are the
sole payloads of the existing confidential `machine.register` and `machine.auth`
responses. Standalone SourceAcceptance and its whole-envelope decoder are retired;
old response shapes have no fallback. This is an incompatible candidate delta.

The response must verify the expected enrolled NSD pin, response direction,
explicit recipient, exact operation, freshness/replay rules and nonce equal to the
caller's pending request id. No duplicate request-id field is carried. Verify the
nested binding signature against the independently enrolled NSD and compare its
recipient, realm/scope, assigned profile and full source Node with independent
expectations. Registration also compares the staged scope, enrollment, capabilities,
profile and lifecycle with retained history. Authentication uses the selected
accepted Node binding; token verification and custody remain consumer duties.
Only a fully validated response supplies source authority; contribution and counters
come from the NSD binding, never the token. Decoding alone never establishes authority.
NSD N04 producer adoption and producer-owned interoperability vectors are outstanding.

## Source-bound publication

The new signed bytes are `SourcePublicationContent = [1,
bstr(SignedSourceBinding), bstr(DeliveryContext), bstr(PublicationEvent)]`;
`SourcePublication = [bstr(SourcePublicationContent), signature64]`, signing input:
`"ns.account.source-publication.v1\0" || SourcePublicationContent bytes`.
The nested PublicationEvent retains its existing independent signature and
complete full key, channel, complete flag, version, issue/expiry, outcome and
payload. Its nested signature and every existing decision rule are still checked.
This intentional incompatible signed-byte delta adds the outer signature domain,
mandatory binding and delivery bytes; an old PublicationEvent is never accepted
by this new decoder. There is no fallback or signature reinterpretation.

Delivery is `[0, boot_nonce16, positive_u32_attempt]` for streams, or
`[1, boot_nonce16, positive_u32_attempt, correlation16]` for snapshots. Nonces and
correlation are nonzero. They echo the subscriber's existing subscription and
poll identities, not a producer-chosen session. The delivery tag must match the
actual receiving channel. The caller supplies outstanding context and current
accepted binding. Outer and binding signatures verify against that current NSD;
all binding fields and delivery fields must equal the supplied values before an
inner event can yield a decision. Inner issuer/recipient/realm/scope must also
match the binding. This authorizes the collection, not equality between enclosing
realm and each contributing realm. RealmPeers, Node-L3, grants, Subnet and public
edge use this form, including complete-empty and authenticated failure events.
Independent participant rosters and M6 keep their existing carriers.

The measured entire outer event is bounded by MAX_PUBLICATION_BYTES. Oversized
stream input terminates; invalid snapshot input rejects the complete snapshot.
Source-bound snapshots use `[1, [bstr(SourcePublication), ...]]`, bounded by
MAX_CONTROL_BODY, strictly increasing full inner keys. Every event is validated
before exposing any decision; omitted keys retain their state. Every entry must
both declare Snapshot and avoid known stream ownership. A known stream-owned
pair is refused even if it declares Snapshot; an unknown registry pair that
declares Stream is also refused. Authenticated unknown pairs that declare
Snapshot yield UnknownKind without authority and preserve adjacent valid updates.
One wrong-channel entry rejects the whole batch, whether valid replacements occur
before or after it. Both the single-source and multi-scope snapshot APIs enforce
these rules without changing the low-level publication decision contract.
Multi-scope polls
supply the accepted binding for each requested scope, bounded by the existing
32-scope request ceiling. Each enclosing issuer/recipient/realm/scope may have
only one current binding; supplying both retired and replacement authority for
one scope is refused. Every returned event must match its scope's exact current
binding; a good event in another scope cannot hide one stale-source event. Existing full-key
version/tombstone retention and deadlines survive source replacement. A higher
per-key version cannot rescue an old source or session. The consumer preserves
this context through queues and compares local attachment generation in the same
serialized source-owner operation as final installation. These APIs perform no
installation and read no clock or state themselves.

## Route commands and immutable receipts

control carrier confidential operations are `node.route.select` and `node.route.clear`, at the
existing control endpoint. They deliberately do not reuse retired gateway-ID
operation identifiers. `RouteCommand = [1, bstr(SignedSourceBinding), request_id,
selection_id, action]`. Select action is `[0, provider_node_I,
bstr(canonical_M6_ServiceRef), selection]`; selection reuses SubnetSelection's exact
`[0, []]` default or `[1, ordered_prefixes]` explicit scope. Prefixes use SubnetSelection's
family/address/length encoding, validation, ordering and overlap bounds. Empty
explicit selects none. Resource authorization and containment in a published
route remain NSD transaction checks, not inferred from identity or decoded bytes.
Clear action is `[1, target_selection_generation]` with positive generation.
Clear's source binding, selection identity and generation name an exact target.

The signed control carrier request nonce is a fresh nonzero transmission-attempt identity,
independent of the immutable payload request_id; signer equals binding recipient,
recipient equals binding NSD, operation equals the action's operation. The binding
signature verifies against the independently trusted NSD. The transaction compares
the authenticated caller, assigned profile and supplied binding with committed
current source authority before a new mutation. Full provider I and stable
ServiceRef are required; gateway strings, carrier credentials and unknown appended
fields are refused. Request and selection identities are required, not optional.

`RouteReceipt = [1, bstr(RouteCommand), selection_generation, outcome]` where
outcome 0 is selected, 1 cleared, 2 clear target absent. Select generation is NSD's
positive committed generation. Clear results retain the exact targeted generation
whether cleared or absent. A receipt is immutable for its exact profile/source/
request identity: store every original receipt, never only the latest per machine.
The same identity with changed command bytes conflicts. A different source has a
separate request namespace even when I/K/addresses and request ids match.

`RouteResponse = [1, bstr(RouteReceipt), replayed_bool]` uses an NSD-signed control
response with the action's operation, explicit recipient and the pending attempt's
nonce. The consumer supplies and compares that exact nonce as well as its entire
pending immutable request and source/profile with the receipt. Retransmission uses
a fresh carrier timestamp/nonce under the unchanged control carrier replay rules while
retaining payload request_id and exact command bytes. Fetching the original
receipt never reuses the first carrier's replay authority.
A response establishes committed command outcome, never applied routing. A replay
returns the original receipt bytes and reports replayed=true; it grants no current
mutation authority. Pure decisions distinguish Replay from Select, Clear and
ClearAbsent. Replays verify original binding and caller and exact receipt content,
then return before comparing mutation authority with a replacement source. New
requests must match current source. Clear only removes a caller-supplied committed
selection with the exact binding, identity and generation. Durable transaction
rechecks, generation allocation, receipt lookup/history and restart restoration
remain NSD responsibilities; pending journals and routing remain ns responsibilities.
Old-profile receipts are refused, not translated.

## Independent consumer sequence

`source_selection_fence` uses a labelled authority with the same full source I,
K and derived addresses across A/B. Register a pending gateway with no contribution
and accept A as nodes authority in its enrollment Network; Equal retains that scope.
Authorize a contribution in that same Network, then authenticate independently for
nodes and egress with the exact pending selector and nonce. Retain both bindings.
Refuse swapped scope or realm and requests missing the selector. Refuse missing or mismatched bindings and wrong correlation
for both operations. Select and clear A's route; replace
only contribution/generation with B, select B's route. Deliver A's delayed signed
success at a higher per-key version: refuse it. Replay A's clear before and after
restoring immutable receipts/current selection from canonical bytes: the receipt
stays A's and B remains intact. Accept the current B publication. Variants refuse
wrong request, boot/attempt or poll context, wrong profile, missing binding,
retired gateway-ID and carrier-credential fields. Independent Python bytes are
consumed by Rust without using Rust output as producer input. Fixture assertions
are contract evidence only; actual producer review and interoperability are open.

## Review boundary

Q12/Q14/Q21 request producer confirmation of these exact bytes and provenance,
including durable source generation and all-receipt ownership.

[Q18](l8-candidate-review-request.md) records the settled owner choice: a shared
participant credential plus a separate NSD-signed directory binding, with the
global directory unchanged. P07 owns those shared definitions (pending), and P08
owns gateway adoption (pending). This source-binding and Node route candidate only
cross-references them; it does not define participant or directory-binding
contracts. NSD producer review and NSD/ns adoption remain outstanding.

## Explicit authentication source selection

AuthenticationRequest is exactly `[1, membership_scope, NodeBinding, "control",
[served_realm, publication_scope]]`. The selector is required, with no default or
old-shape fallback. Realm text is canonical 26-character RealmId; scope uses the
existing nonempty, control-free UTF-8 encoding bounded to 256 bytes. This is an
incompatible candidate request delta. AuthenticationResponse and SignedSourceBinding
encodings and signing domains are unchanged. NSD N04 adoption remains outstanding.

Registration, including pending gateway enrollment and Equal, returns nodes authority
in the accepted registration Network. Recipient and source_node equal the enrolled
identity. The contribution field is the NSD-allocated Node source record in this
scope; it grants no gateway contribution, service resource or M6 admission.

Nodes authentication selects the enrollment Network; egress selects an independently
accepted contribution Network, including home. Consumers retain the exact pending
realm/scope and nonce, compare returned authority against that pair and independently
accepted NSD, recipient, profile and source Node facts, and verify both signatures
and the normal token. Unknown or unauthorized selectors are refused, never replaced
with another binding. Retain each accepted scope independently. Fixture vectors
cover pending registration, Equal and nodes/egress authentication in one Network,
including swapped-scope and swapped-realm refusal.
