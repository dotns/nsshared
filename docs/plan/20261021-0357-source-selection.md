# Source binding and route selection

- **status**: completed
- **createdAt**: 2026-10-21 03:57
- **approvedAt**: 2026-10-21 03:57
- **relatedTask**: 20261021-0357-source-selection

## Context

PublicationEvent already validates exact keys, channels, complete replacement,
versions, signatures and deadlines. Subscription requests provide restart/attempt
context and polls provide correlation. Neither is inside the signed publication.
SubnetSelection and M6 ServiceRef already define route scope and stable identity.
The predecessor selection API addresses gateway strings; its clear store retains
only the latest receipt per machine. Neither establishes the new source fence.
M6 authority_epoch and NodeBinding record generation name independent facts and
cannot become contribution authority. RealmId is the canonical realm type.

## Proposal

Specify and independently generate source bindings, source-bound publication
wrappers and Node/route commands before implementing pure codecs. Authenticate
bindings in correlated control responses. Add exact source/delivery comparisons
before existing per-key publication decisions. Reuse BootstrapEnvelope for command receipts and
SubnetSelection for scope encoding; expose replay as a receipt with no mutation authority.
Keep externally supplied current source and immutable receipt history separate.

## Risks

All new signed forms are incompatible with unbound inputs. Missing binding fails
without fallback. Receipt replay must precede current-source mutation checks but
remain exact to its original request, profile and source. Final serialized source
installation and local attachment generation checks remain consumer obligations.

## Scope

Pure account contracts, independent vectors and documentation. No runtime, I/O,
transaction journal, M6 byte changes or predecessor facade. Producer review and
runtime adoption remain outstanding. Q18 records the settled shared participant
credential and separate signed directory binding, with the directory unchanged.
Shared definitions belong to P07 and gateway adoption to P08, both pending; this
source/selection work only cross-references those contracts.

## Verification

Independent source_selection_fence and refusal variants, failing-first focused
test, format/lint, then the current self-check against the integration baseline.

## Results

Specification and independent Python bytes preceded the codecs. SourceBinding,
DeliveryContext, SourceAcceptance, source-bound publications, scoped snapshots,
route commands and immutable receipts are implemented without runtime or I/O.
The independent corpus has 129 cases; four focused tests pass. The final
`just self-check` against the integration baseline passed static, vector, API,
41 check-selection tests, 492 workspace tests with zero skipped and documentation
checks. Source files remain within their documented size limits.

Failing-first evidence includes missing source/command APIs before implementation,
missing multi-scope snapshot support, and the executable `request-fresh-attempt`
refusal before transport nonces were separated from immutable request identity.
The final implementation accepts a fresh attempt and refuses a previously observed
carrier nonce while preserving the original receipt.

Q18 now records the settled shared participant credential and separate signed
directory binding, with the directory unchanged. P07 definitions and P08 gateway
adoption remain pending. This candidate only cross-references their ownership;
NSD producer review, independent producer vectors and NSD/ns adoption remain
outstanding.

## Documentation acceptance

The Q18 review request, profile and source/selection specification consistently
record the settled participant credential and separate signed directory binding,
with the directory unchanged. P07 definitions and P08 gateway adoption remain
pending; producer review and NSD/ns adoption are external outstanding work.
The current `just self-check` at 68c6591 passed all static, vector, API, workspace
test and documentation checks, including 491 workspace tests with zero skipped.

## Snapshot channel validation

Inspection found that source snapshot aggregation retained ChannelMismatch beside
valid replacements. UnknownKind also requires an explicit signed snapshot-channel
check because the low-level event decision recognizes extensions before checking
known ownership. Both source snapshot APIs share the same aggregation path.

Reject a complete source snapshot on a known channel mismatch or an extension
that declares Stream. Preserve authenticated snapshot-channel unknown pairs and
exact source/context/scope, ordering and multi-scope atomicity. Keep the existing
low-level publication contracts unchanged. Verify the imported stream-entry
regression, independent mixed-event accepted/refused vectors and the current
self-check before recording completion.

## Snapshot validation results

The stream-entry regression first failed with an accepted batch containing
ChannelMismatch and Replace. Independently generated mixed-event cases also
failed before the fix. Both source snapshot APIs now reject channel mismatch
atomically, including a known stream-owned pair that declares Snapshot and an
unknown pair that declares Stream. Authenticated snapshot-channel UnknownKind
extensions retain their adjacent valid actions.

The corpus contains 129 independent cases, including 28 new mixed batches:
six accepted controls and 22 refused batches. Every new batch has independently
ordered full keys and checked per-event authentication/actions; all single-scope
batches exercise both entry points, and multi-scope batches preserve atomicity.
Bad inner/outer signatures, old source, wrong context and wrong scope remain
refused. The valid-only and authenticated mixed-extension controls are retained.

Nine focused tests passed. The current `just self-check` at 619eacf passed
formatting, lint, dependency checks, spelling, independent vectors, API checks,
41 check-selection tests, 492 workspace tests with zero skipped, doctests and
documentation compilation. Only these completion records changed afterward.

Inspection covered every ChannelMismatch/UnknownKind handling path. The source
snapshot aggregator was fixed, and the single-source wrapper inherits that fix.
The snapshot-request boundary already checks both declared channel and known
ownership. Low-level publication decisions and raw snapshot neutral-result
semantics remain unchanged, along with their existing independent controls;
strict source snapshot validation adds no new low-level contract requirement.
