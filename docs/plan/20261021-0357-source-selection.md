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
runtime adoption remain outstanding. Directory/participant disposition text
remains unchanged and outside this implementation.

## Verification

Independent source_selection_fence and refusal variants, failing-first focused
test, format/lint, then the current self-check against the integration baseline.

## Results

Specification and independent Python bytes preceded the codecs. SourceBinding,
DeliveryContext, SourceAcceptance, source-bound publications, scoped snapshots,
route commands and immutable receipts are implemented without runtime or I/O.
The independent corpus has 101 cases; four focused tests pass. The final
`just self-check` against the integration baseline passed static, vector, API,
41 check-selection tests, 491 workspace tests with zero skipped and documentation
checks. Source files remain within their documented size limits.

Failing-first evidence includes missing source/command APIs before implementation,
missing multi-scope snapshot support, and the executable `request-fresh-attempt`
refusal before transport nonces were separated from immutable request identity.
The final implementation accepts a fresh attempt and refuses a previously observed
carrier nonce while preserving the original receipt.

Q18 disposition text remains unchanged; this implementation does not resolve its
separate directory/participant wording. NSD producer review, independent producer
vectors and ns/NSD runtime adoption remain outstanding.
