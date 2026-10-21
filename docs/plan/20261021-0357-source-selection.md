# Source binding and route selection

- **status**: implementing
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
before existing per-key publication decisions. Reuse B43 for command receipts and
B40 scope encoding; expose replay as a receipt with no mutation authority.
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
