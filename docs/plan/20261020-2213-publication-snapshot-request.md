# Publication snapshot poll request

- **status**: completed
- **createdAt**: 2026-10-20 22:13
- **approvedAt**: 2026-10-20 22:13
- **relatedTask**: 20261020-2213-publication-snapshot-request

## Context

The subscription codec carries exact publication scopes and restart/attempt facts. The independent snapshot has only a response codec. The predecessor poll names its active stream session, with no kind selector. Existing snapshots validate signed events and retained versions per publication key.

## Proposal

Specify a bounded canonical request carrying subscriber, sorted exact scopes, boot nonce, checked attempt counter and nonzero poll correlation. Retain the predecessor session facts as caller-supplied correlation, without runtime ownership. Request all snapshot-owned kinds within each exact scope; reject explicit kind selectors as unknown fields. Use the signed response envelope nonce for poll correlation and its unchanged PublicationSnapshot payload. Check pending scopes and recipient before exposing the existing per-key decisions.

## Risks

Correlation cannot authorize scope or reset accepted versions. An authenticated response must not expand the requested scope. Stream-owned events must be refused at this boundary.

## Scope

Pure account codec, independent Python vectors, Rust consumers and candidate documentation.

## Alternatives

A second snapshot wrapper would duplicate the existing response format. A kind selector would add semantics absent from the predecessor.

## Results

The canonical request and signed response boundary reuse subscription scopes and
PublicationSnapshot. The predecessor gateway-only forwarding lease and whole
realm-list removal are explicitly retired in favor of participant roster
authority and complete scoped realm-peers content.

The independent publication_snapshot_request_vectors consumer passes all 44
accepted/refusal fixtures and confirms unchanged per-key replay rejection.
Formatting, workspace lint and the complete scoped self-check pass, including
vector consistency, API compatibility, workspace tests, doctests and documentation.
NSD confirmation and real producer bytes remain outstanding.

## Extension handling

The poll boundary incorrectly equates an unknown registry pair with a known
stream-owned kind. Preserve authenticated UnknownKind decisions beside known
updates by refusing only known stream ownership, while still requiring every
returned event to declare the snapshot channel and match the pending scope.
Independent mixed-event fixtures cover unknown kinds and families, invalid
signatures, recipient/scope/correlation mismatches and known stream kinds.
The publication decision and snapshot paths already retain this distinction;
no changes to their acceptance or version rules are needed.

## Extension acceptance

The initial mixed-snapshot tests failed for both unknown pairs with Channel,
while authenticated known-only and corrupted-envelope controls behaved correctly.
The independent mixed-unknown-kind fixture also failed before the predicate fix.
The corrected boundary requires the declared snapshot channel and refuses a
registry result only when it is a known stream owner. All unknown events still
pass through existing signature, issuer, recipient, scope and validity checks.

The independent fixture set now contains 44 cases. Mixed unknown-kind and
unknown-family snapshots preserve Replace and UnknownKind decisions; signature,
channel, scope, recipient and correlation controls return their typed refusals.
The focused tests and complete scoped self-check pass, including 482 tests with
none skipped, API compatibility, doctests and documentation. Inspection of all
publication_channel lookups and UnknownKind handling found no additional defects.
