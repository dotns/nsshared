# Signed source authority in control responses

- **status**: implementing
- **createdAt**: 2026-10-21 11:09
- **approvedAt**: 2026-10-21 11:09

## Context

Registration and authentication responses omit signed source authority. A separate
SourceAcceptance payload displaces their normal results and duplicates correlation.

## Proposal

Specify incompatible response tuples and independent producer vectors first.
Require SignedSourceBinding in every successful response, remove SourceAcceptance,
and verify nested authority against independent enrollment facts and pending nonce.
Extend source_selection_fence without changing publication or receipt semantics.

## Risks

Existing candidate consumers must adopt the incompatible arities. NSD adoption and
producer-owned interoperability evidence remain outstanding.

## Scope

Pure control exchange, source authority, independent vectors and candidate documents.

## Alternatives

A standalone payload or old-shape fallback loses the single response contract and
is excluded.
