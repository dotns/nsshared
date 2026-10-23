# docs: record echo reply non-emission

- **status**: completed
- **createdAt**: 2026-10-23 03:24
- **approvedAt**: 2026-10-23 03:24
- **relatedTask**: 20261023-0324-echo-reply-non-emission

## Context

The usage specification and profile define completed echo message bytes excluding
IP headers. ServiceOperation::EchoReplySend retains that meaning. The documents
currently omit the frozen packet runtime's missing per-packet send receipt.

## Proposal

Document the unchanged EchoReplySend meaning and current gateway candidate
non-emission in the usage specification, profile and review request. Explain that
synthetic replies are delivered unbilled at nsplane 0.16.0 because the normal
outbound path cannot report individual successful sends. Queue admission is
never completion. Preserve EchoProbeSend and all code, vectors and wire bytes.

## Risks

Readers could confuse delivery or queue admission with billable completion.
State the outstanding runtime capability explicitly without claiming agreement.

## Scope

Three usage-related documents and these plan and acceptance records.

## Alternatives

Changing the unit to queue admission would misstate completed-send accounting.
Reply billing remains deferred until a capable runtime is adopted and qualified.

## Validation

Review the three documents for consistent meaning and non-emission, then run
formatting, lint and the scoped self-check.

## Outcome

The three documentation updates are complete. Formatting, lint and the scoped
self-check passed; the acceptance record contains the documentation assertion
and verification results.
