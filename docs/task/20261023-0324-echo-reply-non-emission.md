# docs: record echo reply non-emission

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-23 03:24

## Description

Preserve completed synthetic ICMP reply bytes excluding IP headers as the shared
EchoReplySend unit. Record that the current gateway candidate delivers replies
unbilled and emits no EchoReplySend at frozen nsplane 0.16.0. Queue admission is
never completion. EchoProbeSend, code, vectors and wire bytes remain unchanged.

## Investigation and proposal

The usage specification and profile describe completed echo bytes, while the
review request asks for service-unit confirmation. Add the missing runtime
capability disposition to all three; retain outstanding review explicitly.

## Acceptance

Document review passed: the usage specification, profile and review request
preserve the completed-send unit, current non-emission, unchanged EchoProbeSend
and outstanding runtime capability without agreement. Code, vectors and wire
bytes are unchanged.

The echo_reply_non_emission_documented text assertion first failed with
"missing EchoReplySend non-emission disposition" on the usage specification;
it passed after all three documents were updated. This checks documentation
presence; the unchanged runtime is not exercised by that assertion.

`just fmt-check` and `just lint` passed before the assertion.
`just self-check feat/l8-account-profile` passed on
`f0d4d512923c49b48ea6cc8b8747d801c0b8aa74`: 521 tests passed, zero skipped;
static checks, doctests and documentation generation also completed successfully.
Only these acceptance records changed after the passing check.
