# docs: record echo reply non-emission

- **status**: in_progress
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

Pending document review and scoped self-check.
