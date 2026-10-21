# Signed source authority in control responses

- **status**: in_progress
- **createdAt**: 2026-10-21 11:09
- **priority**: P1

## Description

Carry signed source authority alongside every successful registration result and
authentication token. Refuse missing or mismatched binding and wrong correlation.

## ActiveForm

Extending response contracts and verifying independent vectors.

## Dependencies

None.

## Notes

Investigation: existing response arities are five and two; SourceAcceptance has
its own three-field payload and whole-envelope decoder. The approved proposal
replaces these with six and three fields, retaining existing normal-result checks.
