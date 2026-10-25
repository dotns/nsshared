# Record review request delivery

- **status**: implementing
- **createdAt**: 2026-10-25 01:57
- **approvedAt**: 2026-10-25 01:57

## Context

The review request and immutable handoff still describe owner forwarding as unrecorded. The owner has confirmed forwarding on 2026-10-25 at revision `958da3f9b31e70f419035b974977f8d0d2895471`.

## Proposal

Record the date, owner route, immutable revision and producer/consumer addressees in both documents. Preserve historical package selection and all unanswered, unresolved and outstanding dispositions. Silence grants no approval.

## Scope

Only the two delivery documents and these plan and completion records change.

## Risks

Delivery must not imply a reply, producer adoption or approval.

## Alternatives

Leaving preparation as the status would omit the confirmed delivery.

## Results

Both documents now record delivery through the owner route on 2026-10-25 (UTC), revision `958da3f9b31e70f419035b974977f8d0d2895471`, and the producer/consumer addressees. No reply or approval is recorded; all outstanding dispositions are preserved.

The delivery assertion failed first on the absent date and passes after the documentation change. Formatting, lint and `just self-check feat/l8-account-profile` passed at commit `1365acf4195bca3ff523ffbf1710f87c8b78dd9b`; only these records changed afterward.

The unchanged `tools/candidate_handoff.py` command documented in the handoff failed with `candidate input differs: crates/nsshared-proto/src/account.rs`. That file is identical to the integration baseline. The historical selected package no longer matches the current library inputs, so complete acceptance remains blocked pending reconciliation of package selection and consumer pins. The delivery update does not change those inputs or claim that the comparison passes.

## Package selection reconciliation

The historical comparison uses shared revision `50dc9db5fe106536d0a7d8b113b5bb4a3e210368` and gateway revision `e506df51e5e580d20d5cdaa25a8f134f87bf3caf`. Select the delivered shared revision `958da3f9b31e70f419035b974977f8d0d2895471` and gateway revision `96fa0dca57c3af5e96ab9f72d710f2cbe6d8cf93` for the current comparison. The gateway workspace manifest pins all three libraries to the delivered revision, but the direct-peer and authority manifests still pin proto to the historical revision. Retain initial per-contract revisions and outstanding review/adoption dispositions. Re-run the unchanged comparison and self-check to qualify the documentation update.

The new comparison confirms 259 shared inputs and the workspace lock resolutions, then fails at direct-peer with `manifest pin differs: nsshared-proto`. The authority manifest has the same old pin. The comparison tool and consumer inputs remain unchanged. Complete qualification still requires a matching immutable gateway revision; the selected documentation now describes this limitation explicitly.

## Current qualification

The selected shared and gateway revisions are updated, and the old comparison remains explicitly historical. Per-contract revision rows and outstanding review/adoption dispositions are unchanged. Selection and delivery assertions pass. The unchanged handoff comparison test passes. Formatting, lint and `just self-check feat/l8-account-profile` pass at `5aedf7df9c49516bb7af34c095948bfc9509a003`; only these records change afterward.

The required comparison exits 1 because two gateway fixture manifests still select the historical shared revision. Shared package equality succeeds for 259 inputs, and the workspace lock comparison succeeds for three shared resolutions. The documentation work is complete; qualification remains blocked by the external manifest pins, without a claim of complete acceptance.
