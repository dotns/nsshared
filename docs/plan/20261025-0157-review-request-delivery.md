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

## Registration lifecycle placeholder clarification

The existing enrollment vectors carry nonzero example incarnation fields. Registration needs no grant or reporter to replace identity or rotate an explicitly authorized K. Keep the six-element lifecycle and existing codec/comparator, document zero-valued registration placeholders, and add independent zero-placeholder vectors for both valid transitions, mismatched before/after and unauthorized rotation. Retain all existing nonzero fixtures as structural coverage rather than a producer form.

Update Lifecycle, RegistrationRequest and Q07 with the exact authority/binding comparisons and separate grant/reporter custody. The delivered package selection remains historical to this additive documentation/vector change. Complete handoff comparison still requires a newly supplied immutable gateway revision with all four input pairs aligned; none is supplied yet. No schema or crate-source change is needed.

## Registration placeholder verification

The new `enrollment_consumer_vectors` test initially failed on the missing independent zero-placeholder identity-replacement vector. After adding five independently generated vectors it passes, alongside the three existing enrollment tests: four passed, zero failed, zero ignored. Every pre-existing fixture record is unchanged. Zero placeholders permit identity replacement and explicitly authorized rotation without grants or a reporter, while exact before/after mismatches and unauthorized rotation remain refused.

Formatting, lint, vector regeneration and `just self-check feat/l8-account-profile` passed at `0c7bddfdea2913f407dce8590cfa6503e70ee31f`; only these records change afterward. Production crate sources, schemas, codecs and tools outside vector generation remain unchanged. The review delivery assertion still passes. The profile and independent fixture extension are complete, with NSD N24/N26 and ns S17 adoption outstanding.

Complete handoff qualification remains blocked pending a named immutable gateway revision with all four manifest/lock pairs aligned. The previously supplied revision retains the two historical fixture pins documented above. The selected package predates this vector addition; any selected-package equality comparison must also distinguish the immutable delivered snapshot from the later fixture extension rather than claim that the new fixture bytes existed in that package.

## Aligned consumer reference

Gateway revision `e70a90abb1a53567bfb6eb28f6ee057d7b9f0dc8` supersedes the intermediate consumer selection. Immutable reads of its root, control-authority, direct-peer and authority manifests and locks confirm all direct shared pins and all shared lock source queries/commits select `958da3f9b31e70f419035b974977f8d0d2895471`, with shared versions `0.6.0`. Update the handoff reference and command, retain both earlier comparison failures as historical evidence, and leave snapshot-boundary qualification pending.

The five added vectors, existing nonzero fixtures, transition refusals and outstanding adoption dispositions require no changes. The selected shared package and comparison tool remain unchanged; input differences are not suppressed. The remaining qualification step is to settle the immutable snapshot boundary before running and recording the complete comparison at the approved boundary.

## Aligned reference verification

The consumer-reference assertion initially failed because the handoff still selected the intermediate revision, then passed after the documentation update. The review delivery assertion also passes. Immutable gateway manifest/lock inspection confirms shared lock resolution counts of 3 for the root, 2 for control-authority, 3 for direct-peer and 2 for authority, all at the selected shared revision. These observations establish pin alignment only.

Formatting, lint and `just self-check feat/l8-account-profile` passed at `8a98b18018cd5cc13c9ad4e6871f53757f60530f`; only these records change afterward. The five new vectors, existing nonzero fixtures, exact transition refusals, implementation and outstanding adoption dispositions are unchanged. Independent documentation work is complete. Snapshot-boundary qualification and the complete comparison remain pending; no current full-comparison pass is claimed and earlier failures remain historical evidence.

## Immutable package and additive extension boundary

Compare an immutable export of shared package `958da3f9b31e70f419035b974977f8d0d2895471` with gateway `e70a90abb1a53567bfb6eb28f6ee057d7b9f0dc8` using the unchanged exported comparison tool and read-only access to repository Git objects. Keep the current placeholder producer/test/fixture extension separate and qualify it with the current-head self-check. The immutable comparison has passed for 259 selected inputs and all four manifest/lock pairs (3, 3, 2, 2 shared resolutions).

Document both evidence boundaries and preserve earlier failures. Crate sources, package/workspace manifests and lockfile compare unchanged from the delivered package. Only complete these records after the current-head self-check also passes. No tool change, consumer repin, input suppression or external approval claim is needed.
