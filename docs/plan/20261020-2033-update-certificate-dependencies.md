# Update certificate dependencies

- **status**: implementing
- **createdAt**: 2026-10-20 20:33
- **approvedAt**: 2026-10-20 20:33
- **relatedTask**: 20261020-2033-update-certificate-dependencies

## Context

The dependency audit reports RUSTSEC-2026-0382 for rustls-webpki 0.103.15 and RUSTSEC-2026-0381 for webpki-roots 1.0.9 and its 0.26.11 compatibility package. Neither dependency is pinned directly in the workspace manifest.

## Proposal

Update rustls-webpki to 0.103.16 and webpki-roots 1.0.9 to 1.0.10 with precise lockfile updates. Retain unrelated package versions and dependency edges. Run the dependency audit, verify the resolved graph excludes ring, and run formatting, linting and the self-check.

## Risks

The audit also flags the older webpki-roots compatibility package; its continued presence may prevent an audit pass even after its underlying root bundle is updated.

## Scope

Cargo.lock and these implementation records. No advisory exemptions or public API changes.

## Alternatives

Broader dependency upgrades increase the change surface and require separate justification.

## Verification result

The two precise updates are complete; formatting and linting pass. The self-check fails on RUSTSEC-2026-0381 for the unchanged 0.26.11 compatibility package. Further upstream dependency investigation is needed before the audit and full QA can pass. No advisory policy was relaxed.
