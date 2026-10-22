# Start the relay with an owned UDP socket

- **status**: completed
- **createdAt**: 2026-10-22 19:38
- **approvedAt**: 2026-10-22 19:38
- **relatedTask**: 20261022-1938-owned-udp-socket

## Context

The runtime binds carriers before initializing the core. UDP serving and shutdown already share ownership of the bound socket. The existing startup derives an IP identity, whereas directory entries require a DNS identity.

## Proposal

Add an owned-socket entry that validates UDP-only settings and derives relay.example.test with the assigned port. Extract initialization after binding so both entries use the same serving and shutdown logic. Reject listen overrides, disabled UDP, WSS and external WSS before spawning tasks. Require the shared listen field to retain its default value because it is unused in this mode.

## Risks

Ownership must survive initialization and be released on every error. Tests queue a signed REGISTER before startup to prove that the original socket is retained.

## Scope

The mock relay runtime and at most four integration tests, plus these records.

## Alternatives

Reserving and rebinding a port creates a race and is excluded. Changing existing startup defaults would change command-line behavior and is excluded.

## Acceptance

Implemented `MockRelay::start_with_udp_socket` with a typed `OwnedUdpConfig` error and shared post-bind initialization. The existing startup and command-line defaults are preserved.

The four owned-socket runtime tests passed in both the focused runtime suite and the complete self-check. A REGISTER queued before startup is accepted with the default DNS identity; the reply source and reported local address match the handed-over socket. Explicit identity remains usable for signed registration. Conflicting carrier and listen settings and invalid core configuration release the socket; shutdown releases it while the handle remains alive.

`just fmt-check lint` passed. The runtime suite passed all 15 tests. The complete `just self-check` passed 515 tests with zero skipped, 41 check-selection tests, compatibility checks and documentation checks. Local diff review found no defects in the changed initialization and ownership paths.
