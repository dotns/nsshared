# Start the relay with an owned UDP socket

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-22 19:38

## Description

Accept a caller-bound UDP socket without rebinding or retrying, use its assigned port in a default DNS identity, reject conflicting configuration, and release ownership on startup failure and shutdown. Preserve existing startup and command-line behavior.

## ActiveForm

Implementing and verifying owned UDP startup.

## Dependencies

None.

## Notes

Investigation and approved design are recorded in the matching plan. Verify queued REGISTER processing, explicit identity, conflicting settings and initialization failure with four tests.

## Validation

The first focused run failed with the expected missing `start_with_udp_socket` function and `OwnedUdpConfig` variant before implementation.

- `owned_udp_socket_serves_queued_register_and_releases_on_shutdown`: accepted the queued signed REGISTER, observed the original address and default DNS identity, and rebound the port after shutdown.
- `owned_udp_socket_preserves_explicit_identity`: accepted registration for the configured identity.
- `owned_udp_socket_rejects_conflicts_and_releases_socket`: observed the typed error for all six conflicting configurations and rebound each released port.
- `owned_udp_socket_releases_on_core_initialization_failure`: observed a core configuration error and rebound the released port.

Formatting and workspace lint passed. The focused runtime suite passed 15 tests. The complete self-check passed 515 tests with zero skipped, 41 check-selection tests, static checks, API compatibility and documentation checks. The four new tests passed again within that check.
