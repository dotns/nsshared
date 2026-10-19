# External WSS listener ownership

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-19 14:47

## Description

Make `external_mode_announces_wss_without_a_tcp_listener` independent of an unrelated process leaving its UDP port number free on TCP. Reproduce the conflicting TCP bind deliberately, preserve all existing assertions, and verify that the relay starts successfully while the caller owns TCP continuously.

## ActiveForm

Verifying external WSS listener ownership.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation: `runtime::bind` computes `listen_wss = config.wss && !config.external_wss`, binds UDP, and returns no TCP listener in external mode. The existing test's post-start TCP bind is the source of the intermittent failure.

Proposal: reserve TCP first, start UDP on the same address, retain the TCP listener through registration and shutdown, and preserve every other assertion. The deliberately retained second bind provides the failing regression before its removal.

Acceptance results:

- The original post-start TCP bind failed with `Os { code: 98, kind: AddrInUse }` when the fixture held the same TCP address. A second invocation of the entire external integration file confirmed the failure: three passed, one failed, zero skipped.
- The final test starts the real relay while the caller owns TCP, verifies UDP uses that address, retains the existing absence-of-listener and certificate checks, completes UDP registration and checks both announced capabilities. The listener stays bound through shutdown.
- `just fmt-check` and `just lint` passed before running tests, both before and after the assertion change.
- `cargo nextest run -p nsshared-mock-relay --test external --locked` passed twice: four tests passed, zero skipped on each invocation.
- `just self-check feat/l8-account-profile` passed at `77b061dc7f249d4af0beacd634b80c64181bff36`: 416 tests passed, zero skipped, with all static, compatibility, doctest and documentation checks passing. Only these documentation records changed afterward.
- Local review found no additional issues. No runtime changes, retries, skips or fallbacks were introduced.
