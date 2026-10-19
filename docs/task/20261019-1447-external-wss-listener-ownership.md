# External WSS listener ownership

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-19 14:47

## Description

Make `external_mode_announces_wss_without_a_tcp_listener` independent of cross-protocol port availability. Preserve the deliberate TCP-conflict reproduction and every original assertion, and verify that external mode ignores an occupied built-in WSS address while allocating UDP independently.

## ActiveForm

Verifying external WSS listener ownership.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation: `runtime::bind` computes `listen_wss = config.wss && !config.external_wss`, binds UDP, and returns no TCP listener in external mode. The original test's post-start TCP bind assumed a free TCP twin of an allocated UDP port. Reserving TCP first and setting `listen` to that address retained the inverse assumption of a free UDP twin.

Proposal: retain a caller-owned TCP listener, pass its address only as `wss_listen: Some(addr)`, set `external_wss: true`, and leave `listen` at `127.0.0.1:0` with `udp_listen: None`. The relay chooses and owns UDP independently. Remove the UDP-equals-TCP assertion, retain all original assertions and the TCP guard through shutdown.

Acceptance results:

- The original post-start TCP bind failed with `Os { code: 98, kind: AddrInUse }` when the fixture held the same TCP address. A second invocation of the entire external integration file confirmed the failure: three passed, one failed, zero skipped. That reproduction remains the evidence for the original defect.
- The earlier same-address fixture passed `just self-check feat/l8-account-profile` at `77b061dc7f249d4af0beacd634b80c64181bff36`: 416 tests passed, zero skipped. That successful invocation remains valid historical verification; it did not prove the fixture had removed the UDP availability assumption.
- The final test starts the real relay with an occupied `wss_listen` address and independently allocated UDP. It retains the absence-of-listener and certificate checks, checks the identifier against the actual UDP address, completes UDP registration and checks both advertised capabilities. The TCP listener remains bound until after relay shutdown.
- `just fmt-check` and `just lint` passed before running the corrected integration tests.
- `cargo nextest run -p nsshared-mock-relay --test external --locked` passed twice at `623c21c24ba7d570077005146794125e01eb330d`: four tests passed, zero skipped on each invocation.
- `just self-check feat/l8-account-profile` passed at `623c21c24ba7d570077005146794125e01eb330d`: 416 tests passed, zero skipped, with all static, compatibility, doctest and documentation checks passing. Only these documentation records changed afterward.
- Local review confirmed the occupied TCP guard is never released during startup or assertions and UDP uses the runtime's own port-zero allocation. No runtime changes, retries, skips or fallbacks were introduced.
