# External WSS listener ownership

- **status**: completed
- **createdAt**: 2026-10-19 14:47
- **approvedAt**: 2026-10-19 14:47
- **relatedTask**: 20261019-1447-external-wss-listener-ownership

## Context

`MockRelay::start` binds UDP independently in external WSS mode. The bind function disables the built-in TCP listener whenever `external_wss` is true. The external integration test instead tried to bind TCP after UDP chose an ephemeral port, although UDP ownership guarantees nothing about TCP availability.

## Proposal

Keep a caller-owned TCP listener bound before starting the relay, and configure the relay's UDP carrier to use that address. First reproduce the failure by retaining the original second TCP bind. Then replace that bind with continuous ownership of the original listener through shutdown. Preserve the checks for no built-in WSS address, no generated certificate, matching relay identifier, successful UDP registration and both announced capabilities.

## Risks

The caller's chosen address must also be available for UDP, as in the combined-server fixture. No socket is closed and rebound to select a port, and there are no retries or skips.

## Scope

`examples/mock-relay/tests/external.rs` and the accompanying plan and acceptance record.

## Alternatives

Checking only `wss_addr()` would avoid a bind but would not exercise successful startup with an externally owned TCP listener. Changing the runtime socket API is unnecessary.

## Annotations

The caller retains TCP ownership until after relay shutdown. The original second bind failed with `AddrInUse` when TCP was deliberately occupied. The replacement passed twice with all four external integration cases. Formatting, lint and `just self-check feat/l8-account-profile` passed, including all 416 tests with zero skips, doctests and documentation checks.
