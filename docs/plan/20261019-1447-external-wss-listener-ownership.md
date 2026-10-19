# External WSS listener ownership

- **status**: completed
- **createdAt**: 2026-10-19 14:47
- **approvedAt**: 2026-10-19 14:47
- **relatedTask**: 20261019-1447-external-wss-listener-ownership

## Context

`MockRelay::start` binds UDP independently in external WSS mode. The bind function disables the built-in TCP listener whenever `external_wss` is true. The external integration test instead tried to bind TCP after UDP chose an ephemeral port, although UDP ownership guarantees nothing about TCP availability. Reserving TCP first and requiring UDP on the same numeric port reverses the same unsupported assumption: TCP ownership does not reserve UDP.

## Proposal

Keep a caller-owned TCP listener bound on `127.0.0.1:0` before starting the relay. Set `external_wss: true` and `wss_listen: Some(addr)` to that listener's address; leave `listen` at its default `127.0.0.1:0` and `udp_listen` at `None`. The relay allocates and retains its own UDP socket independently. Successful startup while the configured WSS address is occupied, together with no built-in WSS address and no generated certificate, proves external mode ignores the TCP listener configuration. Preserve the relay identifier check against the actual UDP address, successful UDP registration and both announced capabilities. Keep the TCP guard through relay shutdown, without requiring either equality or inequality between the independently allocated port numbers.

## Risks

Neither protocol depends on availability of the other's numeric port. Both sockets retain ownership throughout the assertions. No socket is closed and rebound to select a port, and there are no retries or skips.

## Scope

`examples/mock-relay/tests/external.rs` and the accompanying plan and acceptance record.

## Alternatives

Requiring the UDP twin of a TCP reservation still permits an unrelated UDP owner to cause startup failure. Checking only `wss_addr()` avoids that assumption but does not exercise the ignored occupied WSS address. Changing the runtime socket API is unnecessary.

## Annotations

The original second TCP bind failed with `AddrInUse` when TCP was deliberately occupied. An earlier same-address fixture passed the four external cases twice and all 416 self-check tests, but those observations did not establish independent UDP ownership. The corrected configuration passed the complete external integration file twice and `just self-check feat/l8-account-profile`, including all 416 tests with zero skips, doctests and documentation checks. Formatting and lint passed before the test invocations.
