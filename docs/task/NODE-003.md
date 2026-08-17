# NODE-003 Carry the control plane's overlay address assignment to the node

- **status**: review — must merge with the `nsd` and `ns` arms, not ahead of them
- **priority**: P0
- **owner**: node-003-s6f
- **createdAt**: 2026-08-17 09:26 UTC
- **claimedAt**: 2026-08-17 09:26 UTC
- **relatedPlan**: PLAN-015

## Description

`RegisterResponse.wg_tunnel_ip` already exists on the wire
(`control::api::RegisterResponse`), and NSD already allocates a stable
per-machine overlay address for every machine type at registration. What is
missing is the client half: `AuthClient` decodes the registration response into
a **private** `RegisterResponse` (`control/src/auth.rs`) that does not carry the
field at all, so the value is dropped on both the envelope and the legacy JSON
path, and `MachineState` has nowhere to keep it.

The consequence is that a registered node cannot find out which overlay address
the control plane holds for it, and `ns-agent` therefore takes its own address
from `--tunnel-address`. That contradicts the authority model PLAN-124 rests
on: routes are approved, capabilities are projected, leases bind to the control
session — and then the node picks its own address.

This task supplies only the client-side carriage. No allocation, pool
management, or conflict resolution is added here or anywhere; the allocator
already exists in NSD and is untouched.

## Proposal

1. `crates/common/src/state.rs`
   - `MachineState` gains `pub overlay_address: Option<Ipv4Addr>` — the address
     the control plane assigned, not one the node chose.
   - `RegistrationFile` gains `#[serde(default)] overlay_address`, so a
     registration file written before this change loads unchanged and a node
     that was never assigned an address serializes the key away.
   - A dedicated `set_overlay_address` records it. `set_registered`'s signature
     is deliberately **not** extended: it has 21 call sites across four
     repositories, including `nsc`, whose behaviour is out of scope for this
     slice.

2. `crates/control/src/auth.rs`
   - The private `RegisterResponse` gains `#[serde(default)] wg_tunnel_ip`, so
     the legacy JSON path decodes a response that omits it exactly as it does
     today.
   - `register_envelope_inner` forwards `envapi::RegisterResponse.wg_tunnel_ip`
     instead of discarding it.
   - `apply_registration` writes it straight through, including `None`. This
     mirrors `domain_base`: the registration response is the statement of
     record, and a control plane that assigns nothing leaves the node with
     nothing rather than with a stale assignment.

## Acceptance criteria

- A registration response carrying `wg_tunnel_ip` leaves the assigned address
  readable on `MachineState`, on both the envelope and the legacy JSON path.
- A registration response omitting it decodes exactly as before and leaves
  `overlay_address` absent — no error, no default address.
- A registration file written before this change loads without error.
- No wire type, field, or bound changes. `nsc`, `nsn`, `nsd` and `nsgw` compile
  unchanged against this tree.
- Locked QA passes, and `ns`, `nsd`, and `nsgw` all build against this exact
  tree.

## Dependencies

- **blocked by**: none
- **blocks**: the `ns` PLAN-124 S6f arm (`ns-agent` taking its assigned
  address) and the `nsd` arm (projecting the allocation to connectors). All
  three merge in one window; this repository must not merge ahead of its
  consumers.

## Notes

- 2026-08-17 09:26 UTC: Claimed **PLAN-124 S6f** on `bkd/iiyn6df1` from
  `24c8623`. Investigation found the wire contract already complete — the gap
  is entirely in the client decode and in persistence — so this arm adds no
  wire surface. Proposal recorded above before any code changed.
