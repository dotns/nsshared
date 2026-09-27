# 20260927-2212-region-quick-owner-decision Region quick owner agreement decision

- **status**: completed
- **createdAt**: 2026-09-27 22:12
- **approvedAt**: 2026-09-27 22:12
- **relatedTask**: 20260927-2212-region-quick-owner-decision

## Context

A relay region serves quick pairing from one owner member, named with an epoch in every member's configuration and presented in the control HELLO extension (see [Region quick frames](20260927-2148-region-quick-frames.md)). Before a member forwards quick frames on a control link or runs its own broker it has to know whether the peer agrees on the owner, and whether any peer has shown that the local configuration is stale. That judgement is the only guard against two members serving as owner at once, so it belongs in the pure codec and state crate, where every case can be a sealed vector.

## Proposal

A new module `region_quick_owner` in `keynet-proto`, re-exported at the crate root.

- `RegionQuickOwner`: the local owner configuration, an owner in 1..=16 and an epoch of at least 1. The fields are private and `RegionQuickOwner::new` returns `None` for any other value. `None` as the local input means the member has no owner; configuration validation refuses an out-of-range local owner before it reaches the decision.
- The peer input is the peer HELLO's `Option<RegionHelloExtension>` as decoded: `None` is the legacy HELLO and only the legacy HELLO. An extension is never converted to `None` before the decision, so an extension, whatever its values, is never read as legacy.
- `RegionQuickLink`: `Agreed` when both sides carry the same owner and the same epoch; `Inactive` when neither side has an owner; `Mismatched` otherwise, including a legacy HELLO read by a member that has an owner.
- `RegionQuickOwnerState`: the in-memory fencing state, created fresh at start (`Default`). It keeps the highest claim any peer presented and whether peers presented that epoch with more than one owner.
- `decide_region_quick_owner(&mut state, local, peer)`: records the peer's claim and returns `RegionQuickOwnerDecision { link, may_serve }`. `highest_observed_epoch()` reports `H` below.
- `RegionQuickOwnerState::may_serve(local)`: the serving permission for a local configuration without a new HELLO, used after a reload.

### Fencing rule

With `H` the highest epoch a peer presented and `L` the local epoch (0 without an owner):

- nothing observed: the member may serve;
- `L > H`: the member may serve;
- `L < H`: fenced;
- `L == H`: the member may serve only when every peer that presented `H` presented the local owner.

### Out-of-range claims

The decoder rejects an extension whose owner is outside 1..=16 or whose epoch is 0, so a decoded HELLO never carries one; the decision still decides it, and fails closed. Such an extension makes the link `Mismatched` and is recorded as its epoch with no acceptable owner, the same record as two peers presenting that epoch with different owners. The member is then fenced while its local epoch is at most that epoch, which is never less than a valid claim with the same epoch and any owner fences: a valid claim fences a local epoch below it, and an equal one unless the owners match. An out-of-range claim with epoch 0 fences only a member without an owner, the only local epoch that is not above 0. A reload above that epoch or a restart lifts the fence.

### Why the state is bounded

Epochs below `H` need no record: a local epoch below `H` is fenced regardless, and a local epoch above `H` is above all of them. A higher epoch resets the conflict record because only the claims at `H` can meet a local epoch that is not already fenced. The state never lowers `H`, so a fence persists across later agreed links. A reload lifts it by bringing the local epoch to `H` with the owner the peers presented, or above `H`; a restart lifts it with a new state. A reload to `H` with a different owner stays fenced, which is the same-epoch conflict of two members presenting one epoch with different owners: each side fences itself when it reads the other's HELLO.

The module performs no I/O, reads no clock, holds no lock and adds no dependency; the caller serialises access to the state.

## Fixtures

`tests/fixtures/keynet-region-quick-v1/region_quick_owner.vec` holds 32 cases. Each case starts from a fresh state and applies numbered steps `local|peer|link|serving`, where `local` is `none` or `owner@epoch`, `peer` is `legacy`, `owner@epoch` with the values the extension carries (in range or not), or `-` for a local configuration change without a HELLO. The single-step cases cover equal claims, a higher and a lower peer epoch with the same and a different owner, the same epoch with different owners from both sides, a member without an owner, a legacy peer, neither side with an owner, and the largest epoch. The sequence cases cover a fence persisting across agreed and legacy links, lifting by a reload to or above the highest epoch, keeping it on a reload below, a highest epoch that never decreases, a reload to the highest epoch with another owner, peer conflicts above and below the local epoch, and a conflict reset by a higher epoch. Seven cases carry out-of-range extensions: owner 0 above the local epoch (with reloads to and above it), owner 17 at the local epoch, owner 0 below it, epoch 0 with and without a local owner, owner 0 read by a member without an owner, and owner 0 at the local epoch after an agreed link.

The file joins the sealed set: the manifest lists it with its digest and declares the case inventory `region_quick_owner_cases`; `data_file_count` is 2 and `coverage` names `region_quick_owner`. `region_quick_frames.vec` is unchanged.

## Tests

- `tests/region_quick_owner.rs`: the vector-driven test over every step, checking the returned decision and the state query after every step; sequence tests for the higher-epoch fence, a restart, and a same-epoch conflict seen from both members; a test that an out-of-range extension above the local epoch fences the member and raises the highest observed epoch; an exhaustive sweep over peer extensions with owners 0, 1, 2, 16, 17 and epochs 0, 1, 2, 3 and the maximum, the legacy HELLO, and every valid local claim of that grid or none, against the rule stated in the test, checking that each out-of-range claim fences at least as much as every valid claim with its epoch; claim validation.
- `tests/release_inventory.rs`: the new file is sealed; every drift check now runs for every sealed file (missing, corrupted, appended, rehashed, duplicated in the manifest, replaced by a symlink), and adding or removing a case with a rewritten digest is rejected for every case file.

## Risks

- An error in this decision fails open and lets two members serve. An earlier form converted an out-of-range extension to the legacy `None` before the decision, so an extension presenting a higher epoch fenced nothing; the peer input is now the extension itself. Every case is a vector, and the exhaustive sweep checks the full grid against an independent statement of the rule.
- The state is in memory; a restart forgets every observation by design. A restarted stale member is fenced again when it next reads a newer peer HELLO.

## Scope

- `crates/keynet-proto/src/region_quick_owner.rs`, `crates/keynet-proto/src/lib.rs`
- `crates/keynet-proto/tests/region_quick_owner.rs`, `tests/release_inventory.rs`
- `crates/keynet-proto/tests/fixtures/keynet-region-quick-v1/manifest.txt`, `region_quick_owner.vec`
- this plan and its task record

## Alternatives

- Recording every observed claim per epoch would answer the same questions with unbounded memory; only the claims at the highest epoch can affect a member that is not already fenced.
- Lifting a same-epoch conflict by any reload to an epoch at least as high as the highest would unfence a member whose unchanged configuration still conflicts with a peer; the decision keeps it fenced until the local claim matches every claim at that epoch or exceeds it.
