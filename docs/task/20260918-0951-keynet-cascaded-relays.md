# 20260918-0951-keynet-cascaded-relays Keynet cascaded relays: multi-member relay regions

- **status**: pending
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-09-18 09:51

## Description

Specify and implement relay regions for keynet: one advertised authority served
by several relay members that exchange presence and security marks over an
authenticated mesh and forward datagrams once inside the region. The plan of
record is `docs/plan/20260918-0951-keynet-cascaded-relays.md`; this task tracks the ns-shared part (C1, the
`keynet-proto::region` codecs, pure join, presence and staging decisions, and
fixtures) and the cross-repository sequencing. Acceptance: the plan is
approved, C0 (the keynet v0.9 design revision) is reviewed, and C1 lands on
`feat/keynet-cascaded-relays` with sealed fixtures, an updated inventory and
consumer pins.

## ActiveForm

Specifying keynet relay regions and their shared codecs

## Dependencies

- **blocked by**: plan approval; C0 design revision in the documentation repository
- **blocks**: nsgw relay region implementation (C2); ns-remote registration policy (C3a) and region integration (C3b)

## Notes

- Integration branch: `feat/keynet-cascaded-relays` in ns-shared, nsgw and ns-remote, re-cut from the post-keynet `main` on 2026-09-18.
- Design baseline: keynet v0.8 (documentation repository `main` `a8a3022`); the plan adds v0.9.
- Decision status: D1 closed; D2, D4 and D5 decided; D3 and D6 adopted at their defaults on 2026-09-20; D7 and D8 withdrawn.
- 2026-09-20: the first independent review of the plan returned REVISE with 20 findings; all were applied to the plan, which stays in draft until C0 is reviewed.
