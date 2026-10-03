# 20261003-2200-shared-scope-trim Remove relay-internal region protocol and the transfer mapping

- **status**: completed
- **priority**: P1
- **owner**: claude/session-a85oq3gg
- **createdAt**: 2026-10-03 22:00

## Description

Owner decision 2026-10-03: nsshared holds only protocols shared by several
components. The relay region member protocol is relay-internal (only relay
instances encode it) and file transfer is an ns application; neither belongs
here.

Remove from `nsshared-wire` the region member protocol (frames, channel rules,
snapshot chunking, mark join, `MAX_REGION_RENDEZVOUS_FRAME_BYTES`); remove from
`nsshared-rendezvous` the region frame bodies 10-12 (`region` module) and the
transfer mailbox mapping (`KIND_TRANSFER`, `transfer_open_request`); remove the
matching vector producers and fixtures. Keep what clients see: the `region`
capability token, the `unavailable` error and the authority rules.

Acceptance: `just qa` passes; spec coverage marks the removed sections as
relay-owned or ns-owned; changelog records the removal.

## ActiveForm

Trimming nsshared to shared protocols

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

The region code stays available at tag `v0.1.0` for the relay implementation.
