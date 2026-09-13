# Approved keynet design archive

These immutable approval records are maintained in the project. Their historical
wording and original references are preserved exactly; this index records their
current adoption status. Future decisions should add a new version rather than
rewrite an approved record.

| Record | Adoption status | SHA-256 |
| --- | --- | --- |
| [CLI interaction v1](keynet-cli-approved-v1.md) | Approved and applied by the design owner in docs commit `a4b98bc` | `df26a11295645ebacc9a84fc1b8d2306ad0ed2c8ae561e5af94bd6e919137faf` |
| [UDP relay v1](keynet-relay-udp-approved-v1.md) | Approved and applied by the design owner in docs commit `c5f8309` (design v0.5) | `ac4cd46535d71b6dce74bc8f541e5306d307fb8dab6aa96b0f6f0a423e7dca8b` |

The latest owner-reported authoritative English design is
`/workspace/nsiod/docs/docs/ns/keynet.md`, SHA-256
`173d4bf3ed25125822210e17c56ae31e172168098af7209d1d3486a5629b624e` (v0.5, docs commit `c5f8309`).
Archive hashes identify these review documents, not the authoritative design file.

CLI approval covers sections 1.1, 7.5, 7.6 and 14 and the four reviewed defaults.
The owner also applied consistent local Pairing/Pending data-model descriptions
and preparation-deadline references. The wire profile was unchanged.

UDP relay approval covers the complete recommended replacements, additions,
consistency edits, the CLI section 7.5 step-2 clarification and all six defaults.
It changes phases 5 and 6 substantively; design-pin bookkeeping affects phases
1 through 6. The owner alone applies this text and reports the resulting design
digest and revision before future specifications and fixture pins adopt it.

Phases 1 and 2 were built against the original design pin
`7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f`; the
campaign is paused (see `docs/plan/PLAN-017.md`). When it resumes, phase 2 is
re-pinned to v0.5 as metadata, phase 5 receives its specification against the
v0.5 relay profile, and every undispatched phase receives a complete updated
specification before dispatch, preserving its boundaries and pure-codec scope.

Relocating these records does not change design content, approval, source code,
fixture bytes, execution state or the external design checkout. The project
copies supersede the temporary paths as the maintained archive locations.
