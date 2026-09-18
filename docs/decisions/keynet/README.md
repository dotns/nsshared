# Approved keynet design archive

The [default-context profile v1](default-context-v1.md) records the 2026-09-16
client profile decision and shared identifier. It supersedes the network-facing
product behavior below while preserving the original wire conformance release.

These approval records are maintained in the project. Their substantive decisions
are preserved while local coordination metadata is omitted; this index records
their current adoption status. Future decisions should add a new version rather
than rewrite an approved decision.

| Record | Adoption status | SHA-256 |
| --- | --- | --- |
| [CLI interaction v1](keynet-cli-approved-v1.md) | Approved and applied by the design owner in docs commit `a4b98bc` | `3fd9a1b92f4da139b7be529347ee3d83f427b1df589298933eafb87b7ab5289d` |
| [UDP relay v1](keynet-relay-udp-approved-v1.md) | Approved and applied by the design owner in docs commit `c5f8309` (design v0.5) | `6ab7424d99e1f3e0df6b8d85837aa477e39f33555a5819455ebbfed74323576f` |

The latest owner-reported authoritative English design is `docs/ns/keynet.md`
in the documentation repository, SHA-256
`494c50a12112aa88fe6fa084c0be9a14a2ca66415244ff202b72d89e08190fc1` (v0.6, docs commit `0f56552`; v0.5 was `173d4bf3ed25125822210e17c56ae31e172168098af7209d1d3486a5629b624e` at `c5f8309`).
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
implementation is paused (see `docs/plan/PLAN-017.md`). When it resumes, phase 2 is
re-pinned to the current revision as metadata, phase 5 receives its
specification against the current relay and in-band control profiles, and every undispatched phase receives a complete updated
specification before dispatch, preserving its boundaries and pure-codec scope.

Relocating these records does not change design content, approval, source code,
fixture bytes, execution state or the external design checkout. The project
copies supersede the temporary paths as the maintained archive locations.
