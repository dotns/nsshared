# Handoff: make `next` the nsshared main line

> Done 2026-10-03: the archive tag is pushed, remote `main` is `next` (tags
> `v0.1.0`, `v0.2.0`) and the local checkout `/srv/dotns/ns-shared` follows
> `main`. The old remote branches are kept as a record (owner decision; also in
> the bundle backup), so the cleanup command below is not run. Branch
> `refactor/unified-engine` is kept the same way: its author retired the
> duplicate `ns-proto` crate onto this line (its PLAN-027, code equal to
> `12c76b9`); its plan and task records stay on that branch. Still open: the
> consumer steps below.

Status on 2026-10-03, for whoever continues the rewrite in this repository.

## Where things are

| Item | State |
| --- | --- |
| Remote | `ssh://git@git.pvv.cc:33/nsiod/nsshared.git` (renamed from `nsiod/ns-shared`; the old URL redirects) |
| Remote `main` | `7c8214d`, the v1 workspace (`control`, `common`, `acl`, `tunnel-ws`, `telemetry`, `keynet-*`) |
| Local `next` | 60 commits on top of `main`; `main` is an ancestor, so moving `main` to `next` is a fast-forward |
| Archive tag | `archive/v1-20261002` -> `7c8214d`, local only |
| Old remote branches | backed up in `/srv/dotns/.backup/ns-shared-remote-branches-20261002.bundle`; deletion still pending |
| Checkouts | `/srv/dotns/ns-shared` on `main`; worktree `/srv/dotns/ns-shared-next` on `next`; BKD project `z2eicn7y` points at the worktree |

`next` contains:

- `crates/nsshared-wire`: v2 wire formats (identities, node records and
  address derivation, relay v2 packets, region and in-tunnel control messages).
  Normative source: docs `ns/quick-v2.md`.
- `crates/nsshared-rendezvous`: rendezvous v2 (`/quick/v2`): capabilities,
  `hello`, relay directory v2, mailbox phases, node registry, pairing payloads,
  region forwarding bodies. Normative source: docs `ns/rendezvous.md`.
- `tools/vectors`: an independent Python generator for the conformance vectors
  (`just vectors`, `just vectors-check`).
- Spec coverage tables in `docs/spec-coverage/`; 433 tests; `just qa` green at
  `ce0771a`.
- Proposed next plan: `docs/plan/20261003-1400-nsshared-p3-release.md` (P3a:
  typed keys, `nsshared-telemetry`, relay carrier analysis, v1 crate analysis;
  then tag `v0.1.0`).

## Switch the local checkout to `next`

A branch can be checked out in only one worktree. Remove the `next` worktree
first (it has no uncommitted changes when this file is committed):

```bash
git -C /srv/dotns/ns-shared worktree remove /srv/dotns/ns-shared-next
git -C /srv/dotns/ns-shared switch next
```

Optional, already decided: rename the directory to match the repository.

```bash
mv /srv/dotns/ns-shared /srv/dotns/nsshared
```

Then update the BKD project `z2eicn7y` directory to the new path.

## Overwrite the remote

Push the archive tag first, so the v1 tree stays reachable by name:

```bash
cd /srv/dotns/nsshared            # or /srv/dotns/ns-shared
git push origin archive/v1-20261002
git push origin next:main         # fast-forward, no --force needed
git push -u origin next           # optional: keep a next branch on the remote
```

If `main` moved on the remote in the meantime, the fast-forward is refused.
Look at the new commits before deciding on `--force-with-lease=main:7c8214d`.

Clean up the old remote branches once the bundle backup is confirmed:

```bash
git ls-remote --heads origin | awk '{print $2}' | sed 's|refs/heads/||' \
  | grep -v -x -e main -e next | xargs -r -n1 git push origin --delete
```

## Effect on consumers

| Consumer | Effect | Action |
| --- | --- | --- |
| nsgw CI | Checks out `${owner}/ns-shared` at the pinned `shared_rev` (`7c8214d`). The commit stays reachable through `main`'s history and the archive tag | None now. Rename the repository in `ci.yml` to `nsshared` when nsgw moves |
| nsgw local builds | Path dependencies `../ns-shared/crates/{common,control,acl,tunnel-ws,telemetry}` disappear once the local checkout is on `next` | Keep an old checkout for nsgw (`git worktree add ../ns-shared-v1 archive/v1-20261002`) until nsgw moves to the shared v2 crates |
| ns (`refactor/nsplane`) | Uses `git = "file:///srv/dotns/ns-shared", rev = "ce0771a..."` | After the push, switch to `git = "https://git.pvv.cc/nsiod/nsshared.git"` with the same rev, later the `v0.1.0` tag. Update `deny.toml` allow-git. If the directory is renamed first, the `file://` URL breaks |

## Rules carried over

- Protocol is v2 only; no v1 compatibility code.
- Crates are named `nsshared-<purpose>`; library names `nsshared_<purpose>`.
- The pma-rust baseline applies: edition 2024, MSRV 1.96, workspace lints deny
  warnings, no unsafe, no unwrap/expect/panic outside tests, rustls with
  aws-lc-rs, `just qa` (fmt, clippy, deny, shear, typos, nextest, vectors-check).
- Every protocol change updates the docs spec first, then the vectors, then the
  code.
