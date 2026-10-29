# Account migration

How a consumer moves from `nsshared_proto::account` (revision `1bc1d39e`) to
`nsshared_control::account`. The `nsshared-proto` facade does not re-export
`account`, so every account import changes once. The import move preserves wire bytes; the
separate candidate extensions below have explicit compatibility boundaries.

| File | Contents |
| --- | --- |
| [account-migration.json](account-migration.json) | Every public item of `nsshared_proto::account` at `1bc1d39e`: old path, kind, status (`moved`, `renamed`, `changed`, `split`, `removed`), new path, member changes and notes; and one section per error enum with every variant's successor |
| [`scripts/migrate-account-imports.py`](../../scripts/migrate-account-imports.py) | Rewrites the imports and paths of a consumer repository from the map |
| [`scripts/account_migration.py`](../../scripts/account_migration.py) | Generates the map from rustdoc JSON of both revisions and checks that every old item and error variant appears exactly once |

## Steps

1. Run a dry run and read the report:

   ```sh
   python3 scripts/migrate-account-imports.py /path/to/consumer > migration.txt
   ```

   It prints a unified diff of every Rust source it would change, then the
   counts and per-site lists: unmapped paths (left untouched), renamed items
   aliased to their old names, items whose behaviour or signature changed,
   error variants to update by hand, and the dependency changes.
2. Make the Cargo change below. The script never edits manifests.
3. Apply and format:

   ```sh
   python3 scripts/migrate-account-imports.py /path/to/consumer --apply --quiet
   cargo fmt --all
   ```

   The rewritten `use` trees are valid but not wrapped; `cargo fmt` makes them
   rustfmt-clean.
4. Work through the manual items below, using the report's per-site lists.
5. Verify.

What the script rewrites:

- `use` statements at any nesting depth, including brace groups and nested
  groups; non-account members of a mixed group stay with `nsshared_proto`.
  Attributes and doc comments of the statement (`#[cfg(test)]`, `#[allow(..)]`,
  `///`) are repeated on every statement it is split into;
- fully qualified `nsshared_proto::account::...` paths outside `use`, including
  absolute `::nsshared_proto::...` paths and paths inside macro invocations
  (`json!`, `matches!`, `assert_eq!`, ...), whatever token precedes them;
- paths relative to an imported old module (`use nsshared_proto::account;`
  then `account::X`, or `use ...::control_exchange;` then
  `control_exchange::X`): the module is imported as its new area under the old
  name, and items of a split module that live in another area are rewritten to
  their full path;
- glob imports: replaced by explicit imports of the old items the file and its
  out-of-line child modules name, so the area module names (`control`, `node`,
  ...) never enter scope. Old modules a glob brings into scope are followed:
  their paths in the file, `use` statements relative to them
  (`use control_exchange::CONFIG_STREAM;` becomes a full path) and the same
  paths in child modules that `use super::*`. `use nsshared_proto::*;` keeps the
  glob and adds `use nsshared_control::account;` when the file uses `account::`;
- renamed items imported by `use` are aliased to their old name
  (`... as validate_snapshot`) and listed; rename the uses and drop the alias
  when convenient.

A `use` statement containing an unmapped or manual item is left whole and
listed, so nothing half-migrates. Outside `use`, these are left in place and
listed as well: a path group or glob inside a macro
(`m!(nsshared_proto::account::{A, B})`), an old path behind another path
(`other::nsshared_proto::account::X`), and a glob of a module the map does not
know. After rewriting, every old account path still in a file is listed, so
none is skipped silently.

Not followed: a consumer's own re-export of the crate
(`pub use nsshared_proto as shared;` then `shared::account::...`). Point the
re-export at the new crate, or rewrite those paths by hand.

## Cargo change

Add `nsshared-control` from the same source and revision as `nsshared-proto`,
with the `unstable-account` feature, and bump both to a revision that contains
`nsshared-control`:

```toml
[workspace.dependencies]
nsshared-proto = { git = "<nsshared source>", rev = "<rev>" }
nsshared-control = { git = "<nsshared source>", rev = "<rev>", features = ["unstable-account"] }
```

`account` exists only with that feature. It is a candidate contract: not covered
by semver, and it may change incompatibly before the gate is removed and a
release is made, so pin a revision rather than a version range.

Then `nsshared-control.workspace = true` in each member the report names (the
feature comes from the workspace entry). Keep
`nsshared-proto` for its other modules. Pin every nsshared crate, including the
mocks and `nsshared-service-control`, to the same revision: a second revision
duplicates `nsshared-codec` and `nsshared-identity`, and `AccountError::Cbor` or
`RealmId` from one copy no longer matches the other. Add `nsshared-identity`
when the report asks for it (`RealmId` and `RealmIdError` live in
`nsshared_identity::realm`).

## Manual items

- Error matches. Read the `errors` section of the map for each enum the report
  lists. The common rewrites:
  - `AccountError::InvalidField`, `PublicationError::Fields` and
    `SubnetReportError::Fields` are `Field`.
  - `Encoding(CborError::X)` of `BootstrapError`, `PublicationError`,
    `SubnetError` and `SubnetReportError` is `Contract(AccountError::Cbor(CborError::X))`.
  - `SourceError::Conflict` and `SourceError::Reference` moved to
    `control::RouteError`. `RouteCommand`, `RouteResponse`, `RouteReceipt` and
    `decide_route_command` now return `RouteError`; a consumer error type that
    converts with `?` needs a `From<RouteError>` variant beside its
    `From<SourceError>` one.
  - `NodeL3Authority` decoding now returns `node::L3AuthorityError`;
    `GrantError::Policy` became `Contract`. A consumer error with
    `From<GrantError>` needs `From<L3AuthorityError>` as well.
  - `ParticipantRosterError::{BadSignature, StaleVersion, WrongIssuer,
    WrongRecipient}` are `Signature`, `Stale`, `Issuer` and `Recipient`;
    `BindingError::Version` is `Stale`.
  - `EdgeServiceAckError`, `PublicationError` and `SnapshotRequestError` are now
    `non_exhaustive`: an exhaustive `match` needs a wildcard arm.
- The usage digest domain. `USAGE_PART_DOMAIN` was the NUL-terminated byte
  domain; `domains::USAGE_PART_DIGEST_DOMAIN` is the text domain passed to
  `nsshared_control::service::domain_digest`, which appends the separator. Do not hash it
  directly. Code that hashed the old constant must call `domain_digest`.
- Participant frame kinds. The `participant_session` `u8` constants (`ENROLL`,
  `ENROLLED`, `AUTHENTICATE`, `AUTHENTICATED`, `RENEW`, `RENEWED`, `REPORT`,
  `ANSWER`, `ROSTER`, `REFUSED`) are `relay::FrameKind` variants;
  `FrameKind::byte()` gives the wire byte and `Frame` carries a `FrameKind`.
  The script lists every use site.
- Scope text. Every opaque authority scope follows one rule: 1 to 256 UTF-8
  bytes without whitespace or control characters. Publication content,
  subscription, snapshot request, source binding and authentication source
  selection now refuse whitespace (publication content also control
  characters). Consumer fixtures or configuration with such scopes must
  change; the refusal is the only behaviour change.
- Auto traits. `BootstrapError`, `PublicationDecision`, `PublicationError`,
  `SubnetError` and `ServiceControlError` are no longer `UnwindSafe` or
  `RefUnwindSafe`, because they carry `AccountError`. Code that passes them
  across `catch_unwind` needs `AssertUnwindSafe`.

## Verify

```sh
python3 scripts/migrate-account-imports.py /path/to/consumer --quiet   # 0 paths left to rewrite
grep -rn 'nsshared_proto::account' --include='*.rs' /path/to/consumer  # empty
cargo fmt --all --check
cargo check --workspace --all-targets
cargo nextest run --workspace                                          # or the repository's test recipe
```

Every vector or fixture that pins wire bytes must still pass unchanged; only
scope text refusals may move a case from accepted to refused.

In this repository, `just account-migration-check` confirms the
map matches the code, and `python3 -m unittest discover -s scripts/tests`
covers the rewrite script.

## Current candidate delta

This is preparation for candidate consumers, not released migration guidance.
Final release revision and cohort remain **unset**. Keep all shared crates pinned
to one immutable pushed revision and retain `unstable-account` for account APIs.
The M6 floor API itself does not require the account feature.

### Whole-floor M6

Given an existing `Message` with `MessageBody::ReportReplace`, attach metadata
and explicit profiles through the additive API (inside a fallible caller):

```rust
use nsshared_service_control::{ExitSelection, FloorExitProfile, FloorReportMessage};

let complete: FloorReportMessage = report_message.with_floor(
    Vec::new(),
    vec![FloorExitProfile {
        reference: "exit-a".into(),
        selection: ExitSelection::Explicit(vec!["192.0.2.0/24".into()]),
        enabled: true,
        capabilities: Vec::new(),
        policy_labels: Vec::new(),
    }],
)?;
let retry_bytes = complete.encode()?;
```

`report_message` must already carry the current publisher/NSD/Network scope,
positive revision and Node runtime fence. `FloorMetadata.reference` must name a
plain declaration in that report. Exit references bind profiles within the
same enclosing scope; reports never grant traffic authority. Decode complete
requests with `FloorReportMessage::decode` (or authenticated `from_envelope`),
and use `validate_accepted` for the full pending-request comparison. Under the
account carrier, retain `PendingRequest::floor_report()` and validate through
`validate_unary_reply`; its `message()` projection cannot reconstruct a complete
retry. NSD still compares independently persisted current custody.

Empty metadata and Exit profiles keep exact legacy bytes and digest. Nonempty
content carries `floor_version = 1` and uses `ns.service.floor.v1`; legacy decoders
refuse it. `ReportContent`, `ReportReplace` and `ReportAccepted` stay unchanged.
Independent cases live in `crates/nsshared-control/tests/vectors/service/floor.json`;
the legacy baseline is `service/canonical.json` under that same vector root.

### Roster publication versus attribution

Update account roster construction to supply `schema_version` and
`attribution_epoch` explicitly. Preserve schema 1 when re-encoding old signed
content: its epoch must equal `version`. Select schema 2 only for a producer and
consumer that support independent counters. This intentionally changes candidate
Rust struct literals and verification signatures behind `unstable-account`;
legacy wire preservation does not imply source compatibility. Verification supplies both
persisted floors (inside a fallible caller):

```rust
use nsshared_control::account::relay::verify_participant_roster;

let accepted = verify_participant_roster(
    &signed_bytes,
    trusted_issuer,
    expected_recipient,
    last_publication_version,
    last_attribution_epoch,
    now_ms,
)?;
```

Both counters use `RosterVersion`; `Roster.version` is strictly increasing per
issuer/recipient while `Roster.attribution_epoch` is independently non-decreasing.
No ordering relation between their magnitudes is valid. Persist both accepted
floors atomically before exposing admission and restore both after restart.
Initialize both to zero only for a scope without prior accepted publication.
Capture the authenticated epoch at DATA acceptance and retain original usage
attribution across renewal; do not substitute the latest publication version.
Schema-1 bytes/signatures and existing usage bytes are preserved. Independent
schema/counter cases are in
`crates/nsshared-control/tests/vectors/account/relay/participant-roster.vec`.
The separate local admission snapshot is schema 3 with required admission
history, covered by `account/relay/admission-snapshot.vec`; signed roster schema
compatibility does not authorize a history-free local snapshot fallback.

### Remaining prerequisites

The [candidate inventory](account-inventory.md#current-candidate-additions-and-release-inventory)
records current fixture locations and remaining standalone label/vector gaps.
These examples execute no consumer check and establish no producer agreement.
Q22/Q23, M01/M02 and Q24 remain open; bounded Q07/Q11 answers do not approve
remaining producer vectors or unmatched downstream corpora. Keep review approval,
live qualification, retention-seal acceptance and F04 integration outstanding.
Production eligibility requires H03/R01/R02/C01b and C18 re-verification at the
actual release revision; deletion stays held under Q-RET. No tag, dependency
change or feature restriction removal is selected by this guide.
