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
and move both to `v0.8.0` or a compatible later revision:

```toml
[workspace.dependencies]
nsshared-proto = { git = "<nsshared source>", rev = "<rev>" }
nsshared-control = { git = "<nsshared source>", rev = "<rev>" }
```

`account` is available unconditionally and covered by semver from `v0.8.0`.
Remove `features = ["unstable-account"]` when upgrading; that feature no longer
exists. Keep all shared crates on the same immutable release or revision.

Then `nsshared-control.workspace = true` in each member the report names. Keep
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

## Release migration delta

The `v0.8.0` release makes account part of the stable public API. Keep all shared
crates pinned to one immutable release or revision and remove `unstable-account`
from consumer manifests. Planning selects the final merge commit and tag;
review answers no longer block the release.

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
consumer that support independent counters. This changed pre-v0.8.0 candidate
Rust struct literals and verification signatures;
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
actual release revision; deletion stays held under Q-RET. The 2026-11-07 owner
decision removes the feature gate for `v0.8.0`; planning owns the merge and tag.

### Release-time substitutions and examples still required

Use the [exact case index](account-inventory.md#exact-candidate-case-index) to
select fixtures for the actual consumer; do not treat the eleven rows as a
complete release suite. The following checklist remains open:

- [ ] Replace `<nsshared source>` and `<rev>` in the Cargo example with the
  authorized immutable released source/revision shared by both crates. Record
  the actual tag, public export surface and selected consumer versions; the
  import map's historical baseline is not the release selection.
- [ ] Choose the actual producer/consumer cohort and applicable family kinds,
  M6 body variants and signature/digest domains. Supply a compiling migration
  example in each affected consumer at that pin, plus exact input and expected
  output locators. Q23 confirmation and Q22 missing cases remain required.
- [ ] Instantiate the whole-floor example with real accepted custody, explicit
  profiles, persisted runtime fence, complete pending bytes and complete digest
  comparisons. Demonstrate the chosen legacy/extended producer-consumer mix;
  empty-extension compatibility alone does not qualify nonempty reports.
- [ ] Instantiate roster verification with the cohort's supported signed schema,
  both restored counter floors and atomic persistence; demonstrate schema-3 local
  admission history and DATA-time attribution in the actual reader/writer.
  Fixture-fed local unions cannot substitute for that writer.
- [ ] Supply the separate provider-mappings producer/consumer example and the
  missing matching edge/profile/ledger/roster corpus readers. Supply NSD's
  remaining information/discovery and grant/payer/withdrawal producer cases,
  material/auth/policy cases and applicable scope/limit refusals. Preserve each
  corpus's producer revision and matching consumer revision independently.
- [ ] Obtain external review dispositions, including M01/M02 and Q24; reconcile
  any approved API changes against examples rather than inferring approval from
  shared fixture success. Keep opaque `node.control` without invented semantics.
- [ ] Reconcile retention-seal acceptance, F04 integration, original settlement
  and rollback assets with the actual cohort. Record applicable live observations
  and re-verification at the released revision. Keep Q-REL, H03/R01/R02/C01b,
  C18 and Q-RET obligations open until their own evidence is supplied.

No release-time substitution or cohort-specific executable example is selected
by this checklist. The current examples remain candidate guidance.

## Epoch recovery in 0.10.0

The unconditional, semver-covered `account::relay::FrameKind` adds exhaustive
`EpochRequest = 11` and `EpochResult = 12` variants. Consumers must update closed
matches when adopting this minor version. Kinds 1..10, authentication-answer
version 2, signed roster schemas, DATA, usage and retention formats/domains are
unchanged. Old peers reject the new kinds. New decoders preserve all existing
fixtures byte for byte.

| Public API | Meaning |
| --- | --- |
| `EpochRequest::{new, canonical, decode, frame, from_frame, validate_for, scope, correlation, owner_generation, fenced_epoch}` | Strict 97-byte version-1 body; validate supplied authenticated pair/generation |
| `PendingEpochResponse::{new, request}` | Retain the exact recovery request separately from renewal `PendingResponse` |
| `EpochResult::{new, canonical, decode, frame, from_frame, validate_for, request, outcome, result_epoch, publication_version, retry_not_before_unix_ms}` | Strict 122-byte version-1 body; compare all pending fields, never grant roster/custody authority |
| `EpochOutcome::{Allocated, AlreadyFresh, RateLimited, StaleCustody, InvalidEpoch, Unavailable, from_byte, byte}` | Closed bytes 0..5 and strict outcome-specific field combinations |
| `FrameKind::{EpochRequest, EpochResult}`; `Frame::{new, decode, scope, correlation}`; `validate_header` | Shared kind/header validation and pair/correlation access for both new frames |

Consumer call sites inspected at NSD `e89764c3` and nsgw `cc9a2848`:

| Consumer path and item | Required adoption |
| --- | --- |
| NSD `crates/nsd/src/participant_session.rs`: `read_frame`, `connection`, `session_response` | Add kind 11 to the header operation allowlist and authenticated dispatch; bind accepted session generation and current custody in the transaction; return only correlated kind 12 after committed success. Existing wildcard/out-of-order checks stay closed until adoption. |
| nsgw `crates/nsgw-relay-control/src/participant/wire.rs`: `read`, `write` | Shared `FrameKind::from_byte`, `validate_header` and `Frame::new` gain decoder support from this revision. The transport continues to bound before allocating. |
| nsgw `crates/nsgw-relay-control/src/participant/lifecycle/session.rs`: sole session driver | Add an explicit EpochResult branch and a distinct pending epoch exchange alongside Roster, Renewed and Answer; preserve one reader and single consumption. Existing wildcard rejects unsolicited kinds. |
| nsgw `crates/nsgw-relay-control/src/participant/{operations,report,mod}.rs`: enrollment, renewal, report and authentication exchanges | Keep their operation-specific responses closed; an EpochResult cannot satisfy renewal, usage/seal ACK or authentication. |

The focused `epoch_consumer_dispatch_compile_probes` test compiles representative
NSD operation allowlisting and an exhaustive relay dispatch with the new enum.
It is a library compile probe, not a build or integration claim for either consumer.
The typed pending doctest proves renewal pending state cannot validate an epoch
result. Independent `account/relay/epoch.vec` covers exact bytes and malformed
combinations; the existing roster vectors cover unchanged-membership refresh and
fresh epochs with independent publication/attribution floors.

Upgrade NSD before enabling requesting relays; never send unsolicited EpochResult
to old clients. Requesting relays encountering an unsupported authority stay fenced
and diagnose incompatibility. No downgrade, fallback custody mutation, or implicit
negotiation is added. Pin the same immutable release/full resolved commit from
`git.pvv.cc/nsiod/nsshared` in consumer manifests, locks and standalone acceptance
workspaces. No sibling path dependency or local patch is a delivery dependency.
Full runtime, transaction, ordering, retry/cancellation and real-lab acceptance
remain the corresponding consumer deliveries' obligations before deployment.

## Node liveness refusals in 0.11.0

The public unconditional `account::control` API adds `NodeLivenessRefusal`,
`NodeLivenessOperation`, `NodeLivenessRefusalCode`, `NodeLivenessRefusalReason`
and `MAX_NODE_LIVENESS_REFUSAL_BYTES`. Existing exhaustive enums are unchanged.
The new seven-item version-1 response does not alter successful reports,
envelope v1, gateway contracts or M6. See the [exact contract](../spec/account/control.md#signed-node-liveness-refusals).

NSD classifies under locked current authority, returns signed correlated
409 runtime rebind/conflict or 403 genuine refusal, and retains 503 for unavailable
authority. The Node preserves refusal bodies through transport, verifies them
using persisted `NodeReportContext::validate_liveness_refusal` and then calls
`validate_for_heartbeat` or `validate_for_posture` on the complete pending request
before acting. Existing `ControlReportOperation::validate_payload` remains
success-only for these response operations. Reasons do not grant recovery;
runtime conflicts do not permit automatic takeover and scoped refusal does not
itself specify permanent Account sign-out. Metadata receipts remain separate.

Deploy NSD first, then enable new Node recovery on one matching immutable released
shared pin and updated lockfiles. Old raw carriers cannot decode the new payload
and treat 409 as transient; new Nodes retain conservative handling of old untyped
403. No negotiation, release publication or consumer runtime implementation is
included here. Consumer acceptance must cover locked classification, refusal
authentication/correlation, obsolete local ownership and the complete lifecycle.
