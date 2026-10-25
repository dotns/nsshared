# Account migration

How a consumer moves from `nsshared_proto::account` (revision `1bc1d39e`) to
`nsshared_control::account`. The `nsshared-proto` facade does not re-export
`account`, so every account import changes once. Wire bytes do not change.

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
  groups; non-account members of a mixed group stay with `nsshared_proto`;
- fully qualified `nsshared_proto::account::...` paths outside `use`;
- paths relative to an imported old module (`use nsshared_proto::account;`
  then `account::X`, or `use ...::control_exchange;` then
  `control_exchange::X`): the module is imported as its new area under the old
  name, and items of a split module that live in another area are rewritten to
  their full path;
- glob imports: replaced by explicit imports of the old items the file and its
  out-of-line child modules name, so the area module names (`control`, `node`,
  ...) never enter scope;
- renamed items imported by `use` are aliased to their old name
  (`... as validate_snapshot`) and listed; rename the uses and drop the alias
  when convenient.

A `use` statement containing an unmapped or manual item is left whole and
listed, so nothing half-migrates.

## Cargo change

Add `nsshared-control` from the same source and revision as `nsshared-proto`,
and bump both to a revision that contains `nsshared-control`:

```toml
[workspace.dependencies]
nsshared-proto = { git = "<nsshared source>", rev = "<rev>" }
nsshared-control = { git = "<nsshared source>", rev = "<rev>" }
```

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
