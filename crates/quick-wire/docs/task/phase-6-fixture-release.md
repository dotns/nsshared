# Phase 6 interoperability fixture release task

## Status

Completed against keynet v0.7 at documentation commit
`4ae04faa06ca1f5d64e40aca58aa8e55a50c1e6e`, SHA-256
`ceeca74ab6dad33f34df36ef789c1d32014679c9592655439210c169b0bebce6`.

## Delivery boundary

- Seal the complete twelve-file `keynet-v1` data set without changing any
  normative vector byte.
- Publish the full design pin, release identity, file count, family coverage,
  case/field inventories, and per-file SHA-256 values in the manifest.
- Pin the final manifest digest in an implementation-independent release test.
- Reject missing, duplicate, unlisted, non-regular, symlinked, corrupted, and
  locally rehashed fixture inputs.

Runtime behavior, networking, persistence, asynchronous work, randomness,
generated expectations, and new dependencies remain outside this phase.

## RED and GREEN evidence

The first compiling release-inventory test ran two cases. Its drift-rejection
case passed, while the positive release case failed because the pre-release
manifest did not contain the sealed metadata and complete inventory. After the
manifest was completed, both release cases passed.

## Original-to-current assertion mapping

- The missing release seal maps to
  `complete_v07_release_matches_the_sealed_inventory`, which pins the manifest
  digest and every data-file digest without importing the
  protocol implementation.
- Incomplete manifest metadata maps to exact checks for the manifest format,
  release name, full design commit and digest, data-file count, coverage, and
  every block, flat-field, and relay-identifier inventory.
- Filesystem and local-rehash drift maps to
  `release_seal_rejects_manifest_file_and_link_drift`, including missing,
  unlisted, non-regular, symlinked, corrupted, rehashed, and duplicate entries.
- Fixed literal conformance remains exercised by the existing address,
  identity, conflict, KeyBinding, pairing, introduction, naming, relay,
  Revocation, relay-identifier, and control-record suites.

## Sealed inventory

The manifest is the machine-readable case inventory. It names 42 block-vector
cases, 30 relay/Revocation fields, 26 relay-identifier cases, and 11 control
record fields. The release test compares every item, not only these counts.
This includes `invalid_site_local_ipv6`, `greedy_ordered_endpoints`, and
`greedy_omitted_relays`, preserving both phase 5B acceptance repairs.

| Release file | SHA-256 |
| --- | --- |
| `addresses.vec` | `4be3448808959b8ad8bb301c7ed3e88bcf100cd68be13faf114b284d4ada2333` |
| `identities.vec` | `806d82478f9a665b12ba13302f78d590969a6c5371240fc183df9a1aa1f25841` |
| `conflicts.vec` | `87056bf4e15dfa63c67fcaea587ef68dec1c38b625fa713e166c9f12f6aa3b84` |
| `key_bindings.vec` | `0b6378af48eed1b49c96c34f016415e140860c32845e2cae73742d22d2fc46ba` |
| `pairing_tokens.vec` | `e2933b83298772e7fd36b6418f73d899cf4b08cf733e1fe324bdee025f2a571d` |
| `introductions.vec` | `6d0c1ca8f8a3e9199077077e78e543f305b80f7df5a5a61e1ca6463adc45d2e8` |
| `aliases.vec` | `0406dd0e60de7133e92323cdb3c391a17235b747cdd95a5167fb3d02ed6f3916` |
| `labels.vec` | `2b0328e0c3fc700929d58dee51a1a3fbda48518f9304200a2ce3773fa86f5330` |
| `name_records.vec` | `74584e2e68f2eaf382a63d4829b4ea9e92346bd37239208bba6a6e063d3a03e2` |
| `relay_revocation.vec` | `4f36ef6e4e5f07cdb778aea2855f0ffbd9b1597f35f1530ad69dcc092bbe345a` |
| `control_records.vec` | `4197b46b58694796d25a6592a4f1fc795c0a564973716d06eb6687d55b256ba9` |
| `relay_identifiers.vec` | `d5b3c2a0a5ded38201ad8f57ac437f8067d6461125086a0fa5bd854de1183595` |
| `manifest.txt` | `09c5184dfdd114151c6650c02eaca9d0710c6d321b1b5c72847d7fea506d13ea` |

All twelve `.vec` digests are byte-identical to the accepted phase 5B input.
Only the manifest metadata changed for this release.

## Verification evidence

- Focused release inventory: 2 passed after the intentional positive RED.
- Existing literal-vector inventory: 5 passed; inventory refutations: 13
  passed.
- Full package: 84 passed; package runner: 84 passed with zero skipped;
  documentation: 1 passed.
- All-target warning-denied lint, formatting, and whitespace checks passed.
- The repository quality gate passed all six stages and 793 tests with zero
  skipped. Existing dependency-policy warnings for duplicate/wildcard entries
  and the yanked `chacha20` 0.10.1 remained non-blocking and unchanged.
- Across the package gates, anonymous memory was 4,171,550,720 to
  4,180,537,344 bytes and available build-volume space was 102,608,535,552 to
  102,560,325,632 bytes. Across the final repository gate, anonymous memory was
  4,215,730,176 to 4,363,337,728 bytes and available space was
  102,560,059,392 to 101,686,403,072 bytes. The memory limit was
  25,769,803,776 bytes and the OOM-kill counter remained 15 throughout.
- Incremental self-review found no correctness, security, data-integrity,
  resource, or maintainability finding. No production source, dependency,
  protocol byte, runtime behavior, or generated expectation changed.
