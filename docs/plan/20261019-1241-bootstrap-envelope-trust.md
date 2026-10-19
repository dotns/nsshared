# Bootstrap discovery and envelope trust

- **status**: completed
- **createdAt**: 2026-10-19 12:41
- **approvedAt**: 2026-10-19 12:41
- **relatedTask**: 20261019-1241-bootstrap-envelope-trust

## Context

Family 11 already covers discovery and envelope verification but has no detailed
contract. Enrollment binds membership keys; it does not establish transport trust.
The existing signed roster demonstrates canonical content inside a signed carrier.
The service-control Message remains the only service message codec and its raw
envelope stays private. Inventoried trust requires confidential ordered endpoints,
WebPKI discovery, SPKI and signing-key pins, and explicit local-pin intersection.

## Proposal

Specify canonical discovery and signed opaque carriers, then publish independent
Python decisions and signatures consumed directly by Rust tests. Implement only
pure validation with supplied clock and replay observations. Keep the registry and
existing fixture entries unchanged. Document producer questions in Q11 and Q21.

## Risks

Origin normalization, signature domain confusion, empty pin intersections and clock
boundaries must fail closed. Replay persistence and WebPKI authentication belong
to callers; pure validation must not imply either was performed locally.

## Scope

Account bootstrap/envelope modules, independent producer and consumer tests,
profile, review request and the associated plan and work records.

## Alternatives

Retaining JSON or historical wire shapes would introduce compatibility code.
Recreating service-control messages would duplicate their existing contract.

## Acceptance results

The candidate specification, independent producer, pure validators and consumer
tests are implemented. The consumer reads 100 new named vectors with explicit
bytes and decisions. All 106 pre-existing fixture entries and registry bytes are
unchanged. The focused suite passed ten tests, including the four bootstrap tests.

The first consumer build failed because the required bootstrap public APIs were
absent. After implementation, format and lint checks passed, and the generator
reported all nine fixture files current. The first complete scoped self-check
passed 410 tests with zero skipped, plus documentation and static checks.

One scoped self-check after clarifying the review request failed in the
unchanged external relay test: external_mode_announces_wss_without_a_tcp_listener,
examples/mock-relay/tests/external.rs:269, returned AddrInUse during a bind.
It reported 35 passed, one failed and cancelled the remaining tests. This proves
a failed bind, not its ownership or underlying cause.

A subsequent invocation of `just self-check` with the integration base, on the
unchanged implementation at `6fbb1eccd34516ced170c043b538db815fbe003a`, passed
410 tests with zero skipped, all doctests, vector verification and static checks;
it exited successfully. The previous failed bind remains undiagnosed. Listener
code and test/runtime settings are unchanged. Those checks cover the initial
implementation; the IDNA correction below is now verified separately. Independent
producer confirmation remains requested in Q11 and Q21.

## Canonical IDNA origin correction

The initial shared hostname predicate checked ASCII DNS label syntax without
validating Punycode or the Unicode properties of decoded A-labels. Invalid labels were accepted
in the HTTPS discovery source and HTTPS, Noise and QUIC endpoints. The behavioural
test `ascii_idna_origins_reject_invalid_a_labels` establishes this failure across
`decode`, `canonical`, `first_supported` and `effective_envelope_pins`, after valid
DNS and IDNA controls have passed. Its pre-correction result is a failed assertion,
not a build or input-reading failure.

Use a standards-conformant IDNA implementation and require its ASCII output to
equal the supplied hostname exactly, retaining the existing DNS/IP constraints.
At the time of that failure, the crate had no IDNA validator dependency. The
implementation below adds that dependency and the shared predicate correction. A sample
denylist, blanket A-label rejection or handwritten partial Unicode checks would
violate the general canonical-origin contract.

The merged producers regenerate 258 vectors, preserving all 206 earlier account
vectors and all 158 integrated vectors, including 52 Subnet vectors. Registry and
service-control files are unchanged. Formatting and lint pass; the existing
account/bootstrap focused suites pass ten tests. The IDNA behavioural test fails
with all twelve malformed origin placements accepted by all four entry points.
An earlier prescribed self-check exited 101 during API compatibility checking:
the baseline telemetry dependency refresh cannot download serde because its
registry connection terminates unexpectedly. It does not reach the test phase.
The implementation and acceptance results below complete the correction; the
previous registry-fetch failure remains recorded.

## IDNA correction implementation

The implementation uses `idna` 1.1.0, verified against the registry, for UTS #46
ToASCII with the URL
ASCII deny list. Require its result to equal the supplied hostname after existing
ASCII DNS label constraints pass. Keep canonical IP validation and the existing
origin scheme/port rules. This preserves valid DNS labels, including interior
hyphens, and validates decoded A-label Unicode properties without normalizing the
signed publication. Add independent Punycode fixtures across source/HTTPS/Noise/
QUIC, with valid multilingual controls and malformed/noncanonical refusals.
The existing behavioural regression remains unchanged and retains its recorded
pre-correction assertion failure. Dependency policy checks remain unchanged.

## IDNA correction acceptance

The shared predicate now rejects malformed, forbidden and noncanonical A-labels
through decoding, encoding, selection and effective pin establishment for the
HTTPS source and HTTPS/Noise/QUIC endpoints. Existing canonical DNS/IP constraints
remain intact. The original behavioural regression and its valid DNS/IDNA controls
are unchanged and now pass. Seventy-two independent origin vectors add valid DNS,
multilingual and nontransitional controls plus malformed Punycode, NFC, combining
mark, joiner, bidi, unassigned and mapped-character refusals in all four positions.
The consumer checks all four public paths against each vector's decision and bytes.

All 258 previous vector records are preserved field for field in the 330-record
fixture, including all 52 Subnet records. Registry, M6, Subnet and RelayId source
files remain unchanged. The dependency delta is idna 1.1.0 plus 23 resolved
transitive packages; no existing package version, checksum or resolved dependency
edge changed except the direct idna edge. Existing synstructure references gain
version qualification because both resolved versions are present.

Format/lint, license/advisory/bans/source policy, unused-dependency checks, API
compatibility, deterministic vector verification, doctests and documentation pass
without policy changes. The focused origin/bootstrap/account suites pass twelve
tests. The first scoped invocation on the corrected implementation encountered
AddrInUse in the unchanged external relay test: 32 passed, one failed, zero skipped,
with 382 tests cancelled. A separate invocation on the identical implementation
commit `b496fd6fe9ed3e690afb128d587e3b94a7738ce3` passed all 415 tests with zero
skipped and completed all remaining checks, exit 0. The prior failed bind remains
undiagnosed; no listener code, test/runtime setting or host service was changed.
The separate RelayId A-label question remains for its existing contract's review.
Independent producer confirmation remains requested in prepared Q11 and Q21.
