# Ordinary provider Subnet route reports

Status: pure candidate contract; independent fixtures are labelled authority,
not NSD producer output or persistence evidence.

## Wire contract

`node.subnet.report` uses the authenticated confidential BootstrapEnvelope in both
directions. Request payload is `[1, bstr(SignedSourceBinding), report_generation,
offers]`, with each offer `[subnet_id, selection]`. Response payload is
`[1, bstr(SignedSourceBinding), report_generation, allocations]`, with each
allocation `[subnet_id, bstr(canonical_M6_ServiceRef)]`. Arrays have exact arity,
definite lengths and shortest unsigned integers; extra fields and trailing bytes
are refused. Generation is positive u64. Mapping ids are nonzero u32, ascending
and unique. Each list has at most 256 entries. Payloads have an inclusive 1 MiB
encoded limit, in addition to unchanged carrier and transport limits.

Selection retains the exact SubnetSelection representation: `[0, []]` explicitly
offers the logical default; `[1, prefixes]` offers strictly ordered nonoverlapping
network-aligned B40 prefixes, at most 256 per offer. Empty explicit offers no
destinations. Named destinations must fit the mapping's committed real prefix,
with the same family; default requires a real /0. No absent-field default,
chunking, truncation or repair exists. M6, B40 publications and P06 commands keep
their exact existing bytes. M6 supplies reference encoding directly.

## Authority and pure comparisons

NSD enrollment/source custody supplies the full signed nodes binding, including
the assigned profile, full Node identity, source record, epoch and generation.
The sole existing candidate profile remains `explicit-gateway-profile`; no new
profile is inferred. The caller supplies its exact current committed binding and
authenticated caller identity. Nested signature and every binding field must
match; an egress binding cannot substitute. A retired binding is refused even
when replaying identical report content.

NSD mapping custody supplies mapping id, Network, real and mapped prefix,
provider membership and active provider authority. Pure input exposes the owning
Network, full provider identity, active eligibility and real prefix needed for
report qualification. The caller resolves those facts transactionally, including
membership and mapped-prefix validity. Offered ids and configured prefixes are
intent, never authority. Report acceptance grants no membership, consumer
permission, selection or applied routing.

The caller supplies the identity-bound M6 NSD id separately from the NSD signing
identity and the exact Network id. Network equals the binding's served RealmId
bytes. Reference NSD/Network components must equal these independently committed
facts. NSD alone allocates unique service ids in its existing namespace; no
mapping number conversion or private-service reference substitution is defined.

A newer generation replaces the complete source-owned offer set. Omission
withdraws a live offer and an empty set withdraws all. Equal generation and exact
content returns the retained allocation result; changed equal content conflicts;
older generations are refused. Accepted generation/content and allocations remain
retained after withdrawal and restart. Allocation custody is keyed by `(NSD,
Network, full signed source binding, subnet_id)`. Retained allocations include
withdrawn ids. Updates and reoffers must reuse them; a response cannot replace an
already assigned reference. Pure functions return decisions and validate proposed
results without mutating caller state or assigning ids. Callers commit all facts
atomically and preserve history. Current authority is checked before a retry.

The request carrier authenticates Node, NSD recipient, request direction,
operation, freshness, signature and fresh nonzero nonce. A retry retains generation
and content but uses a fresh carrier nonce. The response carrier authenticates
trusted NSD, explicit reporting Node recipient, response direction, operation and
pending nonce. The provider retains the exact pending report and compares binding,
generation, mapping ids/order, current source and each reference's NSD/Network
and prior assignment. It also compares against the last accepted report: older
generations and changed equal-generation content are refused, even when an old
pending request remains in custody. Delayed responses of a retired source cannot restore offers.
Other sources have independent history and remain usable.

## Independent acceptance and adoption

`provider_subnet_report` consumes Python-produced bytes independent of Rust.
The sequence accepts A's explicit/default offers, retries and updates without
reference changes, withdraws one then all offers, reconstructs retained state,
refuses stale restoration, reoffers using retained allocations, retires A and
refuses delayed reports/responses while B remains usable. Wrong source/profile
and mapping association must refuse without mutation. Additional malformed wire,
carrier, bounds and reference variants exercise the same contract.

NSD N30 owns ingestion, allocation and persistence; N07/N08 resolve current
source/mapping authority before selection/projection. ns S11 produces intent and
S25 owns the shared adapter and response custody. Their adoption and producer-owned
interoperability vectors remain outstanding. Gateway self-reporting is deferred
to the later ordinary-provider integration; existing Exit consumption, deferred
live default Exit, M6 declarations and contribution sessions are unchanged.
