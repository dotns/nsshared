# PLAN-003 Gateway certificate distribution contract (nsgw PLAN-071 S1)

- **status**: completed
- **createdAt**: 2026-06-14 05:19
- **approvedAt**: 2026-06-14 05:19
- **completedAt**: 2026-06-14 05:40
- **relatedTask**: EDGE-002

## Context

This is the dependency-root contract slice for `../nsgw/docs/plan/PLAN-071.md`.
PLAN-071 moves multi-gateway shared-host TLS from per-gateway ACME issuance to
central issuance plus gateway-targeted distribution. The trust boundary is:
issuer agent holds DNS provider credentials, NSD stores encrypted cert material
and pushes bundles, and NSGW/Envoy consumes pushed material locally.

Current shared contract state:

- `crates/control/src/messages.rs` has key-free public edge snapshots:
  `GatewayHttpConfig` and `GatewayL4Map`. Both carry
  `Vec<PublicEdgeCertificateRef>`, and `PublicEdgeCertificateRef` contains only
  identity, hostnames, policy metadata, and a key-free source reference.
- `PublicEdgeCertificatePolicy` currently has `issuer_ref`,
  `min_tls_version`, and `require_sni`; it has no ACME challenge preference.
- `ControlMessage` currently has `gateway_http_config.v1` and
  `gateway_l4_map.v1` for policy snapshots, but no secret-bearing certificate
  distribution message.
- `control::api::GatewayReportRequest` is the existing gateway-to-NSD ACK-like
  report path. It already carries optional additive gateway metadata and is
  persisted/ingested by `nsd-api`, so it is the smallest compile-safe place to
  hang future certificate activation ACK status.
- `nsd/crates/nsd-policy/src/snapshot/public_ingress.rs` currently synthesizes
  `cert:{gateway}:{host}` certificate IDs for HTTPS public edge routes. PLAN-071
  requires `cert_id` to be per host/wildcard identity, not per gateway.
- `nsgw/crates/nsgw-control/src/config_stream.rs` dispatches the policy
  snapshot variants. It has no bundle receiver yet; this slice should compile
  and leave S4 TODOs without implementing SDS consumption.

PMA note: this repository does not currently have `docs/changelog.md`, so the
usual changelog-tail check could not be performed. No unrelated changelog file
will be introduced in this contract slice.

## Proposal

Add these shared control types in `crates/control/src/messages.rs`:

```rust
pub enum PublicEdgeCertificateChallengePreference {
    TlsAlpn01,
    Http01,
    Dns01,
}

pub struct GatewayCertificateBundle {
    pub cert_id: String,
    pub hostnames: Vec<String>,
    pub fullchain_pem: String,
    pub private_key_pem: String,
    pub issuer: String,
    pub not_after: u64,
    pub generation: u64,
}

pub struct GatewayCertificateStatus {
    pub cert_id: String,
    pub hostnames: Vec<String>,
    pub issuer: String,
    pub not_after: u64,
    pub fingerprint: String,
    pub gateway_ack_generation: Option<u64>,
    pub last_error_code: Option<String>,
}
```

`not_after` is an epoch timestamp in seconds, matching the assignment's
timestamp requirement while avoiding new dependencies. `generation` is
monotonic per `cert_id`; runtime monotonic enforcement belongs to the S3 store
and S4 consumer, not to this data type.

Extend `PublicEdgeCertificatePolicy`:

```rust
#[serde(default)]
pub challenge_preference: PublicEdgeCertificateChallengePreference,
```

Default it to `TlsAlpn01` so existing policy snapshots keep their current
behavior unless NSD explicitly chooses `Dns01`.

Add a separate control-stream variant:

```rust
#[serde(rename = "gateway_certificate_bundle.v1")]
GatewayCertificateBundle(GatewayCertificateBundle),
```

This variant is intentionally secret-bearing and must not be nested in
`GatewayHttpConfig`, `GatewayL4Map`, `PublicEdgeCertificateRef`,
`PublicEdgeCertificatePolicy`, or `PublicEdgeCertificateSource`.

Use the existing `gateway.report` path for future activation ACKs by extending
`control::api::GatewayReportRequest` with:

```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub certificate_statuses: Vec<GatewayCertificateStatus>,
```

This choice keeps gateway ACKs tied to the already authenticated
gateway-to-NSD envelope, avoids adding another API before S3/S4 know the
persistence semantics, and is additive for older callers. `nsd-api` will pass
the field through the shared request type and leave `// TODO(PLAN-071 S3)` for
store/ACK ingest. `nsgw` will keep emitting an empty list with
`// TODO(PLAN-071 S4)` until SDS activation exists.

Same-window consumer cascade:

- `ns-shared`: add the types, variant, `event_type`, and serde tests for
  bundle, challenge preference, status, and key-free policy snapshots.
- `nsd`: update certificate IDs to per-host identity (`cert:{host}`), default
  policy construction with `challenge_preference`, compile the new
  `GatewayReportRequest` field, and leave S3 TODOs for bundle production,
  encrypted store, push, and certificate ACK ingest. Do not implement storage
  or pushing.
- `nsgw`: update config-stream match arms and gateway report construction for
  the new type/field, and leave S4 TODOs for consuming the bundle into Envoy
  SDS and sending real ACKs. Do not implement SDS consumption.

Adversarial enumeration:

- Private key material must appear only in `GatewayCertificateBundle` and never
  in the key-free `GatewayHttpConfig` / `GatewayL4Map` policy snapshots.
- `cert_id` is per host/wildcard identity, not per gateway; one identity can
  fan out to many gateways.
- `generation` is monotonic per `cert_id`; the bundle is gateway-targeted by
  the signed/sealed control stream and later S3/S4 fan-out, not broadcast.
- `challenge_preference` defaults to `TlsAlpn01`, so existing behavior does not
  silently shift to DNS-01 until NSD explicitly chooses it.

## Risks

- This introduces a secret-bearing shared type. A mistaken field placement in
  policy snapshots would leak private keys into fan-out policy state.
- `gateway.report` ACK embedding is additive but not yet persisted. S3 must
  define durable ACK ingestion and status exposure semantics.
- Changing NSD's synthesized certificate ID from per-gateway to per-host is a
  visible contract change for tests and downstream routes, but it is required
  by PLAN-071's multi-gateway identity model.
- `generation` monotonicity cannot be enforced by a plain struct. It must be
  enforced by S3 storage/push and S4 activation logic.

## Scope

In this slice:

- Shared Rust wire types and serde tests in `ns-shared`.
- Compile-only `nsd` and `nsgw` adaptations with explicit PLAN-071 TODOs.
- Real-binary `just qa` verification in `ns-shared`, `nsd`, and `nsgw`.

Out of scope:

- Certificate store, encrypted-at-rest persistence, issuer-agent integration,
  actual bundle fan-out, Envoy SDS materialization, gateway activation logic,
  and runtime ACK/status exposure endpoints.

## Alternatives

- New `gateway_certificate_ack.report` API: cleaner separation, but premature
  before S3 defines durable ACK ingestion. It also expands the envelope routing
  surface for no runtime gain in this compile-only slice.
- Put bundle material into `PublicEdgeCertificateSource::Sds`: rejected because
  policy snapshots must stay key-free; `Sds` remains a local material reference,
  not private key transport.
- Default `challenge_preference` to `Dns01`: rejected because it would silently
  change existing single-gateway behavior.

## Verification

Implementation completed the PLAN-071 S1 contract and same-window compile
cascade:

- `ns-shared/control` exposes
  `ControlMessage::GatewayCertificateBundle` with
  `type = "gateway_certificate_bundle.v1"` and fields `cert_id`,
  `hostnames`, `fullchain_pem`, `private_key_pem`, `issuer`, `not_after`, and
  `generation`.
- `PublicEdgeCertificatePolicy` now carries
  `challenge_preference: PublicEdgeCertificateChallengePreference` with the
  default `TlsAlpn01`; explicit wire tokens are `tls_alpn_01`, `http_01`, and
  `dns_01`.
- `GatewayCertificateStatus` is the non-secret status/ACK shape with `cert_id`,
  `hostnames`, `issuer`, `not_after`, `fingerprint`,
  `gateway_ack_generation`, and `last_error_code`.
- `GatewayReportRequest.certificate_statuses` is the additive gateway-to-NSD
  ACK path. `nsd` leaves `// TODO(PLAN-071 S3)` for status ingest; `nsgw`
  leaves `// TODO(PLAN-071 S4)` for SDS activation and ACK population.
- `nsd` now synthesizes `cert_id = "cert:{host}"` for public edge HTTPS
  references, not `cert:{gateway}:{host}`, preserving per-host/wildcard
  identity fan-out semantics.
- `nsgw` recognizes `gateway_certificate_bundle.v1` on the config stream,
  logs only non-secret metadata, and ignores the bundle until S4 SDS runtime
  lands.

Focused tests run:

- `ns-shared`: `PATH="$HOME/.cargo/bin:$PATH" cargo test -p control gateway_certificate -- --nocapture` -> PASS.
- `ns-shared`: `PATH="$HOME/.cargo/bin:$PATH" cargo test -p control public_edge_certificate_challenge_preference -- --nocapture` -> PASS.
- `ns-shared`: `PATH="$HOME/.cargo/bin:$PATH" cargo test -p control public_edge_policy_snapshots_never_serialize_private_keys -- --nocapture` -> PASS.
- `nsd`: `PATH="$HOME/.cargo/bin:$PATH" cargo test -p nsd-policy https_routes_carry_transport_agnostic_certificate_refs_and_revision -- --nocapture` -> PASS.
- `nsgw`: `PATH="$HOME/.cargo/bin:$PATH" cargo test -p nsgw-control dispatch_ignores_certificate_bundle_until_sds_consumer_lands -- --nocapture` -> PASS.

Real-binary QA run:

- `ns-shared`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/p071-s1-just-qa.log`).
- `nsd`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/p071-s1-just-qa.log`).
- `nsgw`: `PATH="$HOME/.cargo/bin:$PATH" just qa` -> PASS
  (`.local/p071-s1-just-qa.log`). The repository still prints existing
  rustfmt nightly-only config warnings before QA and non-fatal dependency-tree
  diagnostics before `cargo shear`; the command exited 0 and ended with
  `shear/summary` showing no issues.

Adversarial enumeration results:

- Private key material is serialized only by the explicit
  `GatewayCertificateBundle` message. `GatewayHttpConfig` and `GatewayL4Map`
  tests assert policy snapshots never serialize private key material or the
  bundle type tag.
- `cert_id` is per host/wildcard identity. The NSD public-edge snapshot test
  pins `cert:secure.example.test` and asserts the gateway id is absent.
- `generation` is carried on the bundle and logged as non-secret metadata by
  NSGW; monotonic stale/replay enforcement remains S3/S4 runtime work.
- `challenge_preference` defaults to `TlsAlpn01`, so existing behavior does not
  silently switch to DNS-01.

## Annotations

- 2026-06-14 05:19: Proposal recorded before crate code edits. User assignment
  explicitly requested proposal-first followed by implementation in the same
  window.
- 2026-06-14 05:19: Status moved to implementing after the same-window
  implementation authorization in the assignment.
- 2026-06-14 05:40: Marked completed after focused tests, full QA across
  `ns-shared`, `nsd`, and `nsgw`, and adversarial grep confirmed key-free
  snapshots remain private-key free.
