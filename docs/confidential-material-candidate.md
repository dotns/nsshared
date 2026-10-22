# Confidential certificate and client-CA acquisition candidate

Status: pure candidate contract. NSD producer implementation, dispatch adoption,
confirmation and producer-owned vectors remain outstanding. Independent Python
fixtures are candidate authority, not NSD output or an interoperability agreement.

## Carrier and request

`control_exchange::EDGE_MATERIAL_GET` defines `edge.material.get` once. Use the
existing authenticated confidential BootstrapEnvelope request/response carrier
and signed control endpoint. No certificate, private key or CA bytes travel in a
public-edge publication. `edge.auth.config.get` remains auth-only and unchanged.

The canonical request is `[1, request_id, recipient, served_realm, scope, realm,
material]`. Encodings match AuthConfigRequest: request_id is exactly 16 bytes;
recipient is a validated 32-byte Ed25519 IdentityKey; served_realm is canonical
26-character RealmId text; scope is 1..256 UTF-8 bytes without control characters;
realm is 16 binary RealmId bytes; material is `[kind, reference, generation]`.
Reference is 1..256 UTF-8 bytes without control characters, generation is positive
u64, kind is Certificate (1) or ClientCa (2). Auth (0) and unknown kinds fail.
The acquisition request id is minted independently of the envelope replay nonce.

## Success response

The exact tuple is `[1, request_bytes, hostnames, not_after_unix_seconds, values]`.
`request_bytes` is a byte string containing the complete canonical request above.
It is not a partial correlation or a digest. The consumer compares it byte for
byte with the complete pending canonical request.

`hostnames` contains 0..256 strictly increasing unique ASCII hostnames, each
1..253 bytes. Labels have 1..63 lowercase alphanumeric/hyphen bytes, start and
end alphanumeric, and are separated by dots. Uppercase, wildcards, trailing dots,
empty labels, duplicates and reordered names fail under existing PublicEdge rules.
The list limits material use and never grants route authority.

The deadline is an exclusive unsigned u64 Unix-seconds value, never milliseconds.
The consumer supplies its own clock and rejects expired material; the codec reads
no clock and permits all unsigned values, including an already expired zero.

Values are exactly `[1, fullchain_pem, private_key_pem]` for Certificate or
`[2, ca_pem, trust_domain]` for ClientCa, matching the request kind. PEM fields are
nonblank UTF-8 text, preserving newlines and optional CA CRLs verbatim. No PEM or
X.509 parsing occurs here. The trust domain is 1..256 UTF-8 bytes without control
characters; semantic comparison and SPIFFE validation remain with the consumer.
No null, missing, empty or whitespace-only PEM represents successful acquisition.
Unavailable material uses the existing authenticated operation failure instead.

Every request/response and nested request is bounded by the existing 1 MiB account
limit. PEM text is individually bounded by that limit and the entire encoded
response must also fit it. The existing confidential carrier limits still apply
to the final envelope, including its overhead. All tuples have exact arity;
shortest definite CBOR only, no unknown fields, tags, indefinite lengths, negative
integers, invalid UTF-8 or trailing data. Validation never sorts or repairs input.

## Public API

`nsshared_proto::account::confidential_material` exposes:

- `EdgeMaterialRequest { request_id: [u8; 16], recipient: IdentityKey,
  served_realm: RealmId, scope: String, realm: RealmId, material: EdgeMaterialRef }`.
- `EdgeMaterialValues::Certificate { fullchain_pem: String, private_key_pem: String }`
  and `ClientCa { ca_pem: String, trust_domain: String }`, with redacted Debug.
- `EdgeMaterialResponse { request: EdgeMaterialRequest, hostnames: Vec<String>,
  not_after_unix_seconds: u64, values: EdgeMaterialValues }`.
- Request and response `canonical(&self) -> Result<Vec<u8>, EdgeMaterialError>`
  and `decode(bytes: &[u8]) -> Result<Self, EdgeMaterialError>`.
- Response `validate_for(&self, pending: &EdgeMaterialRequest)
  -> Result<(), EdgeMaterialError>` validates both contracts and the complete
  canonical echo. Typed refusals are Contract(AccountError), Kind, Realm,
  Generation and Echo. Wrong echoed realm/generation have their own refusals;
  every other valid but different request field returns Echo. Kind covers
  forbidden request kinds and request/value disagreement.

## Consumer obligations and status

NSD checks the authenticated requester and requested recipient, scope, realm,
reference and generation against authorized material custody before release.
The gateway verifies signer, explicit recipient, operation and envelope response
correlation against accepted control custody before consuming these payloads.
It rechecks the full dependency against the current authenticated PublicEdge view;
a delayed acquisition cannot restore a replaced or withdrawn dependency.

The gateway joins permitted hosts with current realm-qualified routes and requires
coverage for each activating host. For ClientCa it compares trust_domain with the
current validated auth configuration for that exact CA reference. Certificate/key
matching, certificate host coverage, CA/CRL and X.509 parsing, supplied-clock
validity, limiting the deadline to certificate validity and actual installation
remain with the gateway installer. Acquisition success is not installed readiness.

EdgeMaterialAck bytes do not change. For Certificate and ClientCa its request_id
is a separately gateway-minted installation-status id, not the acquisition id.
The gateway retains the local association with acquisition and full material
scope/generation, emits installed status only after installation, and transports
it with existing exact report/receipt correlation. Auth ACK correlation continues
to use its exact pending auth configuration request id.

## Independent acceptance

`confidential_edge_material_generation` consumes independently generated
`confidential-material.vec` certificate/key and client-CA bytes at generation 7,
including complete request echoes. It rejects wrong realm/generation, changed
echo, other-kind values, Auth/unknown kinds, missing/unknown fields, noncanonical
and oversized encodings and empty values. Existing auth and installation ACK
fixtures remain unchanged. There is no acquisition runtime or I/O in the contract.
