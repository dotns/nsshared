# Versioned M6 whole-floor reports

The gateway's validated local floor produces plain TCP/UDP declarations,
declaration metadata and Default or explicit-CIDR Exit profiles. Accepted Node custody
supplies publisher/NSD/Network scope. Its current Node runtime supplies the
runtime generation and identifier. The existing authenticated M6
`service.control.v1` carrier transports `report.replace`; this extension adds
neither another operation nor another authority source.

## Content and compatibility

`ReportContent`, `ReportReplace` and declaration encodings are unchanged,
including their existing struct-literal construction. `FloorContent` is additive.
`Message::with_floor` adapts an existing `ReportReplace` message into a
`FloorReportMessage` whose typed complete body is `FloorReportReplace`.
`FloorReportMessage::encode` and `decode` retain the existing schema-1 envelope,
`report.replace` kind and body map (`report_revision`, `report_digest`,
`report_content`). The revision remains positive and the existing Node runtime
fence remains mandatory.

If metadata and Exit profiles are both empty, content and digest are exactly
those of the legacy report. Otherwise `report_content` contains canonical M6
CBOR for this exact map:

```text
{
  "floor_version": 1,
  "report": bstr(canonical legacy ReportContent),
  "metadata": [[reference, capabilities, policy_labels], ...],
  "exit_profiles": [[reference, selection, enabled, capabilities, policy_labels], ...]
}
```

The embedded legacy report includes publisher/NSD/Network scope and plain
service declarations. Every plain declaration retains its existing encoding.
An empty extension map is noncanonical: use the legacy encoding instead.
Unknown fields or floor versions are refused. Legacy `Message::decode` and
`ReportContent::decode` deliberately refuse nonempty extensions; they never
silently discard metadata. Adoption requires a floor-aware producer and consumer.
The Rust API extension is additive and source-compatible. Default requires a
Default-aware producer and every consumer to pin a verified pushed immutable
revision containing the compatible contract. Old explicit-only floor decoders
are not Default-capable; unsupported tuples remain unavailable. See
[Default compatibility and delivery](service/default-exit-floor.md#compatibility-and-immutable-delivery).

`report_digest` is SHA-256 of the ASCII bytes `ns.service.floor.v1`, one zero
byte, and the complete canonical extension bytes. Empty extensions retain the
legacy `ns.service.report.v1` domain. `ReportAccepted` is unchanged and echoes the
accepted complete-content digest.

## Canonical validation

A metadata reference names a declaration key present in the same report. Partial
metadata is allowed; its absence makes no capability claim. Exit binding means
exactly the profile reference within the enclosing publisher/NSD/Network scope.
It is not a separate interface, route, source or authority tuple. The profile
retains the existing `EdgeExitProfile` field shape and local enabled,
capabilities and policy-label semantics without depending on candidate account
features.

Selection is exactly `[0]` for Default or `[1, [canonical_CIDR_text, ...]]` for
Explicit. Both variants are valid for enabled and disabled profiles. Default
has no CIDR payload; unknown tags, extra elements and malformed selections are
refused. Enabled intent supplies no traffic authority.
Explicit selections are nonempty; each CIDR uses canonical `std::net::IpAddr`
text, a slash and a minimal decimal prefix length. Host bits must be zero.
IPv4 and IPv6 are supported. Explicit `/0` prefixes are explicit CIDRs; they do
not select the default-selection variant. Duplicate or intersecting ranges of
the same address family within a profile are refused. Different profiles may
name intersecting ranges because their references are distinct declarations.

Metadata and profiles are strictly increasing by UTF-8 reference bytes.
Capabilities and CIDR strings are strictly increasing by UTF-8 bytes; labels
are `[key, value]` pairs strictly increasing by key bytes. Duplicate references,
capabilities, label keys and prefixes are refused. Encoders require this order
and decoders reject other orders. Legacy declaration sorting is unchanged.
References, capabilities and label keys are nonempty. Text is control-free and
at most 255 UTF-8 bytes; only label values may be empty.

Every extended-floor collection, including declarations, metadata, profiles,
capabilities, labels and CIDRs, is bounded to 256 entries. Encoded extension
content is bounded to 65,536 bytes, additionally subject to the existing M6 CBOR
and enclosing carrier limits. Legacy report rules remain applicable to plain
reports. Validation uses typed `ContractError` values: `FloorLimit`,
`InvalidFloorOrder`, `InvalidFloorBinding`, `InvalidFloorCidr`, plus existing
encoding, field, version and digest errors. `DefaultExitUnsupported` remains a
valid wire error for explicit-only consumers. Metadata and profile collection lengths are checked before constructing their typed collections; embedded declarations retain the existing bounded M6 decoder.

## Consumer comparisons

NSD authenticates the signer and compares publisher, NSD/Network scope, accepted
Exit profile, contribution and Node runtime fence with independently
persisted current custody. It decodes the complete floor through
`FloorReportMessage::decode` (or the account-aware
`FloorReportMessage::from_envelope`), validates its references and canonical bytes, then
applies existing revision/digest replacement, replay and idempotency rules to
the whole content. The shared codec cannot establish current custody or detect
a stale generation without that independently persisted state.

The gateway retains the complete pending request. `validate_accepted` compares
scope, subject, runtime generation/id, authority epoch, request id, session,
revision and the entire content digest. Under the account carrier,
`PendingRequest::from_envelope` retains the complete floor and
`validate_unary_reply` also checks signatures, pins, recipient and outer nonce.
`PendingRequest::floor_report` supplies complete retry bytes; `message()` and
`FloorReportMessage::context()` expose only the legacy declaration projection
and envelope context. Never re-encode that projection as a complete-floor retry.
A digest of only the embedded declarations cannot acknowledge a nonempty floor.
Reporting a floor alone grants no traffic authority. Accepted Exit publications
and grants remain separate existing consumer responsibilities.

Independent Python fixtures in `service/floor.json` cover content bytes, digest,
M6 envelopes, signed pending-request correlation and invalid inputs. Existing
M6 vectors remain unchanged.
