# Public-edge content, material and service operations

Membership realm identities follow the [canonical RealmId contract](canonical-realm-identity.md).
Affected text positions retain text but require the exact uppercase 26-character
spelling and decode to RealmId; binary positions retain their exact 16 bytes.
This incompatible candidate delta refuses arbitrary realm labels without fallback.
NSD/ns producer and consumer updates, including the other active consumer delivery,
remain outstanding. Encoding equality is not authentication. Discovery realm hints,
external provider subject namespaces and opaque scopes retain their meanings.
Signed usage bytes and the historical payer pair remain unchanged.


Candidate version 1. All new arrays use shortest-form definite CBOR, strict UTF-8,
no trailing bytes, and at most 1,048,576 encoded bytes. Collections have at most
256 items per encoded collection. Caller-supplied snapshot and material-ACK
collections may contain up to 65,536 entries to cover all realm/route references.
References and general tokens have 1..256 UTF-8 bytes without controls
or whitespace. Sets are strictly ordered by their documented key, never sorted
or deduplicated by the decoder. Unknown discriminants refuse.

## Content and authority

`PublicEdge` = `[1, 7, served_realm, scope, realms]`.
Each `EdgeRealm` = `[realm_16, auth_bytes, routes]`, ordered by binary realm.
`EdgeRoute` = `[id, name_or_null, aliases, domains, service_ref_bytes, backend_I_or_null,
protocol, public_port, virtual_port, policy_bytes, headers_bytes, dependencies, options]`.
Routes are ordered by id. Protocol is 0 HTTP, 6 TCP or 17 UDP. Ports are 1..65535.
HTTP requires a text name. TCP/UDP require exactly CBOR null and empty aliases
and domains; raw text names and HTTP null names refuse. No empty-string
substitute or inferred hostname is permitted. HTTP names, aliases and domains
are canonical lowercase ASCII DNS names, at most 253
bytes, dot-separated labels of 1..63 letters/digits/hyphens with alphanumeric
ends. These public hostnames are not M6 service labels. Aliases/domains are each
strictly ordered. Names and aliases cannot collide within a realm, including
within one route. Discovery name/alias/domain ownership stays realm-local for HTTP. Raw routes
claim no hostname ownership; their identity is the realm-qualified route id.
Physical listener ownership is gateway-wide across every served realm in the
complete publication: raw TCP and UDP use protocol/port, while HTTP uses every
name, alias and domain paired with its listener port. Different HTTP hosts may
share a port, and the same HTTP host may appear in different realms on distinct
ports. Raw TCP cannot share an HTTP port, in either contribution order. TCP and
UDP may use the same port number because their transports are distinct.
Backend virtual ports are unique across the complete publication by full Node
identity, underlying transport and virtual port; HTTP and TCP share the TCP
transport. A null backend owns no Node endpoint. These checks do not globalize
realm-qualified material references, and never infer identity from an address.
A domain may equal its own route name or alias; cross-route hostname collisions
inside a realm refuse.

`options` = `[transport, upstream_authority_or_null, upstream_tls_or_null,
policy_references, request_body_limit_or_null, response_body_limit_or_null,
source_ip_or_null, audit_metadata]`. Transport 0 WG, 1 WSS, 2 prefer WG,
3 prefer WSS. Upstream TLS is `[sni, accept_untrusted]` and always means
reencryption; false requires trusted validation. SNI and upstream authority
are canonical hostnames. The eleven optional token references, in order, are
middleware chain, WAF, external authorization, rate limit, connection limit,
slow client, session limit, request rewrite, response headers, forwarded subject
and audit. No arbitrary named extension is permitted. Source IP policy is
`[allow_cidrs, deny_cidrs, fail_closed]`; CIDRs use canonical network addresses
and decimal prefix lengths, ordered uniquely by their UTF-8 strings. Audit
metadata is an ordered unique sequence of bounded token key/value pairs.
Body limits are positive u64 when supplied. Consumers resolve policy references
through existing configuration; the codec never applies them.

The service reference is the unchanged canonical M6 ServiceRef value in a byte
string. A backend is a full validated Node identity. Null explicitly means no
connector: retain discovery metadata, withhold forwarding, and never fall back
to a guessed address, display name or gateway-local backend. A consumer joins
non-null backends against the authenticated M6 snapshot Resource by ServiceRef,
publisher identity, published virtual port and supported transport. The snapshot
must belong to the signed recipient. Contributions spanning several M6 networks
join against one authenticated snapshot per exact NSD/Network scope; duplicate
snapshot scopes refuse, and no scope is inferred from an unrelated resource.
The validated Resource.service_label is the sole source of service DNS labels; the codec carries no standalone label.

`policy_bytes` reuse SubjectPolicy exactly, with realm equal to the contribution.
`headers_bytes` reuse SignedSubjectHeaderPolicy exactly. Each dependency is an
unchanged material reference tuple below; it must exist in that realm's complete
material set at the exact generation. Enabled signed headers require an auth
material reference matching keyset_ref. No credential, token or ACL evaluation
is performed here.

Only family 7 kind `public-edge`, complete Data on the existing signed stream,
may carry this content. Inner served_realm/scope equal the signed key exactly.
Authenticate with the existing publication decision before interpreting payload.
Commit version, expiry and content atomically only after validation and joins.
All realm contributions replace the previous set in that exact key; omitted
routes/realms/materials are removed. Empty realms withdraw all contributions;
the existing complete empty carrier also withdraws. Malformed/noncanonical
payloads never advance accepted versions or renew previous expiry. Missing
publications retain state until original expiry. Different signed keys never
merge into wildcard authority.

## Material and embedded auth

`EdgeMaterialRef` = `[kind, reference, generation]`: kind 0 auth, 1 certificate,
2 client CA; generation is positive u64. References are ordered by kind/reference.
`EdgeAuth` = `[1, realm_16, materials, bindings, jwt_bindings, authorities]`.
Bindings are exact SubjectBinding byte strings in strict canonical-byte order;
JWT bindings reuse JwtSubjectBinding in the same order. All subjects/bindings
must belong to the realm. Each JWT authority reference resolves locally.
`EdgeJwtAuthority` = `[reference, issuer, audiences, key_material]`, ordered by
reference. Issuer is an explicit HTTPS URL with a canonical DNS host or bracketed IPv6,
optional nonzero canonical decimal port, and no userinfo, backslash, fragment or query;
audiences are nonempty ordered token strings. key_material is an auth reference
present at the exact generation in materials. JWT verification stays external.
SignedUrlScope remains the existing request-borrowed type; key selection uses
auth material references, never serialized HMAC/private key bytes.

`EdgeMaterialAck` = `[1, request_id_16, served_realm, scope, realm_16, material,
status]`; status 0 installed, 1 rejected. The gateway reports installed only after actual installation of the exact
material reference and generation. It copies the exact confidential auth request id
for auth configuration, whose private request/response is specified separately;
for certificate/client-CA reports it mints a unique report id. Receivers compare the
request id, all realm/scope fields and full material kind/reference/generation
against the exact retained context. A receipt cannot cause installation. Routes must remain withheld until every referenced dependency is
installed and acknowledged. A rejected ACK or a missing/different generation is
never ready. Retaining only a numeric generation without its kind/reference and
realm cannot establish readiness. Fetching certificates, CA bytes, verifier
hashes, HMAC secrets and cookie secrets stays on the existing confidential
material transport; this public content contains references only. The separate
[confidential authentication contract](confidential-auth-candidate.md) supplies
auth catalog values inside authenticated confidential control envelopes.

## Declaration, report, response and ACK

Kinds 0 declaration and 2 listener retain the exact existing nine-field
EdgeServiceRequest/Response tuples and unchanged M6 bytes. The complete kind 1
report now includes local floor metadata, non-authoritative Exit profiles and
per-reference outcomes as specified in [control report exchanges](control-report-candidate.md).
That explicit candidate delta replaces the earlier whole-report boolean for kind 1;
all other public-edge, material, declaration and listener bytes remain unchanged.
The complete floor digest covers M6 report bytes, all declaration metadata and every
Exit profile. Unknown or missing submitted-reference outcomes are typed refusals.
Scope, publisher, request id, revision, body kind and the entire floor digest must
match the exact pending request. Rejection carries a reason and creates no readiness.

## Inventory disposition

| Existing surface | Candidate field, reused definition or disposition |
|---|---|
| routing RouteEntry/RoutingConfig, dns DnsRecord/DnsConfig | EdgeRealm.routes; id/name/aliases/domains, ServiceRef, backend, virtual_port, protocol; service DNS labels resolved from snapshot Resource |
| ServiceBackendKind/PublicEdgeBackendKind::NsnBacked | Full Node backend identity; address-derived identity retired because addresses cannot establish publisher authority |
| GatewayEgress/GatewayExit backend variants, capture routes | Existing grant/Subnet families, not public-edge backend authority; no public exposure inferred |
| GatewayHttpConfig/GatewayHttpRoute, GatewayL4Map/GatewayL4Route | EdgeRealm/routes; HTTP/TCP/UDP/public_port; per-realm complete replacement |
| PublicEdgeRouteIdentity/AclRef/PolicyRevision | Route id, ServiceRef, SubjectPolicy, signed publication version; gateway/internal listener ids stay consumer-local; rollback metadata cannot override monotonic signed version |
| PublicEdgeTransportPolicy and upstream TLS policy | EdgeRouteOptions.transport/upstream_authority/upstream_tls, with explicit TLS trust choice; no implicit fallback |
| HttpExternalIdentityImport/ExternalIdentityProviderRef/Kind, GatewayAuthProvider/Kind/OrganizationMode | [AuthConfiguration](confidential-auth-candidate.md): complete provider/import, cookie, redirect, template and organization values on confidential authenticated control transport; NSD confirmation outstanding |
| HttpMiddlewarePolicy/SourceIpAdmissionPolicy, EdgeLimitPolicy/HttpTransformPolicy/EdgeAuditPolicy/L4Policy | EdgeRouteOptions explicit policy references, body bounds, source_ip and audit_metadata; referenced policy implementations remain consumer-owned |
| SignedSubjectHeaderPolicy, AclPolicy rules/groups | Exact reused SignedSubjectHeaderPolicy and SubjectPolicy bytes |
| GatewayAuthConsumer, credential-to-consumer joins | Exact SubjectBinding; display names are presentation only |
| GatewayAuthJwtConsumerBinding/JwtAuthority/JwtKeySource/JwtIssuer | JwtSubjectBinding plus EdgeJwtAuthority issuer/audiences/auth key reference; actual key acquisition and trust qualification remain external |
| GatewayAuthConfig/Generation and Credentials (API key, Basic, signed URL, mTLS, webhook), SecretSet/SecretVersion | AuthConfigRequest/Response and AuthConfiguration supply exact realm/reference/generation and actual secret/verifier values confidentially; existing bindings reused; unsupported webhook reservation retired explicitly |
| rules::signed_url and its constants/helpers | Existing SignedUrlScope canonical_request/signing_input, no second canonicalization |
| CertificateRef/Source/Policy/ChallengePreference, CertificateBundle | Certificate material reference/generation; private key bytes are excluded; fetch/ACME/source configuration remains owned by the material consumer, not identity authority |
| ClientCaBundle/ClientCaDependency, AuthDependency/CertificateDependency | Client-CA/auth/certificate references and exact generation joins plus correlated EdgeMaterialAck |
| GatewayServiceDeclaration/ServicesReport/Request/Response/Ack | EdgeServiceRequest/Response; unchanged M6 objects, complete floor metadata and exact per-kind reference outcomes with explicit reasons |
| GatewayExitProfileDeclaration | EdgeServiceRequest kind 1 exit_profiles reuse SubnetSelection/Prefix semantics as declarations, never Subnet route authority |
| service_fqdn and standalone service-label inputs | Resolve Resource.service_label via M6 ServiceRef; standalone inputs excluded and open pending M01/M02, owned by the M6 contract owner through owner-mediated review |

Confidential configuration is specified separately and claims no predecessor
wire equivalence. Consumer installation and route readiness remain external.
Producer confirmation and producer-owned
vectors remain outstanding with NSD. Python fixtures are labelled candidate
sources, independent of the Rust codecs.


## Anonymous authorization

`EdgeRoute.policy` carries the explicit SubjectSelector contract from the
[account profile](l8-account-payload-profile.md#anonymous-selector-consumption).
Anonymous is the byte string containing canonical CBOR `[1, 3]` (`82 01 03`),
never a PolicySubject or a null wildcard. Older consumers reject it.

An explicitly anonymous HTTP route or TCP/UDP listener needs no Auth dependency.
Absence of Auth alone authorizes nothing: an exact matching Anonymous rule must
admit the actual backend destination, port and protocol. A trusted ingress
adapter classifies the observed unauthenticated visitor without fabricating a
subject. Missing or untrusted input denies; verified principals never match
Anonymous. Null and explicit identity/group selectors admit verified principals
only. Source-IP checks, served realm/source lifetime, connector availability,
independently bound activation, certificate/client-CA dependencies, withdrawal
and transport restrictions still apply.

Routes with an Auth dependency retain its exact configuration/generation and
[confidential authentication](confidential-auth-candidate.md) anonymous_bypass
and fail_closed behavior. An Anonymous selector never skips a required dependency
or converts failed required authentication into bypass. Ordered methods,
default versus ACL-selected OIDC and redirect host remain unchanged. The codec
only validates and carries these facts; matching and forwarding stay external.

## Protocol-specific name vectors

The independent `public_edge_protocol_names` consumer sequence covers HTTP host
bytes, unnamed TCP/UDP on one numeric port with distinct backend endpoints,
protocol/name mismatches, nonempty raw name collections and listener conflicts.
Existing HTTP-only fixture bytes are unchanged. Existing raw-route fixture names
are deliberately regenerated from text to null, including anonymous-policy
fixtures. Version 1 and the thirteen-position tuple remain unchanged; neither
old named raw routes nor a compatibility fallback are accepted. Upstream
authority, TLS SNI and confidential material hostnames retain their own rules.
NSD raw exposure protocol/port supplies null and empty collections; its HTTP
public_host supplies the HTTP name. Real producer adoption remains outstanding;
fixture authority does not establish producer agreement.
