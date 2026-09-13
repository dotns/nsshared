[design-review keynet-cli v1]
basis:
- The reviewed proposal covered the CLI interaction contract.
- Authority remains /workspace/nsiod/docs/docs/ns/keynet.md at SHA-256 7c99ffb2e03c0728128da7270754aa065148e263fdc7c3aef233ff9696fa8a9f, verified during this review. Relevant contracts: sections 1.1 (23-35), 7.4-7.6 (328-379), and 13.2-13.6 (524-595).
- This is a proposal review, not adoption or implementation authorization. Phase 1 continues. Only the design owner applies approved text and reports the new digest.

subsection_verdicts:
- 14.1 verdict=change. Distinguish issuer-local approval items from joiner-local pairing operations; bind consent to a network and full identity; ensure --yes and --json cannot bypass daemon admission policy. Exact replacement is the complete subsection 14.1 in recommended_text below.
- 14.2 verdict=change. Separate token, pairing, pending and peer selectors; define foreground attachment independently of daemon lifetime; use explicit credential input sources; add cancellation and deliberate restoration after removal; disambiguate alias kinds and bridge protocols. Exact replacement is the complete subsection 14.2 below.
- 14.3 verdict=change. Explicit removal must override auto admission and recipient-bound tokens. Revalidate at approval, handle already-admitted retries idempotently, deduplicate and bound pending state, and prevent declined requests from immediately recreating themselves. Exact replacement is the complete subsection 14.3 below.
- 14.4 verdict=change. Separate two runtime lifecycle bounds from the CLI observation budget; start preparation only after validated acknowledgment; do not reset deadlines on retries; silence is not proof of rejection or issuer outage. Exact replacement is subsection 14.4 below.
- 14.5 verdict=change. The proposed exit-code mapping conflates a successful asynchronous submission with connection readiness and claims a one-to-one mapping that does not exist. Define query/submission semantics, stable machine states, and local operational errors. Exact replacement is subsection 14.5 below.
- 14.6 verdict=change. Define credential-bearing output exceptions for issuance and QR, keep list/status/error/notification paths secret-free, and prevent token arguments from entering shell history or process argument lists through the documented interface. Exact replacement is subsection 14.6 below.
- 14.7 verdict=accept. Keep the proposed FFI/QR/notification principle; the accepted wording appears as subsection 14.7 below.
- timer_change verdict=change. Moving the 5 s start boundary is reasonable, but also requires the section 1.1 correction below. Runtime acceptance waiting must not be equated with CLI attachment; prepare timeout must preserve already admitted peers. Exact replacements for sections 7.5 and 7.6 appear below.
- remote_rejection_assumption verdict=reject. The promise that an explicit issuer rejection ends a remote pairing immediately cannot be implemented by current section 13: INTRO_ACK has only the positive five-field shape, and DELIVERY_STATUS reports relay delivery rather than issuer authorization. Preserve the current bytes and report silence as unconfirmed acceptance. A future authenticated negative response requires a separate wire-profile decision.

open_points:
1. Command names: default=Use ns keynet as the canonical documented family, with pair, token, pending, peer, allow and network subcommands. No short alias in v1. Distinct object IDs and unambiguous network-scoped peer resolution matter more than shortening the prefix.
2. Headless policy: default=confirm on every installation, independent of TTY presence. Recipient-bound tokens already support unattended admission after validation and explicit-removal checks. Headless operators may deliberately configure recipient-only; attaching or detaching a terminal never changes policy.
3. Acceptance ownership: default=The runtime owns retries until the token's exclusive expiry, local cancellation or a locally observable terminal failure. CLI --wait only bounds observation. Pending issuer approvals expire at min(token.not_after, first_received + 24 h), are deduplicated, and are subject to the runtime queue caps specified below.
4. Roadmap impact: default=Accept the client interaction/timer revision without adding CLI, IPC, queue, policy, scheduling or retry implementation to keynet-proto. Record deviation affects=[1,2,3,4,5,6] limited to the subsequent authoritative design-digest acceptance pins and fixture metadata/test-pin updates. No phase in_scope expands, no dependencies change, and no derivation/CBOR/signature/PSK/MAC/frame expected bytes change. Apply re-pinning only after the owner reports the new digest, through the normal active-phase handoff; do not pause or restart healthy phase 1 work. Reuse unchanged cryptographic evidence. New wire rejection messages, CLI code or altered expiration checks would require a separate substantive deviation.

roadmap_impact:
- deviation affects=[1,2,3,4,5,6]: every phase is pinned to the current full-design SHA-256; editing sections 1.1, 7.5, 7.6 or adding section 14 changes that acceptance reference. The fixture manifest and its test-side design pin also change when re-pinned. This is metadata impact, so "no phase is affected" would be inaccurate.
- Runtime timer/admission/CLI behavior belongs to the client delivery work, outside phases 1-6. The pure crate continues accepting explicit time/state inputs and enforcing sections 13.1-13.6.
- The current design remains authoritative until the design owner's decision, application and new digest. This review does not reopen phase 1 approval or its ongoing inventory repair.

recommended_text:
The following subsection bodies are the exact replacements. Insert the complete section 14 and replace the complete sections 7.5 and 7.6 with the text provided. Also replace the single section 1.1 deadline row as specified.

## 14. CLI Interaction

This section specifies the client runtime, the ns command-line interface and libns. It adds no fields, messages or algorithms to the wire profile in §13. The runtime owns admission state, retries and timers; keynet-proto provides pure primitives with explicit caller inputs.

### 14.1 Principle

The keynet runtime runs in the daemon of the existing ns process model and is controlled through authenticated local IPC. The daemon never waits for terminal input.

An issuer-side decision requiring human approval creates a local pending item containing a pending_id, network_id, the full requesting identity key, the matching token_id, first-received time, expiry and current state. The CLI shows the full network and identity keys as lowercase hexadecimal before approval; identity names and nicknames are supplementary labels. An approval authorizes the exact identity in that network, not whichever peer later resolves from a nickname. The daemon revalidates the item before applying the decision.

A joiner-side pairing has a separate local pairing_id. It identifies an operation on the joiner's runtime and is not the issuer's pending_id. The existing wire protocol does not expose a remote approval-queue identifier.

Interactive confirmation is confined to the CLI, requires terminal input and a terminal destination for the confirmation text, and is disabled by --yes or --json. --yes supplies consent only for the specifically invoked local operation; it never approves unrelated pending items or bypasses issuer policy. --json changes output format and never grants consent. An operation requiring confirmation fails with confirmation_required when confirmation cannot be obtained and --yes is absent.

### 14.2 Command family

The canonical family is ns keynet. Every command supports --json. Mutations support --yes for local confirmation. Network-scoped commands support --network NETWORK, where NETWORK is a full network_id or an unambiguous local display name; a network argument may be omitted only when context selects exactly one network.

| Command | Effect |
| --- | --- |
| ns keynet up [--network NETWORK] [--relay HOST:PORT] [--detach] | Ensure the daemon runtime is running. With no existing network and no network selection, create a personal network. Without --detach, attach a CLI status view; detaching that view does not stop the daemon. |
| ns keynet down | Stop keynet runtime activity while preserving identity and configuration. |
| ns keynet status | Report identity, networks, peers, paths and operation counts. |
| ns keynet token issue [--network NETWORK] [--recipient PEER] [--ttl DURATION] [--name TEXT] [--qr] | Issue one token. --name sets issuer_name; --recipient resolves to the full recipient identity. Report the effective expiry and token_id. |
| ns keynet token list | List token metadata and revocation state without credentials. |
| ns keynet token revoke TOKEN_ID | Stop further allowlist additions through that token; already admitted identities remain admitted. |
| ns keynet pair (--stdin OR --file PATH OR --scan) [--wait SECONDS] | Read exactly one token, import it and create or resume a local pairing operation. Default --wait is 120 seconds; --wait 0 returns after successful local submission. |
| ns keynet pair status PAIRING_ID | Query operation state, peer identity, current path information and the latest observable error. |
| ns keynet pair cancel PAIRING_ID | Stop an unaccepted pairing's INTRO retries. After admission, use peer remove to remove the peer. |
| ns keynet policy set --join auto OR confirm OR recipient-only | Set issuer admission policy for the selected network. |
| ns keynet pending list | List issuer-local pending approvals with full identity/network keys and expiry. |
| ns keynet pending approve PENDING_ID | Revalidate and approve that exact pending request. |
| ns keynet pending deny PENDING_ID | Deny that request and suppress its retries as described in §14.3. |
| ns keynet allow list | List admitted identities and explicit removal records. |
| ns keynet allow remove PEER | Block the identity in the selected network regardless of tokens and remove its active peer configuration. |
| ns keynet allow restore PEER | Explicitly clear a removal record. This does not itself admit the identity; a valid pairing must still satisfy current policy. |
| ns keynet peers; ns keynet peer show PEER | List peers or show one peer's state. |
| ns keynet peer remove PEER | Perform allow remove and retire the peer's aliases, routes and names according to §§4 and 6.4. |
| ns keynet peer name PEER NICKNAME | Set a local nickname using §§7.2 and 13.4. |
| ns keynet peer alias PEER [--v6 ADDR] [--v4 ADDR] | Set local IPv4 aliases: --v6 selects alias6 for N6 services and --v4 selects alias4 for N4 services. Both values are IPv4 addresses, validated under §6.5. |
| ns keynet aliases export PATH; ns keynet aliases import PATH | Export or import the signed local mapping described in §6.5. |
| ns keynet bridge add PORT[/tcp OR /udp] --backend ADDR:PORT; ns keynet bridge list; ns keynet bridge remove PORT[/tcp OR /udp] | Manage §6.7 port bridges. Omitted protocol means TCP. The backend must be this node's self4 address; these commands do not enable forwarding to another host. |
| ns keynet key rotate [--at TIME] | Publish the next binding and schedule a future cutover under §2.3; report the effective cutover time. |
| ns keynet recovery set-root PUBKEY; ns keynet recovery set-root --threshold N PUBKEY...; ns keynet recover --statement PATH | Configure and apply recovery under §2.4. These client operations do not extend the token or relay schemas in §13. |
| ns keynet network create NAME; ns keynet network list; ns keynet network show NETWORK | Manage local network configuration. |

The word OR in command syntax denotes mutually exclusive alternatives, not a literal argument.

TOKEN_ID is the full lowercase hexadecimal SHA-256 of the canonical signed PairingToken CBOR bytes. It is local management metadata and is not a new token field. PAIRING_ID and PENDING_ID are opaque IDs allocated by their respective local runtimes; commands accept only the corresponding object type.

PEER accepts a full identity key, or an identity name/nickname resolving uniquely to a full identity in the selected network. An unresolved identity name, ambiguous nickname or key prefix is an error. No directory lookup is implied.

The three token input sources are mutually exclusive. The input reader is bounded: it accepts one token of at most 1024 bytes, optionally followed by one LF or CRLF transport terminator, and rejects additional data. It removes only that terminator before strict §13.3 token decoding. QR scanning supplies the same token text and validation. Positional token arguments are not part of this interface.

After import, the operation reports the full issuer identity and identity label. A default nickname may be derived from issuer_name under §7.2; absent or unusable issuer_name falls back to the identity label. A nickname never substitutes for the full identity in an approval.

### 14.3 Acceptance policies

Before applying a policy, the issuer verifies the INTRO MAC and recipient binding, checks network and identity consistency, enforces the token's exclusive expiry and recipient restriction, and applies generation/revocation rules. Explicit removal records override every admission policy, including recipient-bound tokens.

For an identity already admitted in that network, a valid matching INTRO retry is handled idempotently. It creates no new approval item. Token revocation prevents new additions but does not erase an existing allowlist entry; expiration does not remove an admitted peer. Configured peers reconnect through WireGuard without repeating token admission.

For a new identity, the matching token must also be unrevoked:

| Policy | Reusable token | Matching recipient-bound token |
| --- | --- | --- |
| auto | Admit immediately. | Admit immediately. |
| confirm, the default on all installations | Create a pending item; admit only after explicit approval. | Admit immediately because issuance already named the recipient. |
| recipient-only | Do not admit and do not create a pending item. | Admit immediately. |

Admission installs the peer before sending INTRO_ACK. Approval rechecks token validity, current binding and generation, removal records, address conflicts and the capacity needed for installation. An expired or invalid item is not revived by approval.

Deduplicate pending requests by network_id, token_id and full requester identity. Retries do not extend first_received or the pending expiry. Expiry is the earlier of token.not_after and first_received plus 24 hours. A denied or expired pending request is not recreated by retries with the same token and identity; retain bounded suppression state until token expiry. A fresh token is required for another request, and explicit identity removal still takes precedence.

Each node has a hard limit of 1000 live issuer pending/suppression entries and 1000 unaccepted outbound pairing operations. Reject new work when a limit is reached; never silently evict pending consent or removal records. Existing configured-peer and token limits in §1.1 also apply.

Denial is visible to local IPC clients. The v1 wire profile has no authenticated issuer-rejection message. Neither silence nor relay DELIVERY_STATUS proves that an issuer approved or denied the request.

### 14.4 Two timers

Pairing has an acceptance lifetime and a preparation deadline. The CLI wait is a separate observation budget and does not own either runtime lifecycle.

Before acceptance, the runtime retries INTRO with bounded back-off and jitter until the token's exclusive expiry, explicit local cancellation or a locally observable terminal failure. It retains a bounded live attempt and nonce association; retransmissions neither create duplicate pending requests nor extend their expiry. An issuer-local denial is not observable by the joiner through the current wire profile.

For a positive --wait value, the CLI waits up to that many seconds for a valid INTRO_ACK. If acknowledgment arrives within that budget, the CLI observes the subsequent preparation result for up to the 5 s preparation deadline. If no acknowledgment arrives, it returns the local pairing_id and reports waiting_for_acceptance with the latest transport evidence. --wait 0 returns immediately after submission. Exiting the CLI does not cancel the operation.

On the joiner, the 5 s preparation deadline begins only after validation of the first matching INTRO_ACK, including its MAC, identity, network, echoed live nonce and current binding. On the issuer, its preparation deadline begins when it installs the admitted peer and sends that acknowledgment. Duplicate acknowledgments and retransmissions do not restart these deadlines.

Preparation succeeds when the WireGuard path is usable and local publication completes. A usable relay path is sufficient; hole punching continues independently and does not postpone success. Preparation timeout reports prepare_timed_out. It does not revoke admission or remove the installed peer; ordinary reconnection may later make that peer usable.

Use monotonic elapsed-time measurement for local wait/preparation budgets. Check absolute token expiry at validation and admission; neither a retry nor a CLI reconnection renews the credential.

### 14.5 Output and exit codes

Human-readable output is the default and may be localized. JSON uses stable English field names and a schema_version of 1. A response identifies operation, status and applicable network_id, identity, token_id, pairing_id or pending_id. Identity and network values use full lowercase hexadecimal. Errors contain a stable code and a human-readable message. Optional transport evidence is reported separately from admission state.

Pairing states include waiting_for_acceptance, preparing, ready, prepare_timed_out, expired, cancelled and failed. The issuer's local approval states include pending, approved, denied and expired. A query may report a historical preparation timeout together with the peer's newer current connectivity state.

| Exit code | Meaning |
| --- | --- |
| 0 | The requested operation or query succeeded. For pair --wait 0, this means submitted, not connected. For an attached pair operation, it means ready. A status query succeeds even when it reports a pending or failed operation. |
| 1 | Local IPC, permission, storage, capacity or other operational failure, with a specific error code. |
| 2 | Invalid arguments, ambiguous selectors, unsupported option combinations, invalid local configuration input or confirmation_required. |
| 3 | Pairing credential invalid, expired or bound to another identity. |
| 4 | The attached acceptance wait ended without confirmed acceptance, or an explicitly observable local denial/cancellation ended the operation. |
| 5 | Preparation timed out, or an operation failed with directly observed transport evidence. Silence alone is not labelled issuer unreachable. |
| 6 | Address-group conflict, including the conflicting full owner identity. |
| 7 | Alias pool exhausted or shadowed, including the local conflict details. |

Errors do not echo credential input. JSON produces one result object on stdout without prompts or progress text; human progress and diagnostics go to stderr. --json never implies --yes. With --json, --qr is a usage error; issuance returns the token string in the explicit credential-bearing result instead.

### 14.6 Secrets on screen

Pairing tokens contain a bearer secret. Token issuance returns the newly issued token once in its result; --qr adds one explicit QR rendering of the same credential in human mode. Issuance reports token_id, recipient restriction and expiry, and states that the token is a bearer credential. Prefer recipient-bound issuance whenever the peer's full identity is known.

Token list, status, pending items, logs, error messages and notifications never contain the token, secret, PSK or private keys. JSON issuance and the explicitly requested token/QR display are credential outputs, not logs. The application never logs token input. Documented stdin, file and scanner inputs avoid placing credentials in command arguments.

The runtime stores credentials only in its protected local credential storage and limits access through the existing local IPC authorization boundary. Mobile notification bodies contain identifiers and state, not credentials. Revocation stops new admissions; removing already admitted identities is a separate operation.

### 14.7 Mobile and libns

The same operations exist as FFI calls; scanning a QR code is pair. No verb requires a terminal; the pending queue is the integration point for app notifications.

### 7.5 Pairing flow

The flow is import → introduce → prepare → publish. Acceptance may wait for a human or an offline issuer; preparation has a separate 5 s deadline. The runtime owns the operation independently of any attached CLI or application view (§14.4).

1. **Import.** The recipient strictly decodes the token and verifies its signature, recipient restriction and exclusive expiry. It verifies the embedded issuer binding, matching identity/network, current validity and generation/revocation rules, then performs the address-group conflict check (§3.4) and local resource checks. Validation failure installs nothing. On success it derives PSK(issuer, self), both issuer addresses and the required aliases, and installs the issuer as a peer with translation entries, routes and a candidate transport path. Names remain unpublished until the peer is usable. The runtime assigns a local pairing_id.

2. **Introduce.** The recipient constructs the INTRO and MAC exactly as specified in §13.2 and §13.5, using a runtime-generated 32-byte nonce associated with the live attempt. It sends to the issuer's reachable direct endpoint or home relay. When relayed, the recipient first authenticates its own slot on that relay so INTRO_ACK has a return destination. The runtime retries with bounded back-off and jitter until token expiry or local cancellation. The CLI observation budget does not stop retries.

3. **Accept.** The issuer verifies the token proof, binding and recipient/network restrictions, enforces explicit removal records and applies the configured policy (§14.3). A reusable token under confirm creates a bounded, expiring local approval item. Approval revalidates the request before admission; a matching recipient-bound token needs no additional human approval but passes the same validity and removal checks. The issuer installs the admitted peer and sends the positive INTRO_ACK defined by §13. The joiner validates its MAC, scope, current binding and echoed live nonce before treating it as acceptance. No negative acknowledgment is defined in v1, so silence cannot distinguish refusal from unreachability.

4. **Prepare.** The joiner starts its 5 s deadline on the first validated matching INTRO_ACK; the issuer starts its corresponding local deadline when it installs the peer and sends the acknowledgment. Retransmissions do not reset either deadline. The WireGuard handshake establishes a usable direct or relayed path. Endpoint candidates are exchanged inside the session and hole punching may improve the path later. Direct-path success is not a prerequisite when the relay path is usable.

5. **Publish.** Once local forwarding/translation state and the WireGuard path are ready, each endpoint marks that peer's names answerable and releases pending queries. Publication is included in the preparation deadline. If preparation times out, report prepare_timed_out while preserving the admitted peer for ordinary reconnection; do not publish unusable names or silently revoke admission.

Expiry or cancellation before acceptance stops further INTRO attempts and retires unaccepted local installation state, preserving alias tombstones and reject-route behavior where applicable. This cleanup never removes an independently admitted peer. After admission, token expiry does not remove the peer.

Configured peers do not repeat token admission. Their reconnection and key updates follow the ordinary WireGuard and KeyBinding rules. The local pairing_id reports the pairing outcome; the issuer's pending_id is a different local object and is not transmitted by the v1 pairing messages.

### 7.6 Failure semantics

| Outcome | What the user or application sees |
| --- | --- |
| Token invalid, expired at import, or bound to another identity | Import fails with the reason; nothing is installed. |
| Address-group collision | Import fails with the conflicting full identity; nothing is installed. |
| Issuer requires confirmation | The issuer sees a local pending_id. The joiner remains waiting_for_acceptance and can query its separate local pairing_id. |
| Issuer denies the request or refuses it by policy | The issuer records the local outcome and sends no INTRO_ACK. The joiner cannot distinguish this from silence through the v1 wire profile. |
| No valid INTRO_ACK before the CLI acceptance wait ends | The CLI returns waiting_for_acceptance and the local pairing_id with any observed transport evidence. The runtime continues within the acceptance lifetime. |
| Issuer silent or unreachable | Silence is reported as unconfirmed acceptance. A concrete local transport error may be reported separately; it does not prove issuer intent or identity-wide outage. |
| Relay unavailable and no working direct path | Report observed relay/path failure. Direct configured peers are unaffected; a pending runtime operation retries until expiry or cancellation. |
| Token expires before acceptance | Stop INTRO retries, mark the operation expired and retire only its unaccepted installation state. Already admitted peers remain admitted. |
| User cancels an unaccepted pairing | Stop that operation's retries and retire its unaccepted state; do not alter unrelated or admitted peers. |
| Preparation or publication exceeds 5 s after admission/validated acknowledgment | Report prepare_timed_out and retain the admitted peer for ordinary reconnection. Duplicate messages do not extend the deadline. |
| Peer's K rotates while the peer is offline or approval is pending | Require a current, valid binding under the generation rules before installation or further progress; stale bindings are not accepted to satisfy a timer. |
| Alias pool exhausted or shadowed | Report the exact local conflicts. An IPv6-only result requires an explicit user choice; --yes does not silently change the requested service-family behavior. |
| Local pending, pairing, peer or token capacity exhausted | Reject the new operation with a specific capacity error; do not evict existing consent, removal records or configured peers silently. |

An issuer-local denial is not a remotely authenticated rejection result. Relay DELIVERY_STATUS describes relay handling only. Successful token validation, acknowledgment, transport delivery and usable-peer publication are distinct events and must not be reported interchangeably.

required_consistency_edit:
Replace the section 1.1 Pairing deadline row with this exact row:
| Preparation deadline | 5 s design parameter | Per endpoint, from local admission and sending INTRO_ACK (issuer) or validating INTRO_ACK (joiner) through a usable WireGuard path and local publication; acceptance waiting is bounded separately (§7.5, §14.4) |

acceptance_note:
A bare go accepts the replacement text, all four defaults, the section 1.1 consistency edit and the metadata-only roadmap deviation. No wire schema or cryptographic vector changes are proposed. The owner alone applies the text and reports the new digest. No repository, proposal or design files were edited for this review.
[/design-review]
