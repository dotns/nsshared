# Specifications

Contract specifications versioned with the code of this repository. The NS
protocol v2 wire layer and the rendezvous service are specified externally
(`ns/quick-v2.md` and `ns/rendezvous.md` of the docs site, at the pin named by each
vector header and by the [spec coverage tables](../spec-coverage/quick-v2.md)).

| Specification | Contract | Code |
| --- | --- | --- |
| [Canonical RealmId](realm-id.md) | Membership realm identifiers in text and binary positions | `nsshared_identity::realm` |
| [Node-control](node-control.md) | Node-control v2 messages, ACK hashes and endpoint selection | `nsshared_control::node_control` |
| [Account profile](account/profile.md) | Encoding rules, placement, M6 reuse, scope text and the family registry shared by every account contract | `nsshared_control::account` |
| [Node](account/node.md) | Enrollment, identity lifecycle, normalized Node L3 form and authority, local Node naming | `nsshared_control::account::node` |
| [Control](account/control.md) | Bootstrap discovery, signed confidential carriers, control exchanges and reports, machine tokens, signed URL requests, route commands, Node L3 status, the M6 carrier | `nsshared_control::account::control` |
| [Publication](account/publication.md) | Signed publication events and snapshots, source bindings and source-bound publications, subscriptions and snapshot polls | `nsshared_control::account::publication` |
| [Realm](account/realm.md) | Family 2: served realms and peers, policy subjects, subject rules, admin and JWT claims | `nsshared_control::account::realm` |
| [Grants](account/grants.md) | Families 3, 5 and 6: service grants, payers and payer bindings, resource authority | `nsshared_control::account::grants` |
| [Subnet](account/subnet.md) | Family 4: Subnet selection, Exit grants and client route views, provider reports and mappings | `nsshared_control::account::subnet` |
| [Exit readiness](account/exit-readiness.md) | Selection-scoped GatewayReport challenge/observation and separate consumer Snapshot | `nsshared_control::account::subnet` |
| [Edge](account/edge.md) | Family 7: public-edge routes, authentication policy, material, confidential configuration, service declarations | `nsshared_control::account::edge` |
| [Relay](account/relay.md) | Family 8: admission and participant rosters, participant sessions, directory bindings | `nsshared_control::account::relay` |
| [Usage](account/usage.md) | Families 9 and 10: service and relay usage, reports and answers, profile publications | `nsshared_control::account::usage` |

The M6 private service control contract is described in
[`crates/nsshared-service-control/README.md`](../../crates/nsshared-service-control/README.md)
and implemented by `nsshared_control::service`.

The account specifications describe the public `nsshared_control::account`
contract, available unconditionally and covered by semver from `v0.8.0`. The
former `unstable-account` feature has been removed.

Review and adoption state of these contracts (questions to producers, consumer
adoption, delivered revisions) is kept apart in [docs/review](../review/README.md).
