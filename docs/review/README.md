# Review and adoption state

Records of reviews, deliveries and consumer adoption of the contracts specified in
[docs/spec](../spec/README.md). They change as producers and consumers answer and
adopt; the specifications do not depend on them.

| Document | Contents |
| --- | --- |
| [Account review request](account-review-request.md) | Questions to the NSD and node owners, requested M6 changes, dispositions and the delivered revision |
| [Account handoff](account-handoff.md) | The delivered account package, its verification against consumer inputs and the remaining external obligations |
| [Account adoption](account-adoption.md) | Per-contract producer and consumer adoption, review and interoperability status |
| [Account migration](account-migration.md) | Moving consumer imports from `nsshared_proto::account` to `nsshared_control::account`: the item and error map, the rewrite script and the manual items |
| [Account inventory](account-inventory.md) | Predecessor and consumer inventory dispositions: how existing fields and code map to the contracts |
| [Main line handoff](next-takeover-handoff.md) | How the `next` workspace became the main line |
