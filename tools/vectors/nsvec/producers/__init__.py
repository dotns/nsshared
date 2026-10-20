"""Fixture producers. Each module defines CRATE, GROUP, TITLE, SECTIONS and vectors();
register a new producer by adding its module to PRODUCERS."""

from . import (
    account,
    policy_claims,
    control_exchange,
    publication_subscription,
    grant_authority,
    usage,
    realm_publication,
    public_edge,
    dns_txt,
    identities,
    node_records,
    node_control,
    registry_state,
    relay_packets,
    rendezvous_hello,
    rendezvous_mailbox,
    rendezvous_registry,
)

PRODUCERS = [
    account,
    policy_claims,
    control_exchange,
    publication_subscription,
    grant_authority,
    usage,
    realm_publication,
    public_edge,
    identities,
    node_records,
    node_control,
    dns_txt,
    relay_packets,
    rendezvous_hello,
    rendezvous_registry,
    registry_state,
    rendezvous_mailbox,
]
