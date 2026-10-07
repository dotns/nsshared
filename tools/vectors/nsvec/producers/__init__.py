"""Fixture producers. Each module defines CRATE, GROUP, TITLE, SECTIONS and vectors();
register a new producer by adding its module to PRODUCERS."""

from . import (
    dns_txt,
    identities,
    node_records,
    registry_state,
    relay_packets,
    rendezvous_hello,
    rendezvous_mailbox,
    rendezvous_registry,
)

PRODUCERS = [
    identities,
    node_records,
    dns_txt,
    relay_packets,
    rendezvous_hello,
    rendezvous_registry,
    registry_state,
    rendezvous_mailbox,
]
