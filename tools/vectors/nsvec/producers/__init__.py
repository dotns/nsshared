"""Fixture producers. Each module defines CRATE, GROUP, TITLE, SECTIONS and vectors();
register a new producer by adding its module to PRODUCERS."""

from . import (
    identities,
    node_records,
    relay_packets,
    rendezvous_hello,
    rendezvous_mailbox,
    rendezvous_registry,
)

PRODUCERS = [
    identities,
    node_records,
    relay_packets,
    rendezvous_hello,
    rendezvous_registry,
    rendezvous_mailbox,
]
