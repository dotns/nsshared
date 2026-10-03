"""Fixture producers. Each module defines CRATE, GROUP, TITLE, SECTIONS and vectors();
register a new producer by adding its module to PRODUCERS."""

from . import (
    alias4,
    control_messages,
    identities,
    lan6,
    node_records,
    region_frames,
    relay_packets,
    rendezvous_hello,
    rendezvous_mailbox,
    rendezvous_pairing,
    rendezvous_region,
    rendezvous_registry,
)

PRODUCERS = [
    identities,
    lan6,
    alias4,
    node_records,
    relay_packets,
    control_messages,
    region_frames,
    rendezvous_hello,
    rendezvous_registry,
    rendezvous_pairing,
    rendezvous_mailbox,
    rendezvous_region,
]
