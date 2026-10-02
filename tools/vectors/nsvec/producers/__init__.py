"""Fixture producers. Each module defines CRATE, GROUP, TITLE, SECTIONS and vectors();
register a new producer by adding its module to PRODUCERS."""

from . import alias4, identities, lan6, node_records

PRODUCERS = [
    identities,
    lan6,
    alias4,
    node_records,
]
