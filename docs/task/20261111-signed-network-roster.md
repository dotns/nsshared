# Signed Network scope in participant rosters

- **status**: in_progress
- **priority**: P1
- **owner**: root
- **createdAt**: 2026-11-11

## Description

Extend the signed roster contract with an authenticated per-identity Network scope for production Account relay discovery. Coordinate NSD publisher and NSGW participant reader changes.

## Evidence

- Schema 3 requires a Network in every entry and verifies it under the roster signature.
- The nsshared-control account suite passes 201 tests; strict Clippy passes.
- Local schema 4 accepts two distinct Network grants for one identity and rejects duplicate pairs or conflicting class/history; the account suite passes 202 tests and strict Clippy passes.
