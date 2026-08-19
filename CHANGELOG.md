# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-19

First release.

### Added

- `AuthoritySlot`, a single-holder authority slot: initialize with a
  validated holder, assert a signer against the current holder, transfer
  with candidate validation, and renounce to a terminal sentinel that can
  never validate again.
- `AuthorityCandidate`, a transfer-time claim (signer or PDA of another
  program) validated against the account offered as evidence. A default
  id, an undeployed PDA, or a mismatched address is refused at the
  transition, not discovered at the next assert.
- Windowed access: `read_at` and `write_at` operate on a byte window at a
  caller-declared offset with checked bounds and splice-only writes, so a
  slot can live inside a larger account without touching its neighbors.
  Out of bounds is its own error and is never conflated with an
  uninitialized slot.
- Dual MIT/Apache-2.0 license and CI.

[Unreleased]: https://github.com/mmlado/spel-authority/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mmlado/spel-authority/releases/tag/v0.1.0
