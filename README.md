# spel-authority

[![CI](https://github.com/mmlado/spel-authority/actions/workflows/ci.yml/badge.svg)](https://github.com/mmlado/spel-authority/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/mmlado/spel-authority?label=version)](https://github.com/mmlado/spel-authority/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-93450a?logo=rust)](Cargo.toml)

Policy-free primitives for single-holder on-chain authority slots in SPEL libraries: `AuthorityCandidate` (validates a transfer-time claim against on-chain evidence) and `AuthoritySlot` (initialize / assert / transfer / renounce state for one holder).

This crate has no notion of "admin" or "freeze authority" — no instruction handlers, no policy on who can transfer or renounce. Downstream libraries (`admin-authority`, `freeze-authority`) compose these primitives into their own config types and layer their own policy on top.

See [CONTEXT.md](./CONTEXT.md) for the full glossary and [docs/adr](./docs/adr) for design decisions.

## Example

A downstream library wraps `AuthoritySlot` in its own named config type and layers its own transfer policy on top. The crate is named `spel-authority`, the `package` rename below is what makes `use authority::` resolve:

```toml
[dependencies]
authority = { git = "https://github.com/mmlado/spel-authority.git", tag = "v0.1.0", package = "spel-authority" }
```

```rust
use authority::{AuthorityCandidate, AuthoritySlot, AuthorityError};

struct AdminConfig {
    slot: AuthoritySlot,
}

impl AdminConfig {
    fn initialize(admin: AccountId) -> Result<Self, AuthorityError> {
        Ok(Self { slot: AuthoritySlot::initialize(admin)? })
    }

    fn transfer(
        &mut self,
        current: &AccountWithMetadata,
        candidate: AuthorityCandidate,
        new_account: &AccountWithMetadata,
    ) -> Result<(), AuthorityError> {
        self.slot.assert(current)?;
        let next = candidate.validate(new_account)?;
        self.slot.transfer_to(next)?;
        Ok(())
    }
}
```

`AuthoritySlot` itself never decides who may call `transfer` — that check (`self.slot.assert(current)`) is the consuming library's job.

## Versioning and stability

Semantic versioning covers two surfaces: the crate's public Rust API, and `AuthoritySlot`'s 32-byte borsh encoding, which is an on-chain wire format that downstream config types embed. While the version is 0.x, a minor bump may change either, and each such change is called out in the changelog.

The `spel-framework` dependency pins a fork revision for now. Version 1.0.0 lands when the extension mechanism reaches an upstream release ([logos-co/spel#257](https://github.com/logos-co/spel/pull/257)) and the pin moves to it.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE2) at the consumer's option.
