# spel-authority

Policy-free primitives for single-holder on-chain authority slots in SPEL libraries: `AuthorityCandidate` (validates a transfer-time claim against on-chain evidence) and `AuthoritySlot` (initialize / assert / transfer / renounce state for one holder).

This crate has no notion of "admin" or "freeze authority" — no instruction handlers, no policy on who can transfer or renounce. Downstream libraries (`admin-authority`, `freeze-authority`) compose these primitives into their own config types and layer their own policy on top.

See [CONTEXT.md](./CONTEXT.md) for the full glossary and [docs/adr](./docs/adr) for design decisions.

## Example

A downstream library wraps `AuthoritySlot` in its own named config type and layers its own transfer policy on top. The crate is named `spel-authority`, the `package` rename below is what makes `use authority::` resolve:

```toml
[dependencies]
authority = { git = "https://github.com/mmlado/spel-authority.git", branch = "m3", package = "spel-authority" }
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

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE2) at the consumer's option.
