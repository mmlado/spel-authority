# Authority

A SPEL library providing policy-free primitives for a single-holder on-chain authority slot. Extracted out of `admin-authority` and `freeze-authority`, which each embed one and layer their own policy on top (who can transfer, who can renounce, whether renounce is terminal or recoverable).

## Language

**AuthorityCandidate**:
Transfer-time claim describing an intended new holder. `Signer` claims the tx signer; `Pda { program_id, seed }` claims a specific PDA (seed is a single pre-combined 32 bytes, not a seed-part list). Validated against on-chain evidence via `validate()` before the claimed address is trusted.
_Avoid_: passing a bare `AccountId` for transfer (cannot validate key ownership or PDA existence)

**AuthoritySlot**:
Single-holder authority state with at most one Nominee: two private `AccountId` fields, `holder` and the nomination. Exposes `initialize` / `assert` / `transfer_to` / `nominate` / `accept` / `renounce` / `is_renounced` / `pending`. Carries no policy: it never decides who may call an operation, and never decides whether a renounce is recoverable.
_Avoid_: adding policy logic (who can transfer, terminal vs. recoverable renounce) to this crate — that belongs in the consuming library

**Nomination**:
A slot's handover in progress: the account named to become holder, stored until that account accepts. `AccountId::default()` means no nomination. Any change of holder clears it.
_Avoid_: pending admin, candidate (a candidate is the one-step transfer claim)

**Nominee**:
The account a nomination names. It becomes holder only by signing accept itself, a PDA through a chained call from its owning program.
_Avoid_: candidate, successor

**Renounced sentinel**:
`AccountId::default()` stored as `holder`, meaning "no current holder." `assert()` always fails with `Renounced` once set. Whether that's recoverable is entirely a consumer decision, not something `AuthoritySlot` enforces. admin-authority's renounce is terminal: it clears the nomination, `assert()` fails from then on so nothing can call `transfer_to` or nominate again, and its `accept` refuses a renounced slot. freeze-authority's `transfer()` bypasses `slot.assert()` and gates on an admin check instead, and the admin can also nominate a holder who then accepts, so a renounced freeze slot can be repopulated either way.
_See_: admin-authority CONTEXT.md (Renounce), freeze-authority CONTEXT.md (Renounce semantic, ADR-0007)

**AuthorityError**:
Flat error enum spanning `AuthorityCandidate::validate()` failures (`InvalidCandidate`, `UndeployedPda`, `CandidateMismatch`, `UnownedSigner`), `AuthoritySlot::assert()` failures (`Renounced`, `NotHolder`, `MissingSignature`) and `AuthoritySlot::accept()` failures (`NoNomination`, `NotNominee`, `MissingSignature`, `UnownedSigner`). Deliberately kept as one enum rather than split per-function, so each downstream library needs exactly one `impl From<AuthorityError> for {Admin,Freeze}Error` mapping instead of two. Trade-off: `validate()` and `assert()` each only ever produce their own subset of variants, so their `Result` types are wider than strictly necessary.

**Policy-free**:
This crate has no notion of "admin" or "freeze authority" — no instruction handlers, no error mapping to `SpelError`, no config PDA layout beyond the bare slot. Downstream libraries wrap `AuthoritySlot` in their own named config struct (`AdminConfig { slot }`, `FreezeConfig { slot, is_frozen }`) and expose their own semantically-named accessors (`admin()`, `freeze_authority()`).
_Avoid_: adding any admin- or freeze-specific method here — that belongs in the consuming library

## Relationships

- An **AuthoritySlot** holds at most one **holder** `AccountId`, or is renounced, and at most one **Nominee**. Any change of holder clears the Nominee.
- An **AuthorityCandidate** is validated into a plain `AccountId` before it may become a slot's holder — the candidate is the claim, the paired `AccountWithMetadata` is the chain-state evidence.
- Downstream libraries (`admin-authority`, `freeze-authority`) each embed exactly one **AuthoritySlot** inside their own config type and layer transfer/renounce authorization policy on top.

## Example dialogue

> **Dev:** "Why doesn't `AuthoritySlot::renounce()` just make the slot permanently unusable?"
> **Domain expert:** "Because that's a policy decision, and this crate doesn't make policy decisions. admin-authority makes renounce terminal by structuring its API so nothing can call `transfer_to` or `accept` once `assert()` starts failing. freeze-authority instead lets the admin recover a renounced slot, by routing `transfer()` through an admin check rather than `slot.assert()`, and by letting the admin nominate a holder who then accepts. Same primitive, two different lifecycles, both valid."
