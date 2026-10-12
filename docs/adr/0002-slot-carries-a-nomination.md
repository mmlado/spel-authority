# The slot carries a nomination, and every change of holder clears it

**Status:** accepted.

A two-step handover (the holder nominates, the nominee accepts in a later transaction) needs the nominee stored between the two transactions. We store it in `AuthoritySlot` itself: the slot becomes `{ holder, pending }`, two `AccountId`s, and `ENCODED_LEN` goes from 32 to 64. `AccountId::default()` in `pending` means "no nomination", the same sentinel convention as the renounced `holder`, so the encoding stays fixed-size as embedded windows require. admin-authority and freeze-authority both build their handover on it.

The primitives follow the existing split between mechanism and policy:

- `nominate(next)` writes `pending` with no check on who calls, like `transfer_to`. Who may nominate is the consuming library's policy. Nominating `AccountId::default()` cancels.
- `accept(signer)` installs `pending` as `holder` when the signer signed, is the nominee, and is owned by some program (the same rule as the `Signer` candidate check). Refusals are `NoNomination`, `NotNominee`, `MissingSignature` and `UnownedSigner`. A PDA nominee accepts the same way: LEZ marks it authorized when its owning program passes its seeds in a chained call.
- `accept` does not look at `is_renounced`. Whether a vacant slot can be filled again stays the consumer's decision.
- `transfer_to`, `accept` and `renounce` all clear `pending`. Otherwise a nominee left over from before a co-signed transfer could accept afterwards and take the slot from the new holder.

## Considered Options

**1. Grow the slot (chosen).** One mechanism and one encoding for every library that embeds a slot. Every embedded layout shifts: fields after the slot move by 32 bytes. Consumers pin exact versions, and the CHANGELOG lists the new offsets.

**2. A separate nomination PDA.** Keeps the 32-byte slot and every embedded layout. Rejected: nominate, accept, renounce and transfer would each carry a second account, embedded consumers would need a second account beside their own, and the clear-on-holder-change rule would span two accounts.

**3. `pending: Option<AccountId>`.** Rejected: borsh encodes it in 1 or 33 bytes, so the window would no longer be fixed.

**4. Each config type owns its own `pending` bytes next to the slot.** Rejected: the same mechanism written twice, which ADR-0001 extracted this crate to avoid.

## Consequences

- Supersedes "the slot primitive stays 32-byte and slot-only" in admin-authority's `CONTEXT.md` (embedded mode).
- Breaking for every consumer.
- Admin's terminal renounce still holds through policy: renounce clears `pending`, and only the admin may nominate, so nothing can accept afterwards.
