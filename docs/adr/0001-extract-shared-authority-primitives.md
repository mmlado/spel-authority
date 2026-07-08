# Extract shared authority primitives instead of per-library duplication

**Status:** accepted. Supersedes freeze-authority's [ADR-0005](https://github.com/mmlado/spel-freeze-authority/blob/main/docs/adr/0005-local-freeze-candidate.md) (`FreezeCandidate` defined locally, not imported).

admin-authority's `AdminCandidate`/admin-slot logic and freeze-authority's `FreezeCandidate`/freeze-slot logic were ~30 lines of duplicated validation each, chosen deliberately in freeze-authority ADR-0005 over a shared type: the DRY benefit was judged too small against cross-library coordination cost, with the explicit note that "a shared `authority-candidate` crate can extract both [later]. Cheap to do later; expensive to do now."

We extract now, into a new `spel-authority` (crate name `spel-authority`) library providing `AuthorityCandidate` and `AuthoritySlot`. Both admin-authority and freeze-authority depend on it and type-alias their public names onto it (`pub type AdminCandidate = authority::AuthorityCandidate`, `pub type FreezeCandidate = authority::AuthorityCandidate`), preserving the IDL-naming-clarity property ADR-0005 wanted to keep (option 2 was rejected specifically over IDL confusion; the alias sidesteps that).

## Considered Options

**1. Extract to a shared crate (chosen).** One implementation of candidate validation and slot state; each library keeps its own-named type via alias. Couples both libraries to `authority`'s evolution, but `authority` is deliberately policy-free (no admin/freeze-specific logic), so its surface is small and stable.

**2. Keep duplicating (status quo, ADR-0005's choice).** Continues to be viable, but a third consumer library (beyond admin-authority/freeze-authority) was the trigger that made the coordination cost worth paying — see spel-authority/CONTEXT.md.

## Consequences

- `AuthorityError` is one flat enum covering both candidate-validation and slot-assertion failures; each downstream library keeps one `impl From<AuthorityError> for {Admin,Freeze}Error` instead of duplicating error variants by hand.
- `AuthoritySlot` carries no policy (who can transfer, whether renounce is terminal) — that still lives entirely in each consuming library, so ADR-0005's concern about type divergence (admin-authority adding a variant freeze doesn't need) doesn't apply: policy differences are expressed by how each library *uses* the primitive, not by extending the shared type.
