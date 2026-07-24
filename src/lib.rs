//! Reusable authority primitives for SPEL libraries.
//!
//! Provides [`AuthorityCandidate`] for validating a transfer-time claim
//! against on-chain evidence, and [`AuthoritySlot`] as a single-holder
//! authority state with initialize / assert / transfer / renounce
//! semantics. Downstream libraries (`admin-authority`, `freeze-authority`)
//! compose these into their own config types and expose lib-specific
//! policy on top (who can transfer, who can renounce, etc).
//!
//! This crate stays policy-free: no notion of "admin" or "freeze
//! authority" lives here.

#![warn(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use spel_framework::prelude::*;

/// Errors returned by [`AuthorityCandidate::validate`] and
/// [`AuthoritySlot::assert`] / [`AuthoritySlot::initialize`]. Downstream
/// error types typically wrap or map from this via `impl From`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityError {
    /// A `Signer` candidate did not co-sign the transaction, OR
    /// [`AuthoritySlot::initialize`] was called with the renounced
    /// sentinel (`AccountId::default()`).
    InvalidCandidate,
    /// A `Pda` candidate derives to an account that is in default
    /// (unclaimed) state on-chain. Setting an unclaimed PDA as the
    /// authority would brick the slot.
    UndeployedPda,
    /// A `Pda` candidate does not derive to the address of the
    /// supplied account. Wrong account attached to the claim.
    CandidateMismatch,
    /// The signer is authorized, but their `AccountId` does not match
    /// the slot's current holder.
    NotHolder,
    /// The slot is renounced (holder is `AccountId::default()`) and
    /// therefore has no valid signer.
    Renounced,
    /// The signer's `is_authorized` flag is false.
    MissingSignature,
    /// An embedded-slot window `[offset..offset+32)` does not fit inside
    /// the account's data. Layout error: the declared offset and the
    /// account's actual size disagree.
    SlotOutOfBounds,
}

impl core::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::Renounced => write!(f, "authority renounced"),
            AuthorityError::NotHolder => write!(f, "signer is not the current authority"),
            AuthorityError::MissingSignature => write!(f, "authority signature missing"),
            AuthorityError::InvalidCandidate => write!(f, "invalid authority candidate"),
            AuthorityError::UndeployedPda => write!(f, "candidate PDA is not deployed"),
            AuthorityError::CandidateMismatch => write!(f, "candidate address mismatch"),
            AuthorityError::SlotOutOfBounds => write!(f, "embedded slot window out of bounds"),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// Transfer-time claim describing an intended authority holder.
/// Instruction arg for management ops that install a new authority
/// (transfer, bootstrap). Validated against on-chain evidence via
/// [`AuthorityCandidate::validate`] before the address is trusted.
#[derive(Deserialize, Serialize, BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCandidate {
    /// The candidate is the tx signer. Validation checks that the
    /// signer's account co-signed (`is_authorized == true`).
    Signer,
    /// The candidate is a PDA. Validation re-derives the address from
    /// `(program_id, seed)` and confirms the supplied account matches
    /// AND is not in default (unclaimed) state — i.e. the PDA has been
    /// claimed on-chain.
    Pda {
        /// Program that owns the PDA. Part of the address derivation.
        program_id: ProgramId,
        /// 32-byte seed. Part of the address derivation.
        seed: [u8; 32],
    },
}

impl AuthorityCandidate {
    /// Resolves the candidate claim against on-chain evidence and returns
    /// the `AccountId` to install as the authority holder.
    ///
    /// The candidate is the claim; `account` is the chain-state evidence.
    /// Both must agree before the address is trusted.
    ///
    /// Returns:
    /// - `AuthorityError::InvalidCandidate` if `Signer` did not co-sign the
    ///   tx, or the resolved id is the default `AccountId` (the renounced
    ///   sentinel; installing it would be a silent renounce).
    /// - `AuthorityError::CandidateMismatch` if a `Pda` claim does not derive
    ///   to `account.account_id` (wrong account attached to the claim).
    /// - `AuthorityError::UndeployedPda` if the `Pda` derives correctly but
    ///   no program owns the account (`program_owner` is the default
    ///   `ProgramId`). Anyone can fund the derived address; only the owning
    ///   program's claim stamps `program_owner`, so a funded-but-unclaimed
    ///   account is not a real PDA and would brick the slot.
    pub fn validate(&self, account: &AccountWithMetadata) -> Result<AccountId, AuthorityError> {
        let resolved = match self {
            AuthorityCandidate::Signer => {
                if !account.is_authorized {
                    return Err(AuthorityError::InvalidCandidate);
                }
                account.account_id
            }
            AuthorityCandidate::Pda { program_id, seed } => {
                let expected = AccountId::for_public_pda(program_id, &PdaSeed::new(*seed));
                if account.account_id != expected {
                    return Err(AuthorityError::CandidateMismatch);
                }
                if account.account == Account::default()
                    || account.account.program_owner == ProgramId::default()
                {
                    return Err(AuthorityError::UndeployedPda);
                }
                account.account_id
            }
        };
        if resolved == AccountId::default() {
            return Err(AuthorityError::InvalidCandidate);
        }
        Ok(resolved)
    }
}

/// A single authority slot storing one holder.
///
/// Lifecycle: [`initialize`](Self::initialize) sets a holder, then
/// [`assert`](Self::assert) gates callers against that holder,
/// [`transfer_to`](Self::transfer_to) hands it off, and
/// [`renounce`](Self::renounce) vacates the slot.
///
/// The renounced sentinel is `AccountId::default()`. A renounced slot
/// rejects all `assert` calls until a downstream policy re-populates
/// the holder via `transfer_to`.
#[account_type]
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthoritySlot {
    holder: AccountId,
}

impl AuthoritySlot {
    /// Borsh-encoded size of the slot. The single source of truth for the
    /// embedded window width; `encoded_len_matches_borsh` pins it to the
    /// actual encoding.
    pub const ENCODED_LEN: usize = 32;
    /// Builds a slot with the given initial holder.
    ///
    /// Rejects `AccountId::default()` because that's the renounced
    /// sentinel; initializing directly to renounced is meaningless.
    pub fn initialize(holder: AccountId) -> Result<Self, AuthorityError> {
        if holder == AccountId::default() {
            return Err(AuthorityError::InvalidCandidate);
        }
        Ok(Self { holder })
    }

    /// Confirms the signer is the current holder.
    ///
    /// Returns:
    /// - `AuthorityError::Renounced` if the slot has been renounced.
    /// - `AuthorityError::MissingSignature` if `signer.is_authorized`
    ///   is false.
    /// - `AuthorityError::NotHolder` if the signer is authorized but
    ///   their `AccountId` does not match the holder.
    pub fn assert(&self, signer: &AccountWithMetadata) -> Result<(), AuthorityError> {
        if self.is_renounced() {
            return Err(AuthorityError::Renounced);
        }
        if !signer.is_authorized {
            return Err(AuthorityError::MissingSignature);
        }
        if signer.account_id != self.holder {
            return Err(AuthorityError::NotHolder);
        }
        Ok(())
    }

    /// Returns the current holder. Callers wanting a semantically-named
    /// getter (e.g. `admin()` / `freeze_authority()`) should wrap this
    /// in their own config type.
    pub fn holder(&self) -> AccountId {
        self.holder
    }

    /// Returns `true` if the slot holds the renounced sentinel
    /// (`AccountId::default()`), i.e. `assert` will always fail.
    pub fn is_renounced(&self) -> bool {
        self.holder == AccountId::default()
    }

    /// Reads the slot from the 32-byte window at `offset` in `data`.
    ///
    /// Used when the slot is embedded inside a larger account instead of
    /// occupying a dedicated PDA's whole data. Returns
    /// `AuthorityError::SlotOutOfBounds` when `data` is too short for the
    /// window. The primitive knows nothing about states: config types run
    /// their empty-data check first, so this error only ever means a
    /// non-empty layout that disagrees with the declared offset.
    pub fn read_at(data: &[u8], offset: usize) -> Result<Self, AuthorityError> {
        let window = offset
            .checked_add(Self::ENCODED_LEN)
            .and_then(|end| data.get(offset..end))
            .ok_or(AuthorityError::SlotOutOfBounds)?;
        // The bounds check guarantees an ENCODED_LEN-byte window, so decoding a
        // fixed ENCODED_LEN-byte slot cannot fail here.
        Self::try_from_slice(window).map_err(|_| AuthorityError::SlotOutOfBounds)
    }

    /// Writes the slot into an ENCODED_LEN-byte window at `offset` in `data`,
    /// leaving every byte outside the window untouched.
    ///
    /// Returns `AuthorityError::SlotOutOfBounds` when `data` is too short
    /// for the window. On error `data` is not modified.
    pub fn write_at(&self, data: &mut [u8], offset: usize) -> Result<(), AuthorityError> {
        let window = offset
            .checked_add(Self::ENCODED_LEN)
            .and_then(|end| data.get_mut(offset..end))
            .ok_or(AuthorityError::SlotOutOfBounds)?;
        let bytes = borsh::to_vec(self).map_err(|_| AuthorityError::SlotOutOfBounds)?;
        window.copy_from_slice(&bytes);
        Ok(())
    }

    /// Installs `next` as the new holder without any auth check on the
    /// caller.
    ///
    /// Enforcing "who is allowed to transfer" is the caller's job
    /// (downstream config types layer their own policy on top). This
    /// primitive still validates the incoming holder: `AccountId::default()`
    /// is rejected with `AuthorityError::InvalidCandidate` because that
    /// value is the renounced sentinel. To vacate the slot, use
    /// [`renounce`](Self::renounce) instead.
    pub fn transfer_to(&mut self, next: AccountId) -> Result<(), AuthorityError> {
        if next == AccountId::default() {
            return Err(AuthorityError::InvalidCandidate);
        }
        self.holder = next;
        Ok(())
    }

    /// Vacates the slot by writing the renounced sentinel.
    ///
    /// Not terminal at this layer. A downstream policy may re-populate
    /// the slot via `transfer_to`. After renounce, `assert` always fails
    /// with `AuthorityError::Renounced` until repopulated.
    pub fn renounce(&mut self) {
        self.holder = AccountId::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(id_byte: u8, signed: bool) -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized: signed,
            account_id: AccountId::new([id_byte; 32]),
        }
    }

    #[test]
    fn authority_candidate_accepts_signer() {
        let account = acct(1, true);
        let candidate = AuthorityCandidate::Signer;
        let result = candidate.validate(&account);
        assert_eq!(result, Ok(account.account_id));
    }

    #[test]
    fn authority_candidate_rejects_invalid_signer() {
        let account = acct(1, false);
        let candidate = AuthorityCandidate::Signer;
        assert_eq!(
            candidate.validate(&account),
            Err(AuthorityError::InvalidCandidate)
        );
    }

    #[test]
    fn authority_candidate_accepts_pda() {
        let program_id: ProgramId = [1; 8];
        let seed = [1; 32];
        let derived = AccountId::for_public_pda(&program_id, &PdaSeed::new(seed));
        let account = &AccountWithMetadata {
            account: Account {
                data: vec![1].try_into().unwrap(),
                program_owner: program_id,
                ..Account::default()
            },
            is_authorized: false,
            account_id: derived,
        };
        let candidate = AuthorityCandidate::Pda { program_id, seed };
        assert_eq!(candidate.validate(account), Ok(derived));
    }

    #[test]
    fn authority_candidate_rejects_invalid_pda() {
        let program_id: ProgramId = [1; 8];
        let seed = [1; 32];
        let account = &AccountWithMetadata {
            account: Account {
                data: vec![1].try_into().unwrap(),
                ..Account::default()
            },
            is_authorized: false,
            account_id: AccountId::new([9; 32]),
        };
        let candidate = AuthorityCandidate::Pda { program_id, seed };
        assert_eq!(
            candidate.validate(account),
            Err(AuthorityError::CandidateMismatch)
        );
    }

    #[test]
    fn authority_candidate_rejects_not_deployed_pda() {
        let program_id: ProgramId = [1; 8];
        let seed = [1; 32];
        let derived = AccountId::for_public_pda(&program_id, &PdaSeed::new(seed));
        let account = &AccountWithMetadata {
            account: Account::default(),
            is_authorized: false,
            account_id: derived,
        };
        let candidate = AuthorityCandidate::Pda { program_id, seed };
        assert_eq!(
            candidate.validate(account),
            Err(AuthorityError::UndeployedPda)
        );
    }

    #[test]
    fn authority_slot_initialize_sets_holder() {
        let account_id = AccountId::new([1; 32]);
        let slot = AuthoritySlot::initialize(account_id).unwrap();
        assert_eq!(slot.holder(), account_id);
    }

    #[test]
    fn authority_slot_initialize_rejects_default_account() {
        assert_eq!(
            AuthoritySlot::initialize(AccountId::default()),
            Err(AuthorityError::InvalidCandidate)
        );
    }

    #[test]
    fn authority_slot_assert_accepts_holder() {
        let account = acct(1, true);
        let slot = AuthoritySlot {
            holder: account.account_id,
        };
        assert!(slot.assert(&account).is_ok());
    }

    #[test]
    fn authority_slot_assert_rejects_renounced_holder() {
        let signer = acct(1, true);
        let slot = AuthoritySlot {
            holder: AccountId::default(),
        };
        assert_eq!(slot.assert(&signer), Err(AuthorityError::Renounced));
    }

    #[test]
    fn authority_slot_assert_rejects_missing_signature() {
        let signer = acct(1, false);
        let slot = AuthoritySlot {
            holder: signer.account_id,
        };
        assert_eq!(slot.assert(&signer), Err(AuthorityError::MissingSignature));
    }

    #[test]
    fn authority_slot_assert_rejects_not_holder() {
        let signer = acct(1, true);
        let slot = AuthoritySlot {
            holder: AccountId::new([2; 32]),
        };
        assert_eq!(slot.assert(&signer), Err(AuthorityError::NotHolder));
    }

    #[test]
    fn authority_slot_transfer_to_accepts_valid_account_id() {
        let account_id = AccountId::new([1; 32]);
        let next_account_id = AccountId::new([2; 32]);
        let mut slot = AuthoritySlot { holder: account_id };
        assert_eq!(slot.holder, account_id);
        assert_eq!(slot.transfer_to(next_account_id), Ok(()));
        assert_eq!(slot.holder, next_account_id);
    }

    #[test]
    fn authority_slot_transfer_to_rejects_default_account_id() {
        let mut slot = AuthoritySlot {
            holder: AccountId::new([1; 32]),
        };
        assert_eq!(
            slot.transfer_to(AccountId::default()).unwrap_err(),
            AuthorityError::InvalidCandidate
        );
    }

    #[test]
    fn authority_slot_renounce() {
        let signer = acct(1, true);
        let mut slot = AuthoritySlot {
            holder: signer.account_id,
        };
        assert_eq!(slot.holder, signer.account_id);
        slot.renounce();
        assert_eq!(slot.holder, AccountId::default());
    }

    #[test]
    fn authority_slot_sequence() {
        let account_id = AccountId::new([1; 32]);
        let next_account_id = AccountId::new([2; 32]);
        let mut slot = AuthoritySlot::initialize(account_id).unwrap();
        assert_eq!(slot.holder, account_id);
        slot.transfer_to(next_account_id).unwrap();
        assert_eq!(slot.holder, next_account_id);
        slot.renounce();
        assert_eq!(slot.holder, AccountId::default());
    }

    #[test]
    fn authority_candidate_rejects_funded_but_unclaimed_pda() {
        let program_id: ProgramId = [1; 8];
        let seed = [1; 32];
        let derived = AccountId::for_public_pda(&program_id, &PdaSeed::new(seed));
        let account = &AccountWithMetadata {
            account: Account {
                data: vec![1].try_into().unwrap(),
                ..Account::default()
            },
            is_authorized: false,
            account_id: derived,
        };
        let candidate = AuthorityCandidate::Pda { program_id, seed };
        assert_eq!(
            candidate.validate(account),
            Err(AuthorityError::UndeployedPda)
        );
    }

    #[test]
    fn authority_candidate_rejects_default_resolved_signer() {
        let account = AccountWithMetadata {
            account: Account::default(),
            is_authorized: true,
            account_id: AccountId::default(),
        };
        assert_eq!(
            AuthorityCandidate::Signer.validate(&account),
            Err(AuthorityError::InvalidCandidate)
        );
    }

    #[test]
    fn read_at_reads_slot_at_nonzero_offset() {
        let mut data = vec![0xAA; 72]; // sentinel neighbors
        data[8..40].copy_from_slice(&[7; 32]); // slot window at 8
        let slot = AuthoritySlot::read_at(&data, 8).unwrap();
        assert_eq!(slot.holder(), AccountId::new([7; 32]));
    }

    #[test]
    fn read_at_offset_zero_is_the_dedicated_case() {
        let data = [9u8; 32];
        let slot = AuthoritySlot::read_at(&data, 0).unwrap();
        assert_eq!(slot.holder(), AccountId::new([9; 32]));
    }

    #[test]
    fn read_at_too_short_data_is_out_of_bounds() {
        let data = [0u8; 40];
        assert_eq!(
            AuthoritySlot::read_at(&data, 9),
            Err(AuthorityError::SlotOutOfBounds)
        );
    }

    #[test]
    fn read_at_huge_offset_does_not_overflow() {
        let data = [0u8; 32];
        assert_eq!(
            AuthoritySlot::read_at(&data, usize::MAX),
            Err(AuthorityError::SlotOutOfBounds)
        );
    }

    #[test]
    fn write_at_splices_only_the_window() {
        let mut data = vec![0xAA; 72];
        let slot = AuthoritySlot::initialize(AccountId::new([5; 32])).unwrap();
        slot.write_at(&mut data, 8).unwrap();
        assert!(data[..8].iter().all(|b| *b == 0xAA), "prefix trampled");
        assert!(data[40..].iter().all(|b| *b == 0xAA), "suffix trampled");
        assert_eq!(&data[8..40], &[5; 32]);
    }

    #[test]
    fn write_at_out_of_bounds_leaves_data_untouched() {
        let mut data = vec![0xAA; 30];
        let slot = AuthoritySlot::initialize(AccountId::new([5; 32])).unwrap();
        assert_eq!(
            slot.write_at(&mut data, 0),
            Err(AuthorityError::SlotOutOfBounds)
        );
        assert!(data.iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn read_write_roundtrip_at_unaligned_offset() {
        let mut data = vec![0u8; 64];
        let slot = AuthoritySlot::initialize(AccountId::new([3; 32])).unwrap();
        slot.write_at(&mut data, 7).unwrap();
        assert_eq!(AuthoritySlot::read_at(&data, 7).unwrap(), slot);
    }

    #[test]
    fn renounced_slot_writes_zeros_into_window() {
        let mut data = vec![0xFF; 40];
        let mut slot = AuthoritySlot::initialize(AccountId::new([4; 32])).unwrap();
        slot.renounce();
        slot.write_at(&mut data, 4).unwrap();
        assert_eq!(&data[4..36], &[0u8; 32]);
        assert!(AuthoritySlot::read_at(&data, 4).unwrap().is_renounced());
    }

    #[test]
    fn encoded_len_matches_borsh() {
        let slot = AuthoritySlot::initialize(AccountId::new([1; 32])).unwrap();
        assert_eq!(
            borsh::to_vec(&slot).unwrap().len(),
            AuthoritySlot::ENCODED_LEN
        );
    }
}
