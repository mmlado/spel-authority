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
    /// An embedded-slot window `[offset..offset+64)` does not fit inside
    /// the account's data. Layout error: the declared offset and the
    /// account's actual size disagree.
    SlotOutOfBounds,
    /// A `Signer` candidate's account is owned by no program. LEZ v0.2.1
    /// to v0.2.4 rejects such an account in every transaction after its
    /// first, so installing it would strand the slot. Run
    /// `wallet auth-transfer init` on the key first.
    UnownedSigner,
    /// `accept` was called on a slot with no nomination.
    NoNomination,
    /// The signer of `accept` is not the nominee.
    NotNominee,
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
            AuthorityError::UnownedSigner => write!(f, "candidate signer is owned by no program"),
            AuthorityError::NoNomination => write!(f, "no nomination to accept"),
            AuthorityError::NotNominee => write!(f, "signer is not the nominee"),
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
    /// signer's account co-signed (`is_authorized == true`) and that some
    /// program owns it.
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
    /// - `AuthorityError::UnownedSigner` if a `Signer`'s account is owned by
    ///   no program.
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
                if account.account.program_owner == ProgramId::default() {
                    return Err(AuthorityError::UnownedSigner);
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

/// A single authority slot storing one holder and at most one nominee.
///
/// Lifecycle: [`initialize`](Self::initialize) sets a holder, then
/// [`assert`](Self::assert) gates callers against that holder. The holder
/// changes by [`transfer_to`](Self::transfer_to) in one step, or by
/// [`nominate`](Self::nominate) followed by the nominee's
/// [`accept`](Self::accept). [`renounce`](Self::renounce) vacates the slot.
///
/// `AccountId::default()` is the sentinel in both fields: a renounced
/// holder, and no nomination. Every change of holder clears the
/// nomination (ADR-0002).
#[account_type]
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthoritySlot {
    holder: AccountId,
    pending: AccountId,
}

impl AuthoritySlot {
    /// Borsh-encoded size of the slot. The single source of truth for the
    /// embedded window width; `encoded_len_matches_borsh` pins it to the
    /// actual encoding.
    pub const ENCODED_LEN: usize = 64;
    /// Builds a slot with the given initial holder.
    ///
    /// Rejects `AccountId::default()` because that's the renounced
    /// sentinel; initializing directly to renounced is meaningless.
    pub fn initialize(holder: AccountId) -> Result<Self, AuthorityError> {
        if holder == AccountId::default() {
            return Err(AuthorityError::InvalidCandidate);
        }
        Ok(Self {
            holder,
            pending: AccountId::default(),
        })
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

    /// Returns the nominee, or `None` when there is no nomination.
    pub fn pending(&self) -> Option<AccountId> {
        (self.pending != AccountId::default()).then_some(self.pending)
    }

    /// Names `next` as the nominee without any auth check on the caller,
    /// replacing any earlier nomination. `AccountId::default()` cancels.
    ///
    /// Who may nominate is the consuming library's policy.
    pub fn nominate(&mut self, next: AccountId) {
        self.pending = next;
    }

    /// Installs the nominee as holder on the nominee's own signature and
    /// clears the nomination.
    ///
    /// Does not look at `is_renounced`: whether a vacant slot may be filled
    /// is the consuming library's policy.
    ///
    /// Returns:
    /// - `AuthorityError::NoNomination` if there is no nominee.
    /// - `AuthorityError::MissingSignature` if `signer.is_authorized` is false.
    /// - `AuthorityError::NotNominee` if the signer is not the nominee.
    /// - `AuthorityError::UnownedSigner` if no program owns the signer's account.
    pub fn accept(&mut self, signer: &AccountWithMetadata) -> Result<(), AuthorityError> {
        let nominee = self.pending().ok_or(AuthorityError::NoNomination)?;
        if !signer.is_authorized {
            return Err(AuthorityError::MissingSignature);
        }
        if signer.account_id != nominee {
            return Err(AuthorityError::NotNominee);
        }
        if signer.account.program_owner == ProgramId::default() {
            return Err(AuthorityError::UnownedSigner);
        }
        self.holder = nominee;
        self.pending = AccountId::default();
        Ok(())
    }

    /// Reads the slot from the `ENCODED_LEN`-byte window at `offset` in `data`.
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
        self.pending = AccountId::default();
        Ok(())
    }

    /// Vacates the slot by writing the renounced sentinel, and clears any
    /// nomination.
    ///
    /// Not terminal at this layer. A downstream policy may re-populate
    /// the slot via `transfer_to` or a nomination. After renounce, `assert`
    /// always fails with `AuthorityError::Renounced` until repopulated.
    pub fn renounce(&mut self) {
        self.holder = AccountId::default();
        self.pending = AccountId::default();
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

    // What `wallet auth-transfer init` leaves behind: a key some program owns.
    fn owned_acct(id_byte: u8, signed: bool) -> AccountWithMetadata {
        let mut account = acct(id_byte, signed);
        account.account.program_owner = [5; 8];
        account
    }

    #[test]
    fn authority_candidate_accepts_signer() {
        let account = owned_acct(1, true);
        let candidate = AuthorityCandidate::Signer;
        let result = candidate.validate(&account);
        assert_eq!(result, Ok(account.account_id));
    }

    #[test]
    fn authority_candidate_rejects_unowned_signer() {
        let account = acct(1, true);
        assert_eq!(
            AuthorityCandidate::Signer.validate(&account),
            Err(AuthorityError::UnownedSigner)
        );
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
            ..Default::default()
        };
        assert!(slot.assert(&account).is_ok());
    }

    #[test]
    fn authority_slot_assert_rejects_renounced_holder() {
        let signer = acct(1, true);
        let slot = AuthoritySlot {
            holder: AccountId::default(),
            ..Default::default()
        };
        assert_eq!(slot.assert(&signer), Err(AuthorityError::Renounced));
    }

    #[test]
    fn authority_slot_assert_rejects_missing_signature() {
        let signer = acct(1, false);
        let slot = AuthoritySlot {
            holder: signer.account_id,
            ..Default::default()
        };
        assert_eq!(slot.assert(&signer), Err(AuthorityError::MissingSignature));
    }

    #[test]
    fn authority_slot_assert_rejects_not_holder() {
        let signer = acct(1, true);
        let slot = AuthoritySlot {
            holder: AccountId::new([2; 32]),
            ..Default::default()
        };
        assert_eq!(slot.assert(&signer), Err(AuthorityError::NotHolder));
    }

    #[test]
    fn authority_slot_transfer_to_accepts_valid_account_id() {
        let account_id = AccountId::new([1; 32]);
        let next_account_id = AccountId::new([2; 32]);
        let mut slot = AuthoritySlot {
            holder: account_id,
            ..Default::default()
        };
        assert_eq!(slot.holder, account_id);
        assert_eq!(slot.transfer_to(next_account_id), Ok(()));
        assert_eq!(slot.holder, next_account_id);
    }

    #[test]
    fn authority_slot_transfer_to_rejects_default_account_id() {
        let mut slot = AuthoritySlot {
            holder: AccountId::new([1; 32]),
            ..Default::default()
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
            ..Default::default()
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
        let mut account = owned_acct(0, true);
        account.account_id = AccountId::default();
        assert_eq!(
            AuthorityCandidate::Signer.validate(&account),
            Err(AuthorityError::InvalidCandidate)
        );
    }

    #[test]
    fn read_at_reads_slot_at_nonzero_offset() {
        let mut data = vec![0xAA; 104]; // sentinel neighbors
        data[8..40].copy_from_slice(&[7; 32]); // holder at 8
        data[40..72].copy_from_slice(&[6; 32]); // nominee at 40
        let slot = AuthoritySlot::read_at(&data, 8).unwrap();
        assert_eq!(slot.holder(), AccountId::new([7; 32]));
        assert_eq!(slot.pending(), Some(AccountId::new([6; 32])));
    }

    #[test]
    fn read_at_offset_zero_is_the_dedicated_case() {
        let data = [9u8; 64];
        let slot = AuthoritySlot::read_at(&data, 0).unwrap();
        assert_eq!(slot.holder(), AccountId::new([9; 32]));
    }

    #[test]
    fn read_at_too_short_data_is_out_of_bounds() {
        let data = [0u8; 72];
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
        let mut data = vec![0xAA; 104];
        let slot = AuthoritySlot::initialize(AccountId::new([5; 32])).unwrap();
        slot.write_at(&mut data, 8).unwrap();
        assert!(data[..8].iter().all(|b| *b == 0xAA), "prefix trampled");
        assert!(data[72..].iter().all(|b| *b == 0xAA), "suffix trampled");
        assert_eq!(&data[8..40], &[5; 32]);
        assert_eq!(&data[40..72], &[0; 32], "no nomination is the default id");
    }

    #[test]
    fn write_at_out_of_bounds_leaves_data_untouched() {
        let mut data = vec![0xAA; 62];
        let slot = AuthoritySlot::initialize(AccountId::new([5; 32])).unwrap();
        assert_eq!(
            slot.write_at(&mut data, 0),
            Err(AuthorityError::SlotOutOfBounds)
        );
        assert!(data.iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn read_write_roundtrip_at_unaligned_offset() {
        let mut data = vec![0u8; 96];
        let mut slot = AuthoritySlot::initialize(AccountId::new([3; 32])).unwrap();
        slot.nominate(AccountId::new([4; 32]));
        slot.write_at(&mut data, 7).unwrap();
        assert_eq!(AuthoritySlot::read_at(&data, 7).unwrap(), slot);
    }

    #[test]
    fn renounced_slot_writes_zeros_into_window() {
        let mut data = vec![0xFF; 72];
        let mut slot = AuthoritySlot::initialize(AccountId::new([4; 32])).unwrap();
        slot.renounce();
        slot.write_at(&mut data, 4).unwrap();
        assert_eq!(&data[4..68], &[0u8; 64]);
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

    fn nominated(holder: u8, nominee: u8) -> AuthoritySlot {
        let mut slot = AuthoritySlot::initialize(AccountId::new([holder; 32])).unwrap();
        slot.nominate(AccountId::new([nominee; 32]));
        slot
    }

    #[test]
    fn nominate_records_the_nominee_without_moving_the_holder() {
        let slot = nominated(1, 2);
        assert_eq!(slot.holder(), AccountId::new([1; 32]));
        assert_eq!(slot.pending(), Some(AccountId::new([2; 32])));
    }

    #[test]
    fn nominating_the_default_id_cancels() {
        let mut slot = nominated(1, 2);
        slot.nominate(AccountId::default());
        assert_eq!(slot.pending(), None);
    }

    #[test]
    fn a_later_nomination_replaces_an_earlier_one() {
        let mut slot = nominated(1, 2);
        slot.nominate(AccountId::new([3; 32]));
        assert_eq!(slot.pending(), Some(AccountId::new([3; 32])));
    }

    #[test]
    fn accept_moves_the_holder_and_clears_the_nomination() {
        let mut slot = nominated(1, 2);
        assert_eq!(slot.accept(&owned_acct(2, true)), Ok(()));
        assert_eq!(slot.holder(), AccountId::new([2; 32]));
        assert_eq!(slot.pending(), None);
    }

    #[test]
    fn accept_without_a_nomination_is_refused() {
        let mut slot = AuthoritySlot::initialize(AccountId::new([1; 32])).unwrap();
        assert_eq!(
            slot.accept(&owned_acct(2, true)),
            Err(AuthorityError::NoNomination)
        );
    }

    #[test]
    fn accept_without_a_signature_is_refused() {
        let mut slot = nominated(1, 2);
        assert_eq!(
            slot.accept(&owned_acct(2, false)),
            Err(AuthorityError::MissingSignature)
        );
    }

    #[test]
    fn accept_by_someone_other_than_the_nominee_is_refused() {
        let mut slot = nominated(1, 2);
        assert_eq!(
            slot.accept(&owned_acct(3, true)),
            Err(AuthorityError::NotNominee)
        );
        assert_eq!(slot.holder(), AccountId::new([1; 32]));
    }

    #[test]
    fn accept_by_an_unowned_nominee_is_refused() {
        let mut slot = nominated(1, 2);
        assert_eq!(
            slot.accept(&acct(2, true)),
            Err(AuthorityError::UnownedSigner)
        );
    }

    #[test]
    fn accept_fills_a_vacant_slot() {
        let mut slot = nominated(1, 2);
        slot.holder = AccountId::default();
        assert_eq!(slot.accept(&owned_acct(2, true)), Ok(()));
        assert_eq!(slot.holder(), AccountId::new([2; 32]));
    }

    #[test]
    fn transfer_to_clears_the_nomination() {
        let mut slot = nominated(1, 2);
        slot.transfer_to(AccountId::new([3; 32])).unwrap();
        assert_eq!(slot.pending(), None);
        assert_eq!(
            slot.accept(&owned_acct(2, true)),
            Err(AuthorityError::NoNomination)
        );
    }

    #[test]
    fn renounce_clears_the_nomination() {
        let mut slot = nominated(1, 2);
        slot.renounce();
        assert_eq!(slot.pending(), None);
    }
}
