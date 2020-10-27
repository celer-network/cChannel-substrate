//! A crate that hosts a common definitions that are relevant for the pallet-contracts.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;

/// A result type of a resolve call.
pub type ResolveResult<AccountId> = Result<AccountId, ContractAccessError>;

/// A result type of a get storage call.
pub type GetStorageResult = Result<Option<Vec<u8>>, ContractAccessError>;

/// The possible errors that can happen querying the storage of a contract.
#[derive(Eq, PartialEq, codec::Encode, codec::Decode, sp_runtime::RuntimeDebug)]
pub enum ContractAccessError {
	/// The given address doesn't point to a contract.
	DoesntExist,
	/// The specified contract is a tombstone and thus cannot have any storage.
	IsTombstone,
}

/// A result type of a `rent_projection` call.
pub type RentProjectionResult<BlockNumber> =
	Result<RentProjection<BlockNumber>, ContractAccessError>;

#[derive(Eq, PartialEq, codec::Encode, codec::Decode, sp_runtime::RuntimeDebug)]
pub enum RentProjection<BlockNumber> {
	/// Eviction is projected to happen at the specified block number.
	EvictionAt(BlockNumber),
	/// No eviction is scheduled.
	///
	/// E.g. because the contract accumulated enough funds to offset the rent storage costs.
	NoEviction,
}
