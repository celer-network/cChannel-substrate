#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_mut_passed)]

use codec::{Codec, Decode, Encode};
#[cfg(feature = "std")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_runtime::traits::{MaybeDisplay, MaybeFromStr};
use sp_std::{prelude::*, vec::Vec};

#[derive(Eq, PartialEq, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
pub struct BalanceInfo<Balance> {
	#[cfg_attr(feature = "std", serde(bound(serialize = "Balance: std::fmt::Display")))]
	#[cfg_attr(feature = "std", serde(serialize_with = "serialize_as_string"))]
	#[cfg_attr(feature = "std", serde(bound(deserialize = "Balance: std::str::FromStr")))]
	#[cfg_attr(feature = "std", serde(deserialize_with = "deserialize_from_string"))]
	pub amount: Balance,
}

#[derive(Eq, PartialEq, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
pub struct SeqNumInfo {
	#[cfg_attr(feature = "std", serde(serialize_with = "serialize_as_string"))]
	#[cfg_attr(feature = "std", serde(deserialize_with = "deserialize_from_string"))]
	pub number: u128,
}

#[cfg(feature = "std")]
fn serialize_as_string<S: Serializer, T: std::fmt::Display>(t: &T, serializer: S) -> Result<S::Ok, S::Error> {
	serializer.serialize_str(&t.to_string())
}

#[cfg(feature = "std")]
fn deserialize_from_string<'de, D: Deserializer<'de>, T: std::str::FromStr>(deserializer: D) -> Result<T, D::Error> {
	let s = String::deserialize(deserializer)?;
	s.parse::<T>()
		.map_err(|_| serde::de::Error::custom("Parse from string failed"))
}

sp_api::decl_runtime_apis! {
    pub trait CelerPayModuleApi<AccountId, Hash, Balance, BlockNumber> where 
        AccountId: Codec,
        Hash: Codec,
        Balance: Codec + MaybeDisplay + MaybeFromStr,
        BlockNumber: Codec,
    {
        fn get_celer_ledger_id() -> AccountId;

        fn get_settle_finalized_time(channel_id: Hash) -> BlockNumber;

        fn get_channel_status(channel_id: Hash) -> u8;

        fn get_cooperative_withdraw_seq_num(channel_id: Hash) -> SeqNumInfo;

        fn get_total_balance(channel_id: Hash) -> BalanceInfo<Balance>;

        fn get_balance_map(channel_id: Hash) -> (Vec<AccountId>, Vec<BalanceInfo<Balance>>, Vec<BalanceInfo<Balance>>);

        fn get_dispute_time_out(channel_id: Hash) -> BlockNumber;

        fn get_state_seq_num_map(channel_id: Hash) -> (Vec<AccountId>, Vec<SeqNumInfo>);

        fn get_transfer_out_map(channel_id: Hash) -> (Vec<AccountId>, Vec<BalanceInfo<Balance>>);

        fn get_next_pay_id_list_hash_map(channel_id: Hash) -> (Vec<AccountId>, Vec<Hash>);

        fn get_last_pay_resolve_deadline_map(channel_id: Hash) -> (Vec<AccountId>, Vec<BlockNumber>);

        fn get_pending_pay_out_map(channel_id: Hash) -> (Vec<AccountId>, Vec<BalanceInfo<Balance>>);

        fn get_withdraw_intent(channel_id: Hash) -> (AccountId, BalanceInfo<Balance>, BlockNumber, Hash);

        fn get_channel_status_num(channel_status: u8) -> u8;

        fn get_balance_limits(channel_id: Hash) -> BalanceInfo<Balance>;

        fn get_balance_limits_enabled(channel_id: Hash) -> bool;

        fn get_peers_migration_info(channel_id: Hash) -> (
            Vec<AccountId>,
            Vec<BalanceInfo<Balance>>,
            Vec<BalanceInfo<Balance>>,
            Vec<SeqNumInfo>,
            Vec<BalanceInfo<Balance>>,
            Vec<BalanceInfo<Balance>>
        );

        fn get_celer_wallet_id() -> AccountId;

        fn get_wallet_owners(wallet_id: Hash) -> Vec<AccountId>;

        fn get_wallet_balance(wallet_id: Hash) -> BalanceInfo<Balance>;

        fn get_pool_id() -> AccountId;

        fn get_pool_balance(owner: AccountId) -> BalanceInfo<Balance>;

        fn get_allowance(owner: AccountId, spender: AccountId) -> BalanceInfo<Balance>;

        fn get_pay_resolver_id() -> AccountId;

        fn get_pay_info(pay_id: Hash) -> (BalanceInfo<Balance>, BlockNumber);
    }
}