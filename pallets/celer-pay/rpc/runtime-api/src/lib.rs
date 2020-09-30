#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_mut_passed)]

use codec::Codec;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    pub trait CelerPayModuleApi<AccountId, Hash, Balance, BlockNumber> where 
        AccountId: Codec,
        Hash: Codec,
        Balance: Codec,
        BlockNumber: Codec,
    {
        fn get_celer_ledger_id() -> AccountId;

        fn get_settle_finalized_time(channel_id: Hash) -> Option<BlockNumber>;

        fn get_channel_status(channel_id: Hash) -> u8;

        fn get_cooperative_withdraw_seq_num(channel_id: Hash) -> Option<u128>;

        fn get_total_balance(channel_id: Hash) -> Balance;

        fn get_balance_map(channel_id: Hash) -> (Vec<AccountId>, Vec<Balance>, Vec<Balance>);

        fn get_dispute_time_out(channel_id: Hash) -> Option<BlockNumber>;

        fn get_state_seq_num_map(channel_id: Hash) -> Option<(Vec<AccountId>, Vec<u128>)>;

        fn get_transfer_out_map(channel_id: Hash) -> Option<(Vec<AccountId>, Vec<Balance>)>;

        fn get_next_pay_id_list_hash_map(channel_id: Hash) -> Option<(Vec<AccountId>, Vec<Hash>)>;

        fn get_last_pay_resolve_deadline_map(channel_id: Hash) -> Option<(Vec<AccountId>, Vec<BlockNumber>)>;

        fn get_pending_pay_out_map(channel_id: Hash) -> Option<(Vec<AccountId>, Vec<Balance>)>;

        fn get_withdraw_intent(channel_id: Hash) -> Option<(AccountId, Balance, BlockNumber, Hash)>;

        fn get_channel_status_num(channel_status: u8) -> Option<u8>;

        fn get_balance_limits(channel_id: Hash) -> Option<Balance>;

        fn get_balance_limits_enabled(channel_id: Hash) -> Option<bool>;

        fn get_peers_migration_info(channel_id: Hash) -> Option<(
            Vec<AccountId>,
            Vec<Balance>,
            Vec<Balance>,
            Vec<u128>,
            Vec<Balance>,
            Vec<Balance>
        )>;

        fn get_celer_wallet_id() -> AccountId;

        fn get_wallet_owners(wallet_id: Hash) -> Option<Vec<AccountId>>;

        fn get_wallet_balance(wallet_id: Hash) -> Option<Balance>;

        fn get_pool_id() -> AccountId;

        fn get_pool_balance(owner: AccountId) -> Option<Balance>;

        fn get_allowance(owner: AccountId, spender: AccountId) -> Option<Balance>;

        fn get_pay_resolver_id() -> AccountId;

        fn calculate_pay_id(pay_hash: Hash) -> Hash;
    }
}