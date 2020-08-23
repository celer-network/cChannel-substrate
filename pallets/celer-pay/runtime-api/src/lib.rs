#![cfg_attr(not(feature = "std"), no_std)]

use codec::Codec;
use sp_std::vec::Vec;

sp_api:decl_runtime_apis! {
    pub trait CelerPayModuleApi<AccountId, Hash> where 
        AccountId: Codec,
        Hash: Codec,
    {
        fn get_celer_ledger_id() -> AccountId;

        fn get_celer_wallet_id() -> AccountId;

        fn get_pool_id() -> AccountId;

        fn get_pay_resolver_id() -> AccountId;

        fn calculate_pay_id() -> Hash;
    }
}