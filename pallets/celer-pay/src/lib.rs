#![recursion_limit = "200"]
#![cfg_attr(not(feature = "std"), no_std)]

mod celer_wallet;
mod ledger_operation;
mod mock;
mod pay_registry;
mod pay_resolver;
mod pool;
pub mod weights;
pub use weights::WeightInfo;
pub mod traits;

#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, ensure,
    traits::Currency, dispatch::DispatchResultWithPostInfo,
    weights::{Weight, DispatchClass},
};
use frame_system::{self as system, ensure_signed};
use ledger_operation::{
    ChannelOf, CooperativeSettleRequestOf, CooperativeWithdrawRequestOf,
    LedgerOperation, OpenChannelRequestOf, PayIdList, SignedSimplexStateArrayOf, CELER_LEDGER_ID,
};
use celer_wallet::{WalletOf, WALLET_ID};
use pay_registry::{PayInfoOf};
use pay_resolver::{PayResolver, ResolvePaymentConditionsRequestOf, VouchedCondPayResultOf, PAY_RESOLVER_ID};
use pool::{Pool, POOL_ID};
pub use traits::Trait;
use sp_runtime::traits::{AccountIdConversion, CheckedAdd, CheckedSub, Hash, Zero, Verify};
use sp_runtime::{RuntimeDebug, DispatchResult, DispatchError};
use sp_std::{prelude::*, vec, vec::Vec};
use celer_pay_module_rpc_runtime_api::{BalanceInfo, SeqNumInfo};

pub type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

// A value placed in storage that represents the current version of the Celer Ledger storage.
// This value is used by the `on_runtime_upgrade` logic to determine whether we run
// storage migration logic. This should match directly with the semantic versions of the Rust crate.
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, RuntimeDebug)]
enum Releases {
    V1_0_0,
    V2_0_0,
}

impl Default for Releases {
    fn default() -> Self {
        Releases::V1_0_0
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as CelerLedger {
        /// Celer Ledger
        /// Mapping channel status to number of channel which is corresponding to status
        pub ChannelStatusNums get(fn channel_status_nums):
            map hasher(blake2_128_concat) u8 => Option<u8>;
        /// Mapping the channel id to Channel
        pub ChannelMap get(fn channel_map):
                map hasher(blake2_128_concat) T::Hash => Option<ChannelOf<T>>;

        /// Celer Wallet
        /// Number of wallet
        pub WalletNum get(fn wallet_num): u128;
        /// Mapping the wallet id(channel id) to Wallet
        pub Wallets get(fn wallet): map hasher(blake2_128_concat) T::Hash => Option<WalletOf<T>>;

        /// Pool
        /// Mapping owner to amount of funds in Pool
        pub PoolBalances get(fn balances):
                map hasher(blake2_128_concat) T::AccountId => Option<BalanceOf<T>>;
        /// Mapping (owner, spender) to amount of funds to be allowed by owner
        pub Allowed get(fn allowed):
                double_map hasher(blake2_128_concat) T::AccountId, hasher(blake2_128_concat) T::AccountId => Option<BalanceOf<T>>;

        // PayRegistry
        /// Mapping pay id to PayInfo
        pub PayInfoMap get(fn info_map):
                map hasher(blake2_128_concat) T::Hash => Option<PayInfoOf<T>>;

        // Storage version of the pallet
        StorageVersion build(|_| Releases::V1_0_0): Releases;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;
        
        fn deposit_event() = default;

 /// ============================ Celer Ledger Operation =========================================
        /// Set the balance limits
        ///
        /// Parameters:
        /// - `channel_id`: Id of the channel
        /// - `limits`: Limits amount of channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     71.06 µs
        /// #</weight>
        #[weight =(
            <T as traits::Trait>::WeightInfo::set_balance_limits(),
            DispatchClass::Operational
        )]
        fn set_balance_limits(
            origin,
            channel_id: T::Hash,
            #[compact] limits: BalanceOf<T>
        ) -> DispatchResult {
            LedgerOperation::<T>::set_balance_limits(origin, channel_id, limits)?;
            Ok(())
        }
        
        /// Disable balance limits
        ///
        /// Parameter:
        /// `channel_id`: Id of the channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `0(1)
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     70.58 µs
        /// #</weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::disable_balance_limits(),
            DispatchClass::Operational
        )]
        fn disable_balance_limits(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::disable_balance_limits(origin, channel_id)?;
            Ok(())
        }

        /// Enable balance limits
        ///
        /// Parameter:
        /// `channel_id`: Id of the channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `0(1)`
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     71.33 µs
        /// #</weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::enable_balance_limits(),
            DispatchClass::Operational
        )]
        fn enable_balance_limits(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::enable_balance_limits(origin, channel_id)?;
            Ok(())
        }

        /// Open a state channel through auth withdraw message
        ///
        /// Parameters:
        /// `open_request`: open channel request message
        /// `msg_value`: amount of funds to deposit from caller
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        ///   - 1 storage write `ChannelMap`
        ///   - 1 storage reads `Wallets`
        ///   - 1 storage mutation `Wallets`
        ///   - 1 storage reads `PoolBalances`
        ///   - 1 storage mutation `PoolBalances`
        ///   - 2 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        ///   - 1 storage write `WalletNum`
        /// - Based on benchmark:
        ///     503.2 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::open_channel(),
            DispatchClass::Operational
        )]
        fn open_channel(
            origin,
            open_request: OpenChannelRequestOf<T>,
            msg_value: BalanceOf<T>
        ) -> DispatchResult {
            LedgerOperation::<T>::open_channel(origin, open_request, msg_value)?;            
            let wallet_num = Self::wallet_num() + 1;
            WalletNum::put(wallet_num);
            Ok(())
        }

        /// Deposit funds into the channel
        ///
        /// Parameters:
        /// `channel_id`: Id of the channel
        /// `receiver`: address of the receiver
        /// `msg_value`: amount of funds to deposit from caller
        /// `transfer_from_amount`: amount of funds to be transfered from Pool
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        ///   - 2 storage reads `Wallets`
        ///   - 2 storage mutation `Wallets`
        ///   - 1 storage reads `PoolBalances`
        ///   - 1 storage mutation `PoolBalances`
        ///   - 2 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        /// - Based on benchmark:
        ///     218.3 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::deposit(),
            DispatchClass::Operational
        )]
        fn deposit(
            origin,
            channel_id: T::Hash,
            receiver: T::AccountId,
            msg_value: BalanceOf<T>,
            transfer_from_amount: BalanceOf<T>
        ) -> DispatchResult {
            LedgerOperation::<T>::deposit(origin, channel_id, receiver, msg_value, transfer_from_amount)?;
            Ok(())
        }

        /// Deposit funds into the channel
        ///
        /// Parameters:
        /// `channel_ids`: Id list of channel
        /// `receivers`: address list of receiver
        /// `msg_values`: amounts list of funds to deposit from caller
        /// `transfer_from_amounts`: amounts list of funds to be transfered from Pool
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N)`
        ///     - `N` channel_ids-len
        /// - DB:
        ///   - N storage reads  `ChannelMap`
        //    - N storage mutation `ChannelMap`
        ///   - 2*N storage reads `Wallets`
        ///   - 2*N storage mutation `Wallets`
        ///   - N storage reads `PoolBalances`
        ///   - N storage mutation `PoolBalances`
        ///   - 2*N storage reads `Allowed`
        ///   - N storage mutation `Allowed`
        /// - Based on benchmark:
        ///     218.3 * N µs
        /// # </weight
        #[weight = (
            <T as traits::Trait>::WeightInfo::deposit_in_batch(
                channel_ids.len() as u32, // N
            ),
            DispatchClass::Operational
        )]
        fn deposit_in_batch(
            origin,
            channel_ids: Vec<T::Hash>,
            receivers: Vec<T::AccountId>,
            msg_values: Vec<BalanceOf<T>>,
            transfer_from_amounts: Vec<BalanceOf<T>>
        ) -> DispatchResultWithPostInfo {
            ensure!(
                channel_ids.len() == receivers.len() &&
                receivers.len() == msg_values.len() &&
                msg_values.len() == transfer_from_amounts.len(),
                "Length do not match"
            );
            for i in 0..channel_ids.len() {
                LedgerOperation::<T>::deposit(origin.clone(), channel_ids[i], receivers[i].clone(), msg_values[i], transfer_from_amounts[i])?;
            }

            Ok(Some(<T as traits::Trait>::WeightInfo::deposit_in_batch(
                channel_ids.len() as u32, // N
            )).into())
        }

        /// Store signed simplex states on-chain as checkpoints
        ///
        /// Dev: simplex states in this array are not necessarily in the same channel,
        ///      which means snapshotStates natively supports multi-channel batch processing.
        ///      This function only updates seqNum, transferOut, pendingPayOut of each on-chain
        ///      simplex state. It can't ensure that the pending pays will be cleared during
        ///      settling the channel, which requires users call intendSettle with the same state.
        ///
        /// Parameter:
        /// `signed_simplex_state_array`: SignedSimplexStateArray message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N)`
        ///     - `N` signed_simplex_states-len
        /// - DB:
        ///   - N storage reads `ChannelMap`
        ///   - N storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     100.2 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::snapshot_states(
                signed_simplex_state_array.signed_simplex_states.len() as u32, // N
            ),
            DispatchClass::Operational
        )]
        fn snapshot_states(
            origin,
            signed_simplex_state_array: SignedSimplexStateArrayOf<T>
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            LedgerOperation::<T>::snapshot_states(signed_simplex_state_array.clone())?;
            
            Ok(Some(<T as traits::Trait>::WeightInfo::snapshot_states(
                signed_simplex_state_array.signed_simplex_states.len() as u32, // N
            )).into())
        }

        /// Intend to withdraw funds from channel
        ///
        /// Dev: only peers can call intend_withdraw
        ///
        /// Parameters:
        /// `channel_id`: Id of channel
        /// `amount`: amount of funds to withdraw
        /// `recipient_channel_id`: withdraw to receiver address if get_zero_hash(),
        ///     otherwise deposit to receiver address in the recipient channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     93.57 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::intend_withdraw(),
            DispatchClass::Operational
        )]
        fn intend_withdraw(
            origin,
            channel_id: T::Hash,
            amount: BalanceOf<T>,
            recipient_channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::intend_withdraw(origin, channel_id, amount, recipient_channel_id)?;
            Ok(())
        }

        /// Confirm channel withdrawal
        ///
        /// Dev: anyone can confirm a withdrawal intent
        ///
        /// Parameter:
        /// `channel_id`: Id of channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 2 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        ///   - 2 storage reads `Wallets`
        ///   - 2 storage mutation `Wallets`
        /// - Based on benchmark:
        ///     212.1 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::confirm_withdraw(),
            DispatchClass::Operational
        )]
        fn confirm_withdraw(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            ensure_signed(origin)?;
            LedgerOperation::<T>::confirm_withdraw(channel_id)?;
            Ok(())
        }

        /// Veto current withdrawal intent
        ///
        /// Dev: only peers can veto withdrawal intent;
        ///      peers can veto a withdrawal even after (request_time + dispute_timeout)
        ///
        /// Parameter:
        /// `channel_id`: Id of channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///    - 1 storage reads `ChannelMap`
        ///    - 1 storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     73.18 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::veto_withdraw(),
            DispatchClass::Operational
        )]
        fn veto_withdraw(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::veto_withdraw(origin, channel_id)?;
            Ok(())
        }

        /// Cooperatively withdraw specific amount of balance
        ///
        /// Parameter:
        /// `cooperative_withdraw_request`: CooprativeWithdrawRequest message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///    - 2 storage reads `ChannelMap`
        ///    - 1 storage mutation `ChannelMap`
        ///    - 2 storage reads `Wallets`
        ///    - 2 storage mutation `Wallets`
        /// - Based on benchmark:
        ///     208.5 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::cooperative_withdraw(),
            DispatchClass::Operational
        )]
        fn cooperative_withdraw(
            origin,
            cooperative_withdraw_request: CooperativeWithdrawRequestOf<T>
        ) -> DispatchResult {
            ensure_signed(origin)?;
            LedgerOperation::<T>::cooperative_withdraw(cooperative_withdraw_request)?;
            Ok(())
        }

        /// Intend to settle channel with an array of signed simplex states
        ///
        /// Dev: simplex states in this array are not necessarily in the same channel,
        ///      which means intendSettle natively supports multi-channel batch processing.
        ///      A simplex state with non-zero seqNum (non-null state) must be co-signed by both peers,
        ///      while a simplex state with seqNum = 0 (null state) only needs to be signed by one peer.
        ///
        /// Parameter:
        /// `signed_simplex_state_array`: SignedSimplexStateArray message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N * M)`
        ///     - `N` signed_simplex_states-len
        ///     - `M` pay_ids-len
        /// - DB:
        ///   - N storage reads `ChannelMap`
        ///   - N storage mutation `ChannelMap`
        ///   - M storage reads `PayInfoMap`
        /// - Based on benchmark:
        ///     633.2 µs
        /// # </weight>
        #[weight = (
            if signed_simplex_state_array.signed_simplex_states[0].simplex_state.pending_pay_ids.is_some() == true {
                <T as traits::Trait>::WeightInfo::intend_settle(
                    signed_simplex_state_array.signed_simplex_states.len() as u32, // N
                    signed_simplex_state_array.signed_simplex_states[0].simplex_state.pending_pay_ids.as_ref().unwrap().pay_ids.len() as u32, // M
                )
            } else {
                <T as traits::Trait>::WeightInfo::intend_settle(
                    signed_simplex_state_array.signed_simplex_states.len() as u32, // N
                    0 as u32, // M
                )
            },
            DispatchClass::Operational
        )]
        fn intend_settle(
            origin,
            signed_simplex_state_array: SignedSimplexStateArrayOf<T>
        ) -> DispatchResultWithPostInfo {
            LedgerOperation::<T>::intend_settle(origin, signed_simplex_state_array.clone())?;

            if signed_simplex_state_array.signed_simplex_states[0].simplex_state.pending_pay_ids.is_some() == true {
                Ok(Some(<T as traits::Trait>::WeightInfo::intend_settle(
                    signed_simplex_state_array.signed_simplex_states.len() as u32, // N
                    signed_simplex_state_array.signed_simplex_states[0].simplex_state.pending_pay_ids.as_ref().unwrap().pay_ids.len() as u32, // M
                )).into())
            } else {
                Ok(Some(<T as traits::Trait>::WeightInfo::intend_settle(
                    signed_simplex_state_array.signed_simplex_states.len() as u32, // N
                    0 as u32, // M
                )).into())
            }
        }

        /// Read payment results and add results to corresponding simplex payment channel
        ///
        /// Parameters:
        /// `channel_id`: Id of channel
        /// `peer_from`: address of the peer who send out funds
        /// `pay_id_list`: PayIdList
        ///
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N)`
        ///     - `N` pay_ids-len
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// - Based on benchmark:
        ///     152.1 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::clear_pays(),
            DispatchClass::Operational
        )]
        fn clear_pays(
            origin,
            channel_id: T::Hash,
            peer_from: T::AccountId,
            pay_id_list: PayIdList<T::Hash>
        ) -> DispatchResult {
            ensure_signed(origin)?;
            LedgerOperation::<T>::clear_pays(channel_id, peer_from, pay_id_list)?;
            Ok(())
        }

        /// Confirm channel settlement
        ///
        /// Dev: This must be called after settle_finalized_time
        ///
        /// Parameters:
        /// `channel_id`: Id of channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        ///   - 2 storage reads `ChannelStatusNums`
        ///   - 2 storage mutation `ChannelStatusNums`
        ///   - 2 storage reads `Wallets`
        ///   - 2 storage mutation `Wallets`
        /// - Based on benchmark:
        ///     345.7 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::confirm_settle(),
            DispatchClass::Operational
        )]
        fn confirm_settle(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            ensure_signed(origin)?;
            LedgerOperation::<T>::confirm_settle(channel_id)?;
            Ok(())
        }

        /// Cooperatively settle the channel
        ///
        /// Parameter
        /// `settle_request`: CooperativeSettleRequest message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 2 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        ///   - 2 storage reads `ChannelStatusNums`
        ///   - 2 storage mutation `ChannelStatusNums`
        ///   - 2 storage reads `Wallets`
        ///   - 2 storage mutation `Wallets`
        /// - Based on benchmark:
        ///     337.1 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::cooperative_settle(),
            DispatchClass::Operational
        )]
        fn cooperative_settle(
            origin,
            settle_request: CooperativeSettleRequestOf<T>
        ) -> DispatchResult {
            ensure_signed(origin)?;
            LedgerOperation::<T>::cooperative_settle(settle_request)?;
            Ok(())
        }

 /// ========================= Pool ===================================================
        /// Deposit native token into Pool
        ///
        /// Parameters:
        /// `receiver`: the address native token is deposited to pool
        /// `msg_value`: amount of funds to deposit to pool
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `PoolBalances`
        ///   - 1 storage mutation `PoolBalances`
        /// - Based on benchmark:
        ///     140.4 µs
        /// #</weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::deposit_pool(),
            DispatchClass::Operational
        )]
        fn deposit_pool(
            origin,
            receiver: T::AccountId,
            msg_value: BalanceOf<T>
        ) -> DispatchResult {
            Pool::<T>::deposit_pool(origin, receiver, msg_value)?;
            Ok(())
        }

        /// Withdraw native token from Pool
        ///
        /// Parameter:
        /// `value`: amount of funds to withdraw from pool
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `PoolBalances`
        ///   - 1 storage mutation `PoolBalances`
        /// - Based on benchmark:
        ///     123.4 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::withdraw_from_pool(),
            DispatchClass::Operational
        )]
        fn withdraw_from_pool(
            origin,
            value: BalanceOf<T>
        ) -> DispatchResult {
            Pool::<T>::withdraw(origin, value)?;
            Ok(())
        }

        /// Approve the passed address the spend the specified amount of funds on behalf of caller.
        ///
        /// Parameters:
        /// `spender`: the address which will spend the funds
        /// `value`: amount of funds to spent
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage write `Allowed`
        /// - Based on benchmark:
        ///     45.26 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::approve(),
            DispatchClass::Operational
        )]
        fn approve(
            origin,
            spender: T::AccountId,
            value: BalanceOf<T>
        ) -> DispatchResult {
            Pool::<T>::approve(origin, spender, value)?;
            Ok(())
        }

        /// Transfer funds from one address to another.
        ///
        /// Parameters:
        /// `from`: the address which you want to transfer funds from
        /// `to`: the address which you want to transfer to
        /// `value`: amount of funds to be transferred
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        ///   - 2 storage reads `PoolBalances`
        ///   - 1 storage mutation `PoolBalances`
        /// - Based on benchmark:
        ///     186.9 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::transfer_from(),
            DispatchClass::Operational
        )]
        fn transfer_from(
            origin,
            from: T::AccountId,
            to: T::AccountId,
            value: BalanceOf<T>
        ) -> DispatchResult {
            Pool::<T>::transfer_from(origin, from, to, value)?;
            Ok(())
        }

        /// Increase the amount of native token that an owner allowed to a spender.
        ///
        /// Parameters:
        /// `spender`: the address which spend the funds.
        /// `added_value`: amount of funds to increase the allowance by
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        /// - Based on benchmark:
        ///     61.49 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::increase_allowance(),
            DispatchClass::Operational
        )]
        fn increase_allowance(
            origin,
            spender: T::AccountId,
            added_value: BalanceOf<T>
        ) -> DispatchResult {
            Pool::<T>::increase_allowance(origin, spender, added_value)?;
            Ok(())
        }

        /// Decrease the amount of native token that an owner allowed to a spender.
        ///
        /// Parameters:
        /// `spender`: the address which will spend the funds
        /// `subtracted_value`: amount of funds to decrease the allowance by
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        /// - Based on benchmark:
        ///     58.82 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::decrease_allowance(),
            DispatchClass::Operational
        )]
        fn decrease_allowance(
            origin,
            spender: T::AccountId,
            subtracted_value: BalanceOf<T>
        ) -> DispatchResult {
            Pool::<T>::decrease_allowance(origin, spender, subtracted_value)?;
            Ok(())
        }

 /// ==================================== PayResolver =============================================
        /// Resolve a payment by onchain getting its conditons outcomes
        ///
        /// Dev: HASH_LOCK should only be used for establishing multi-hop paymetns,
        ///      and is always required to be true for all transfer function logic types.
        ///      a pay with not condiiton or only true HASH_LOCK conditions in condition array.
        ///
        /// Parameters:
        /// `resolve_pay_request`: ResolvePayByConditionsRequest message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N)`
        ///     - N: condtions-len
        /// - DB:
        ///   - 1 storage reads `PayRegistry`
        ///   - 1 storage mutation `PayRegistry`
        /// - Based on benchmark:
        ///     135.3 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::resolve_payment_by_conditions(
                resolve_pay_request.cond_pay.conditions.len() as u32, // N
            ),
            DispatchClass::Operational
        )]
        fn resolve_payment_by_conditions(
            origin,
            resolve_pay_request: ResolvePaymentConditionsRequestOf<T>
        ) -> DispatchResultWithPostInfo {
            let caller = ensure_signed(origin)?;
            PayResolver::<T>::resolve_payment_by_conditions(caller, resolve_pay_request.clone())?;
            
            Ok(Some(<T as traits::Trait>::WeightInfo::resolve_payment_by_conditions(
                resolve_pay_request.cond_pay.conditions.len() as u32, // N
            )).into())
        }

        ///　Resolve a payment by submitting an offchain vouched result
        ///
        /// Parameter:
        /// `vouched_pay_result`: VouchedCondPayResult message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N)`
        ///     - N: conditions-len
        /// - DB:
        ///   - 1 storage reads `PayRegistry`
        ///   - 1 storage mutation `PayRegistry`
        /// - Based on benchmark:
        ///     132.3 µs
        /// # </weight>
        #[weight = (
            <T as traits::Trait>::WeightInfo::resolve_payment_by_vouched_result(
                vouched_pay_result.cond_pay_result.cond_pay.conditions.len() as u32, // N
            ),
            DispatchClass::Operational
        )]
        fn resolve_payment_by_vouched_result(
            origin,
            vouched_pay_result: VouchedCondPayResultOf<T>
        ) -> DispatchResultWithPostInfo {
            ensure_signed(origin)?;
            PayResolver::<T>::resolve_payment_vouched_result(vouched_pay_result.clone())?;
            
            Ok(Some(<T as traits::Trait>::WeightInfo::resolve_payment_by_vouched_result(
                vouched_pay_result.cond_pay_result.cond_pay.conditions.len() as u32, // N
            )).into())
        }
      
        fn on_runtime_upgrade() -> Weight {
            //migration::on_runtime_upgrade::<T>();
            500_000
        }
    }
}

decl_event! (
    pub enum Event<T> where
        <T as system::Trait>::Hash,
        <T as system::Trait>::AccountId,
        Balance = BalanceOf<T>,
        <T as system::Trait>::BlockNumber
    {
        /// CelerLedger
        /// SetBalanceLimits(channel_id, limits)
        SetBalanceLimits(Hash, Balance),
        /// DisableBalanceLimits(channel_id)
        DisableBalanceLimits(Hash),
        /// EnableBalanceLimits(channel_id)
        EnableBalanceLimits(Hash),
        /// OpnChannel(channel_id, channel_peers, deposits)
        OpenChannel(Hash, Vec<AccountId>, Vec<Balance>),
        /// DepositToChannel(channel_id, chanel_peers, deposits, withdrawals)
        DepositToChannel(Hash, Vec<AccountId>, Vec<Balance>, Vec<Balance>),
        /// SnapshotStates(channel_id,seq_nums)
        SnapshotStates(Hash, Vec<u128>),
        /// IntendWithdraw(channel_id, receiver, amount)
        IntendWithdraw(Hash, AccountId, Balance),
        /// ConfirmWithdraw(channel_id, withdrawn_amount, receiver, recipient_channel_id, deposits, withdrawals)
        ConfirmWithdraw(Hash, Balance, AccountId, Hash, Vec<Balance>, Vec<Balance>),
        /// VetoWithdraw(channel_id)
        VetoWithdraw(Hash),
        /// CooperativeWithdraw(channel_id, withdrawn_amount, receiver, recipient_channel_id, deposits, withdrawals, seq_num)
        CooperativeWithdraw(Hash, Balance, AccountId, Hash, Vec<Balance>, Vec<Balance>, u128),
        /// IntendSettle(channel_id, seq_nums)
        IntendSettle(Hash, Vec<u128>),
        /// ClearOnePay(channel_id, pay_id, peer_from, amount)
        ClearOnePay(Hash, Hash, AccountId, Balance),
        /// ConfirmSettle(channel_id, settle_balances)
        ConfirmSettle(Hash, Vec<Balance>),
        /// ConfirmSettleFail(channel_id)
        ConfirmSettleFail(Hash),
        /// CooperativeSettle(channel_id, settle_balances)
        CooperativeSettle(Hash, Vec<Balance>),

        /// Celer Wallet
        /// CreateWallet(channel_id, channel_peers)
        CreateWallet(Hash, Vec<AccountId>),
        /// DepositToWallet(wallet_id, amount)
        DepositToWallet(Hash, Balance),
        /// WithdrawFromWallet(wallet_id, receiver, amount)
        WithdrawFromWallet(Hash, AccountId, Balance),

        /// Pool
        /// DepositToPool(receiver, amount)
        DepositToPool(AccountId, Balance),
        /// WithdrawFromPool(receiver, amount)
        WithdrawFromPool(AccountId, Balance),
        /// Approval(owner, spender, amount)
        Approval(AccountId, AccountId, Balance),

        /// PayRegsitry
        /// PayInfoUpdate(pay_id, amount, resolve_deadline)
        PayInfoUpdate(Hash, Balance, BlockNumber),
        /// ResolvePayment(pay_id, amount, resolve_deadline)
        ResolvePayment(Hash, Balance, BlockNumber),
    }   
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        // error
        Error,
        // overflow
        OverFlow,
        // underflow
        UnderFlow,
        // channel peer is not exist
        PeerNotExist,
        // balance_limits is not exist
        BalanceLimitsNotExist,
        // simplex_state does not contains all data
        InvalidSimplexState,
        // cooperative settle info does not contains all data
        InvalidCooperativeSettle,
        // channel is not exist
        ChannelNotExist,
        // withdrraw_intent is not exist
        WithdrawIntentNotExist,
        // who is not channel peer
        NotChannelPeer,
        // confrom_settle fail
        ConfirmSettleFail,
        // Balances is not exist
        PoolBalancesNotExist,
        // Wallet is not exist
        WalletNotExist,
        // Allowed is not exist
        AllowedNotExist,
        // PayInfo is not exist
        PayInfoNotExist,
        // hash_lock is not exit
        HashLockNotExist,
        // A runtime module condition is not regstered into runtime_module_condition_caller file
        RuntimeModuleConditionNotRegistered,
        // boolean_module_call_data is not exist
        BooleanModuleCallDataNotExist,
        // numeric_module_call_data is not exist
        NumericModuleCallDataNotExist,
        // smart_contract_call_data is not exist
        SmartContractCallDataNotExist,
        // A scale-codec encoded value can not decode correctly
		MustBeDecodable,
    }
}

impl<T: Trait> Module<T> {
/// ============================== Celer Ledger Operation =======================================    
    /// Return AccountId of Ledger Operation module
    pub fn get_celer_ledger_id() -> T::AccountId {
        return CELER_LEDGER_ID.into_account();
    }

    /// Return channel confirm settle open time
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_settle_finalized_time(channel_id: T::Hash) -> T::BlockNumber {
        let c = Self::channel_map(channel_id).unwrap();
        return c.settle_finalized_time.unwrap_or(Zero::zero());
    }

    /// Return channel status
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_channel_status(channel_id: T::Hash) -> u8 {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return 0 as u8,
        };
        return c.status as u8;
    }

    /// Return cooperative withdraw seq_num
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_cooperative_withdraw_seq_num(channel_id: T::Hash) -> SeqNumInfo {
        let c = Self::channel_map(channel_id).unwrap();
        return SeqNumInfo { number: c.cooperative_withdraw_seq_num.unwrap_or(0) };
    }

    /// Return one channel's total balance amount
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_total_balance(channel_id: T::Hash) -> BalanceInfo<BalanceOf<T>> {
        let c: ChannelOf<T> = Self::channel_map(channel_id).unwrap();
        let mut balance: BalanceOf<T> = c.peer_profiles[0].deposit;
        balance = balance.checked_add(&c.peer_profiles[1].deposit).unwrap();
        balance = balance.checked_sub(&c.peer_profiles[0].clone().withdrawal.unwrap_or(Zero::zero())).unwrap();
        balance = balance.checked_sub(&c.peer_profiles[1].clone().withdrawal.unwrap_or(Zero::zero())).unwrap();

        return BalanceInfo { amount: balance };
    }

    /// Return one channel's balance map
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_balance_map(
        channel_id: T::Hash,
    ) -> (Vec<T::AccountId>, Vec<BalanceInfo<BalanceOf<T>>>, Vec<BalanceInfo<BalanceOf<T>>>) {
        let c = Self::channel_map(channel_id).unwrap();
        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].deposit }, 
                BalanceInfo { amount: c.peer_profiles[1].deposit }
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].clone().withdrawal.unwrap_or(Zero::zero()) },
                BalanceInfo { amount: c.peer_profiles[1].clone().withdrawal.unwrap_or(Zero::zero()) }
            ],
        );
    }

    /// Return channel's dispute timeout    
    ///
    /// Parameter:
    /// `channel_id: Id of channel
    pub fn get_dispute_time_out(channel_id: T::Hash) -> T::BlockNumber {
        let c = Self::channel_map(channel_id).unwrap();
        return c.dispute_timeout;
    }

    /// Return state seq_num map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_state_seq_num_map(channel_id: T::Hash) -> (Vec<T::AccountId>, Vec<SeqNumInfo>) {
        let c = Self::channel_map(channel_id).unwrap();
        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                SeqNumInfo { number: c.peer_profiles[0].state.seq_num },
                SeqNumInfo { number: c.peer_profiles[1].state.seq_num },
            ],
        );
    }

    /// Return transfer_out map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_transfer_out_map(
        channel_id: T::Hash,
    ) -> (Vec<T::AccountId>, Vec<BalanceInfo<BalanceOf<T>>>) {
        let c = Self::channel_map(channel_id).unwrap();
        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].state.transfer_out },
                BalanceInfo { amount: c.peer_profiles[1].state.transfer_out },
            ],
        );
    }

    /// Return next_pay_id_list_hash map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_next_pay_id_list_hash_map(
        channel_id: T::Hash,
    ) -> (Vec<T::AccountId>, Vec<T::Hash>) {
        let c = Self::channel_map(channel_id).unwrap();

        let zero_hash = Self::get_zero_hash();
        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0].state.next_pay_id_list_hash.unwrap_or(zero_hash),
                c.peer_profiles[1].state.next_pay_id_list_hash.unwrap_or(zero_hash),
            ],
        );
    }

    /// Return last_pay_resolve_deadline map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_last_pay_resolve_deadline_map(
        channel_id: T::Hash,
    ) -> (Vec<T::AccountId>, Vec<T::BlockNumber>) {
        let c = Self::channel_map(channel_id).unwrap();

        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0].state.last_pay_resolve_deadline,
                c.peer_profiles[1].state.last_pay_resolve_deadline,
            ],
        );
    }

    /// Return pending_pay_out map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_pending_pay_out_map(
        channel_id: T::Hash,
    ) -> (Vec<T::AccountId>, Vec<BalanceInfo<BalanceOf<T>>>) {
        let c = Self::channel_map(channel_id).unwrap();

        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].state.pending_pay_out },
                BalanceInfo { amount: c.peer_profiles[1].state.pending_pay_out },
            ],
        );
    }

    /// Return the withdraw intent info of the channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_withdraw_intent(
        channel_id: T::Hash,
    ) -> (T::AccountId, BalanceInfo<BalanceOf<T>>, T::BlockNumber, T::Hash) {
        let c = Self::channel_map(channel_id).unwrap();

        let zero_channel_id: T::Hash = Module::<T>::get_zero_hash();
        return (
            c.withdraw_intent.receiver,
            BalanceInfo { amount: c.withdraw_intent.amount.unwrap_or(Zero::zero()) },
            c.withdraw_intent.request_time.unwrap_or(Zero::zero()),
            c.withdraw_intent.recipient_channel_id.unwrap_or(zero_channel_id),
        );
    }

    /// Return the channel number of given status
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_channel_status_num(channel_status: u8) -> u8 {
        let nums = match Self::channel_status_nums(channel_status) {
            Some(_nums) => _nums,
            None => return 0
        };
        
        return nums;
    }

    /// Return balance limits
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_balance_limits(channel_id: T::Hash) -> BalanceInfo<BalanceOf<T>> {
        let c = Self::channel_map(channel_id).unwrap();
        return BalanceInfo { amount: c.balance_limits.unwrap_or(Zero::zero()) };
    }

    /// Whether balance limits is enable.
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_balance_limits_enabled(channel_id: T::Hash) -> bool {
        let c = Self::channel_map(channel_id).unwrap();
        return c.balance_limits_enabled;
    }

    /// Return migration info of the peers in the channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_peers_migration_info(
        channel_id: T::Hash,
    ) -> (
        Vec<T::AccountId>,
        Vec<BalanceInfo<BalanceOf<T>>>,
        Vec<BalanceInfo<BalanceOf<T>>>,
        Vec<SeqNumInfo>,
        Vec<BalanceInfo<BalanceOf<T>>>,
        Vec<BalanceInfo<BalanceOf<T>>>,
    ) {
        let c = Self::channel_map(channel_id).unwrap();

        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].deposit }, 
                BalanceInfo { amount: c.peer_profiles[1].deposit }
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].withdrawal.unwrap_or(Zero::zero()) },
                BalanceInfo { amount: c.peer_profiles[1].withdrawal.unwrap_or(Zero::zero()) },
            ],
            vec![
                SeqNumInfo { number: c.peer_profiles[0].state.seq_num },
                SeqNumInfo { number: c.peer_profiles[1].state.seq_num },
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].state.transfer_out },
                BalanceInfo { amount: c.peer_profiles[1].state.transfer_out },
            ],
            vec![
                BalanceInfo { amount: c.peer_profiles[0].state.pending_pay_out },
                BalanceInfo { amount: c.peer_profiles[1].state.pending_pay_out },
            ],
        );
    }

/// ================================= Celer Wallet =================================
    /// Return AccountId of Celer Wallet module
    pub fn get_celer_wallet_id() -> T::AccountId {
        return WALLET_ID.into_account();
    }

    /// Return wallet owner conrresponding tp wallet_id
    ///
    /// Parameter:
    /// `wallet_id`: Id of the wallet
    pub fn get_wallet_owners(wallet_id: T::Hash) -> Vec<T::AccountId> {
        let w: WalletOf<T> = Self::wallet(wallet_id).unwrap();
        return w.owners;
    }

    /// Return amount of funds which is deposited into specified wallet
    ///
    /// Parameter:
    /// `wallet_id`: Id of the wallet
    pub fn get_wallet_balance(wallet_id: T::Hash) -> BalanceInfo<BalanceOf<T>> {
        let w: WalletOf<T> = Self::wallet(wallet_id).unwrap();
        return BalanceInfo { amount: w.balance };
    }

/// =================================== Pool ===================================================
    /// Return AccountId of Pool
    pub fn get_pool_id() -> T::AccountId {
        return POOL_ID.into_account();
    }

    /// Return amount of funds which is pooled of specified address
    ///
    /// Prameter:
    /// `owner`: the address of query balance of
    pub fn get_pool_balance(owner: T::AccountId) -> BalanceInfo<BalanceOf<T>> {
        return BalanceInfo { amount: Self::balances(owner).unwrap_or(Zero::zero()) };
    }

    /// Return amount of funds which owner allowed to a spender
    ///
    /// Parameters:
    /// `owner`: the address which owns the funds
    /// `spender`: the address which will spend the funds
    pub fn get_allowance(owner: T::AccountId, spender: T::AccountId) -> BalanceInfo<BalanceOf<T>> {
        return BalanceInfo { amount: Self::allowed(owner, spender).unwrap_or(Zero::zero()) };
    }

/// ================================ PayResolver =============================================
    /// Return AccountId of PayResolver module
    pub fn get_pay_resolver_id() -> T::AccountId {
        return PAY_RESOLVER_ID.into_account();
    }

/// ================================= PayRegistry ============================================
    /// Return PayInfo corresponding to pay_id
    ///
    /// Parameter:
    /// `pay_id`: Id of payment
    pub fn get_pay_info(pay_id: T::Hash) -> (BalanceInfo<BalanceOf<T>>, T::BlockNumber) {
        match PayInfoMap::<T>::get(&pay_id) {
            Some(pay_info) => {
                return (
                    BalanceInfo { amount: pay_info.amount.unwrap_or(Zero::zero()) },
                    pay_info.resolve_deadline.unwrap_or(Zero::zero())
                );
            },
            None => return (
                BalanceInfo { amount: Zero::zero() }, 
                Zero::zero()
            )
        };
    }

/// =================================== Helper ===============================================
    pub fn valid_signers(
        signatures: Vec<<T as Trait>::Signature>,
        encoded: &[u8],
        signers: Vec<T::AccountId>,
    ) -> Result<(), DispatchError> {
        for i in 0..2 {
            ensure!(
                &signatures[i].verify(encoded, &signers[i]),
                "Check co-sigs failed"
            );
        }
        Ok(())
    }

    pub fn check_single_signature(
        signature: <T as Trait>::Signature,
        encoded: &[u8],
        signer: T::AccountId,
    ) -> Result<(), DispatchError> {
        ensure!(signature.verify(encoded, &signer), "Check sig failed");
        Ok(())
    }

    pub fn get_zero_hash() -> T::Hash {
        T::Hashing::hash_of(&0)
    }
}