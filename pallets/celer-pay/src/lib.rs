#![recursion_limit = "200"]
#![cfg_attr(not(feature = "std"), no_std)]

mod celer_wallet;
mod ledger_operation;
mod mock;
mod mock_numeric_condition;
mod pay_registry;
mod pay_resolver;
mod pool;
mod migration;

#[cfg(test)]
pub mod tests;

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage, ensure, Parameter,
    storage::StorageMap,
    traits::{Currency, Get},
    dispatch::{DispatchResultWithPostInfo, PostDispatchInfo, IsSubType},
    weights::{Weight, DispatchClass, GetDispatchInfo},
};
use frame_system::{self as system, ensure_signed};
use ledger_operation::{
    ChannelOf, ChannelStatus, CooperativeSettleRequestOf, CooperativeWithdrawRequestOf,
    LedgerOperation, OpenChannelRequestOf, PayIdList, SignedSimplexStateArrayOf,
};
use celer_wallet::{CelerWallet, WalletOf};
use pallet_timestamp;
use pay_registry::{PayInfoOf, PayRegistry};
use pay_resolver::{PayResolver, ResolvePaymentConditionsRequestOf, VouchedCondPayResultOf};
use pool::Pool;
use sp_runtime::traits::{
    CheckedAdd, CheckedSub, Hash, IdentifyAccount, 
    Member, Verify, Zero, Dispatchable,
};
use sp_runtime::{RuntimeDebug, DispatchResult, DispatchError};
use sp_std::{prelude::*, vec, vec::Vec};

pub type BalanceOf<T> =
    <<T as Trait>::Currency as Currency<<T as system::Trait>::AccountId>>::Balance;

pub trait Trait: system::Trait + pallet_timestamp::Trait {
    type Currency: Currency<Self::AccountId>;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = <Self as Trait>::Public> + Member + Decode + Encode;
    /// The overarching call type
    type Call: Parameter + Dispatchable<Origin=Self::Origin, PostInfo=PostDispatchInfo>
		+ GetDispatchInfo + From<frame_system::Call<Self>> + IsSubType<Module<Self>, Self>;
}

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
        pub ChannelStatusNums get(fn channel_status_nums):
            map hasher(blake2_128_concat) u8 => Option<u8>;

        pub ChannelMap get(fn channel_map):
                map hasher(blake2_128_concat) T::Hash => Option<ChannelOf<T>>;

        /// Celer Wallet
        pub WalletNum get(fn wallet_num): u128;
        pub Wallets get(fn wallet): map hasher(blake2_128_concat) T::Hash => Option<WalletOf<T>>;

        /// Pool
        pub Balances get(fn balances):
                map hasher(blake2_128_concat) T::AccountId => Option<BalanceOf<T>>;
        pub Allowed get(fn allowed):
                double_map hasher(blake2_128_concat) T::AccountId, hasher(blake2_128_concat) T::AccountId => Option<BalanceOf<T>>;

        // PayRegistry
        pub PayInfoMap get(fn info_map):
                map hasher(blake2_128_concat) T::Hash => Option<PayInfoOf<T>>;

        // Storage version of the pallet
        StorageVersion build(|_| Releases::V1_0_0): Releases;
    }
}

mod weight_for {
    use frame_support::{traits::Get, weights::Weight};
    use super::Trait;

    /// Calculate the weight for `deposit_in_batch`
    pub(crate) fn deposit_in_batch<T: Trait>(
        channel_id_len: u64,
        channel_id_len_weight: Weight
    ) -> Weight {
        T::DbWeight::get().reads_writes(7 * channel_id_len, 5 * channel_id_len)
            .saturating_add(channel_id_len_weight.saturating_mul(100_000_000))
    }

    /// Calculate the weight for `snapshot_states`
    pub(crate) fn snapshot_states<T: Trait>(
        signed_simplex_states_len: u64,
        signed_simplex_states_len_weight: Weight
    ) -> Weight {
        T::DbWeight::get().reads_writes(signed_simplex_states_len, signed_simplex_states_len)
            .saturating_add(signed_simplex_states_len_weight.saturating_mul(100_000_000))
    }

    /// Calculate the weight for `intend_settle`
    pub(crate) fn intend_settle<T: Trait>(
        signed_simplex_states_len: u64,
        signed_simplex_states_len_weight: u64,
        pay_ids_len: Weight,
        pay_ids_len_weight: Weight,
    ) -> Weight {
        T::DbWeight::get().reads_writes(signed_simplex_states_len + 2 * pay_ids_len , 2 * pay_ids_len)
            .saturating_add(pay_ids_len_weight.saturating_mul(50_000_000))
            .saturating_add(signed_simplex_states_len_weight.saturating_mul(100_000_000))
    }

    /// Calculate the weight for `resolve_payment_by_conditions`
    pub(crate) fn resolve_payment_by_conditions<T: Trait>(
        conditions_len: Weight
    ) -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
            .saturating_add(100_000_000)
            .saturating_add(conditions_len.saturating_mul(50_000_000))
    }

    /// Calculate the weight for `resolve_payment_vouched_result`
    pub(crate) fn resolve_payment_by_vouched_result<T: Trait>(
        conditions_len: Weight
    ) -> Weight {
        T::DbWeight::get().reads_writes(2, 1)
            .saturating_add(100_000_000)
            .saturating_add(conditions_len.saturating_mul(50_000_000))
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;
        
        pub fn deposit_event() = default;

        /// Celer Ledger
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
        /// #</weight>
        #[weight = 50_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn set_balance_limits(
            origin,
            channel_id: T::Hash,
            #[compact] limits: BalanceOf<T>
        ) -> DispatchResult {
            LedgerOperation::<T>::set_balance_limits(origin, channel_id, limits)?;
            
            Self::deposit_event(RawEvent::SetBalanceLimits(
                channel_id,
                limits
            ));
            
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
        /// #</weight>
        #[weight = 50_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn disable_balance_limits(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::disable_balance_limits(origin, channel_id)?;
            Self::deposit_event(RawEvent::DisableBalanceLimits(channel_id));
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
        /// #</weight>
        #[weight = 50_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn enable_balance_limits(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::enable_balance_limits(origin, channel_id)?;
            Self::deposit_event(RawEvent::EnableBalanceLimits(channel_id));
            Ok(())
        }

        /// Open a state channel through auth withdraw message
        ///
        /// Parameters:
        /// `open_request`: open channel request message
        /// `amount`: caller's deposit amount
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        ///   - 1 storage write `ChannelMap`
        ///   - 1 storage reads `Wallets`
        ///   - 1 storage mutation `Wallets`
        ///   - 1 storage reads `Balances`
        ///   - 1 storage mutation `Balances`
        ///   - 2 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        ///   - 1 storage write `WalletNum`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(4, 5)]
        fn open_channel(
            origin,
            open_request: OpenChannelRequestOf<T>,
            amount: BalanceOf<T>
        ) -> DispatchResult {
            let channel_id: T::Hash = LedgerOperation::<T>::open_channel(origin, open_request, amount)?;
            let c = Self::channel_map(channel_id).unwrap();
            Self::deposit_event(RawEvent::OpenChannel(
                channel_id,
                vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()],
                vec![c.peer_profiles[0].deposit, c.peer_profiles[1].deposit]
            ));

            let wallet_num = Self::wallet_num() + 1;
            WalletNum::put(wallet_num);

            Ok(())
        }

        /// Deposit native token into the channel
        ///
        /// Parameters:
        /// `channel_id`: Id of the channel
        /// `receiver`: address of the receiver
        /// `amount`: caller's deposit amount
        /// `transfer_from_amount`: amount of funds to be transfered from Pool
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 2 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        ///   - 2 storage reads `Wallets`
        ///   - 2 storage mutation `Wallets`
        ///   - 1 storage reads `Balances`
        ///   - 1 storage mutation `Balances`
        ///   - 2 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(7, 5)]
        fn deposit(
            origin,
            channel_id: T::Hash,
            receiver: T::AccountId,
            amount: BalanceOf<T>,
            transfer_from_amount: BalanceOf<T>
        ) -> DispatchResult {
            LedgerOperation::<T>::deposit(origin, channel_id, receiver, amount, transfer_from_amount)?;
            let c = Self::channel_map(channel_id).unwrap();
            let zero_balance: BalanceOf<T> = Zero::zero();
            Self::deposit_event(RawEvent::Deposit(
                channel_id,
                vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()],
                vec![c.peer_profiles[0].deposit, c.peer_profiles[1].deposit],
                vec![c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance), c.peer_profiles[1].clone().withdrawal.unwrap_or(zero_balance)]
            ));

            Ok(())
        }

        /// Deposit native tokens into the channel
        ///
        /// Parameters:
        /// `channel_ids`: Ids of channel
        /// `receivers`: addresses of receiver
        /// `amounts`: caller's deposit amounts
        /// `transfer_from_amounts`: amounts of funds to be transfered from Pool
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N)`
        ///     - `N` channel_ids-len
        /// - DB:
        ///   - 2*N storage reads  `ChannelMap`
        //    - N storage mutation `ChannelMap`
        ///   - 2*N storage reads `Wallets`
        ///   - 2*N storage mutation `Wallets`
        ///   - N storage reads `Balances`
        ///   - N storage mutation `Balances`
        ///   - 2*N storage reads `Allowed`
        ///   - N storage mutation `Allowed`
        /// # </weight
        #[weight = (
            weight_for::deposit_in_batch::<T>(
                channel_ids.len() as u64, // N
                channel_ids.len() as Weight, // N
            ),
            DispatchClass::Operational
        )]
        fn deposit_in_batch(
            origin,
            channel_ids: Vec<T::Hash>,
            receivers: Vec<T::AccountId>,
            amounts: Vec<BalanceOf<T>>,
            transfer_from_amounts: Vec<BalanceOf<T>>
        ) -> DispatchResultWithPostInfo {
            let _ = ensure_signed(origin.clone())?;

            ensure!(
                channel_ids.len() == receivers.len() &&
                receivers.len() == amounts.len() &&
                amounts.len() == transfer_from_amounts.len(),
                "Length do not match"
            );

            for i in 0..channel_ids.len() {
                LedgerOperation::<T>::deposit(origin.clone(), channel_ids[i], receivers[i].clone(), amounts[i], transfer_from_amounts[i])?;
                let c = match Self::channel_map(channel_ids[i]) {
                    Some(channel) => channel,
                    None => return Err(Error::<T>::ChannelNotExist)?
                };
                let zero_balance: BalanceOf<T> = Zero::zero();

                Self::deposit_event(RawEvent::Deposit(
                    channel_ids[i],
                    vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()],
                    vec![c.peer_profiles[0].deposit, c.peer_profiles[1].deposit],
                    vec![c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance), c.peer_profiles[1].clone().withdrawal.unwrap_or(zero_balance)]
                ));
            }

            Ok(Some(weight_for::deposit_in_batch::<T>(
                channel_ids.len() as u64,
                channel_ids.len() as Weight,
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
        /// # </weight>
        #[weight = (
            weight_for::snapshot_states::<T>(
                signed_simplex_state_array.signed_simplex_states.len() as u64, // N
                signed_simplex_state_array.signed_simplex_states.len() as Weight, // N
            ),
            DispatchClass::Operational
        )]
        fn snapshot_states(
            origin,
            signed_simplex_state_array: SignedSimplexStateArrayOf<T>
        ) -> DispatchResultWithPostInfo {
            let _ = ensure_signed(origin)?;
            LedgerOperation::<T>::snapshot_states(signed_simplex_state_array.clone())?;
            
            Ok(Some(weight_for::snapshot_states::<T>(
                signed_simplex_state_array.signed_simplex_states.len() as u64, // N
                signed_simplex_state_array.signed_simplex_states.len() as Weight, // N
            )).into())
        }

        /// Intend to withdraw funds from channel
        ///
        /// Dev: only peers can call intend_withdraw
        ///
        /// Parameters:
        /// `channel_id`: Id of channel
        /// `amount`: amount of funds to withdraw
        /// `receipient_channel_id`: withdraw to receiver address if hash(0),
        ///     otherwise deposit to receiver address in the recipient channel
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// # </weight>
        #[weight = 50_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn intend_withdraw(
            origin,
            channel_id: T::Hash,
            amount: BalanceOf<T>,
            receipient_channel_id: T::Hash
        ) -> DispatchResult {
            let (_, _receiver, _amount): (T::Hash, T::AccountId, BalanceOf<T>) =
                LedgerOperation::<T>::intend_withdraw(origin, channel_id, amount, receipient_channel_id)?;
            Self::deposit_event(RawEvent::IntendWithdraw(
                channel_id,
                _receiver,
                _amount
            ));
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
        ///   - 2 storage mutation `ChannelMap`
        ///   - 2 storage reads `Wallets`
        ///   - 2 storage mutation `Wallets`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(4, 4)]
        fn confirm_withdraw(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let (_withdraw_amount, _receiver, _receipient_channel_id): (BalanceOf<T>, T::AccountId, T::Hash)
                = LedgerOperation::<T>::confirm_withdraw(channel_id)?;
            let (_, _deposits, _withdrawals): (Vec<T::AccountId>, Vec<BalanceOf<T>>, Vec<BalanceOf<T>>)
                = Self::get_balance_map(channel_id);
            Self::deposit_event(RawEvent::ConfirmWithdraw(
                channel_id,
                _withdraw_amount,
                _receiver,
                _receipient_channel_id,
                _deposits,
                _withdrawals
            ));

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
        /// # </weight>
        #[weight = 50_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn veto_withdraw(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            LedgerOperation::<T>::veto_withdraw(origin, channel_id)?;
            Self::deposit_event(RawEvent::VetoWithdraw(channel_id));
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
        ///    - 2 storage mutation `ChannelMap`
        ///    - 2 storage reads `Wallets`
        ///    - 2 storage mutation `Wallets`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(4, 4)]
        fn cooperative_withdraw(
            _origin,
            cooperative_withdraw_request: CooperativeWithdrawRequestOf<T>
        ) -> DispatchResult {
            let (_channel_id, _withdrawn_amount, _receiver, _receipient_channel_id, _seq_num): (T::Hash, BalanceOf<T>, T::AccountId, T::Hash, u128)
                = LedgerOperation::<T>::cooperative_withdraw(cooperative_withdraw_request)?;
            let (_, _deposits, _withdrawals): (Vec<T::AccountId>, Vec<BalanceOf<T>>, Vec<BalanceOf<T>>)
                = Self::get_balance_map(_channel_id);
            Self::deposit_event(RawEvent::CooperativeWithdraw(
                _channel_id,
                _withdrawn_amount,
                _receiver,
                _receipient_channel_id,
                _deposits,
                _withdrawals,
                _seq_num
            ));
            Ok(())
        }

        /// Intent to settle channel with an array of signed simplex states
        ///
        /// Dev: simplex states in this array are not necessarily in the same channel,
        ///      which means intendSettle natively supports multi-channel batch processing.
        ///      A simplex state with non-zero seqNum (non-null state) must be co-signed by both peers,
        ///      while a simplex state with seqNum=0 (null state) only needs to be signed by one peer.
        ///
        /// Parameter:
        /// `signed_simplex_state_array`: SignedSimplexStateArray message
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(N * M)`
        ///     - `N` signed_simplex_states-len
        ///     - `M` pay_hashes-len
        /// - DB:
        ///   - N storage reads `ChannelMap`
        ///   - 2 * N storage mutation `ChannelMap`
        ///   - 2 * M storage reads `PayInfoMap`
        /// # </weight>
        #[weight = (
            weight_for::intend_settle::<T>(
                signed_simplex_state_array.signed_simplex_states.len() as u64,
                signed_simplex_state_array.signed_simplex_states[0].clone().simplex_state.clone().pending_pay_ids.unwrap().pay_ids.len() as u64, // M
                signed_simplex_state_array.signed_simplex_states.len() as Weight, // N
                signed_simplex_state_array.signed_simplex_states[0].clone().simplex_state.clone().pending_pay_ids.unwrap().pay_ids.len() as Weight, // M
            ),
            DispatchClass::Operational
        )]
        fn intend_settle(
            origin,
            signed_simplex_state_array: SignedSimplexStateArrayOf<T>
        ) -> DispatchResultWithPostInfo {
            LedgerOperation::<T>::intend_settle(origin, signed_simplex_state_array.clone())?;

            Ok(Some(weight_for::intend_settle::<T>(
                signed_simplex_state_array.signed_simplex_states.len() as u64, // N
                signed_simplex_state_array.signed_simplex_states[0].clone().simplex_state.clone().pending_pay_ids.unwrap().pay_ids.len() as u64, // M
                signed_simplex_state_array.signed_simplex_states.len() as Weight, // N
                signed_simplex_state_array.signed_simplex_states[0].clone().simplex_state.clone().pending_pay_ids.unwrap().pay_ids.len() as Weight, // M
            )).into())
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
        ///   - 2 storage reads `ChannelMap`
        ///   - 1 storage mutation `ChannelMap`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(2, 1)]
        fn clear_pays(
            _origin,
            channel_id: T::Hash,
            peer_from: T::AccountId,
            pay_id_list: PayIdList<T::Hash>
        ) -> DispatchResult {
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
        ///   - 2 storage mutation `ChannelMap`
        ///   - 1 storage reads `ChannelStatusNums`
        ///   - 1 storage mutation `ChannelStatusNums`
        ///   - 1 storage reads `Wallets`
        ///   - 1 storage mutation `Wallets`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(3, 4)]
        fn confirm_settle(
            origin,
            channel_id: T::Hash
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let (_channel_id, _settle_balance) = LedgerOperation::<T>::confirm_settle(channel_id)?;
            Self::deposit_event(RawEvent::ConfirmSettle(
                _channel_id,
                _settle_balance
            ));
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
        ///   - 1 storage reads `ChannelStatusNums`
        ///   - 1 storage mutation `ChannelStatusNums`
        ///   - 1 storage reads `Wallets`
        ///   - 1 storage mutation `Wallets`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(4, 3)]
        fn cooperative_settle(
            origin,
            settle_request: CooperativeSettleRequestOf<T>
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let (_channel_id, _settle_balance): (T::Hash, Vec<BalanceOf<T>>)
                = LedgerOperation::<T>::cooperative_settle(settle_request)?;
            Self::deposit_event(RawEvent::CooperativeSettle(
                _channel_id,
                _settle_balance
            ));
            Ok(())
        }

        /// Celer Wallet
        /// Deposit native token to a wallet.
        ///
        /// Parameter:
        /// `wallet_id`: Id of the wallet to deposit into
        /// `amount`: depoist amount
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Walletss`
        ///   - 1 storage mutation `Wallets`
        /// # </weight>
        #[weight = 500_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn deposit_native_token(
            origin,
            wallet_id: T::Hash,
            amount: BalanceOf<T>
        ) -> DispatchResult {
            let (_wallet_id, _amount): (T::Hash, BalanceOf<T>) = CelerWallet::<T>::deposit_native_token(origin, wallet_id, amount)?;
            Self::deposit_event(RawEvent::DepositToWallet(_wallet_id, _amount));
            Ok(())
        }

        /// Pool
        /// Deposit native token into Pool
        ///
        /// Parameters:
        /// `receiver`: the address native token is deposited to
        /// `amount`: amount of deposit
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 2 storage reads `Balances`
        ///   - 1 storage mutation `Balances`
        /// #</weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(2, 1)]
        fn deposit_pool(
            origin,
            receiver: T::AccountId,
            amount: BalanceOf<T>
        ) -> DispatchResult {
            let (_receiver, _amount): (T::AccountId, BalanceOf<T>)
                = Pool::<T>::deposit_pool(origin, receiver, amount)?;
            Self::deposit_event(RawEvent::PoolDeposit(_receiver, _amount));
            Ok(())
        }

        /// Withdraw native token from Pool
        ///
        /// Parameter:
        /// `value`: amount of native token to withdraw
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 2 storage reads `Balances`
        ///   - 1 storage mutation `Balances`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(2, 1)]
        fn withdraw_from_pool(
            origin,
            value: BalanceOf<T>
        ) -> DispatchResult {
            let (_receiver, _amount): (T::AccountId, BalanceOf<T>)
                = Pool::<T>::withdraw(origin, value)?;
            Self::deposit_event(RawEvent::WithdrawFromPool(_receiver, _amount));
            Ok(())
        }

        /// Approve the passed address the spend the specified amount of native token on behalf of caller.
        ///
        /// Parameters:
        /// `spender`: the address which will spend the funds
        /// `value`: amount of native token to spent
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage write `Allowed`
        /// # </weight>
        #[weight = 500_000 + T::DbWeight::get().writes(1)]
        fn approve(
            origin,
            spender: T::AccountId,
            value: BalanceOf<T>
        ) -> DispatchResult {
            let (_owner, _spender, _value): (T::AccountId, T::AccountId, BalanceOf<T>)
                = Pool::<T>::approve(origin, spender, value)?;
            Self::deposit_event(RawEvent::Approval(_owner, _spender, _value));
            Ok(())
        }

        /// Transfer native token from one address to another.
        ///
        /// Parameters:
        /// `from`: the address which you want to transfer native token from
        /// `to`: the address which you want to transfer to
        /// `value`: amount of native token to be transferred
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 2 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        ///   - 3 storage reads `Balances`
        ///   - 1 storage mutation `Balances`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(5, 2)]
        fn transfer_from(
            origin,
            from: T::AccountId,
            to: T::AccountId,
            value: BalanceOf<T>
        ) -> DispatchResult {
            let (_from, _to, _value): (T::AccountId, T::AccountId, BalanceOf<T>)
                = Pool::<T>::transfer_from(origin, from, to, value)?;
            Self::deposit_event(RawEvent::Transfer(_from, _to, value));
            Ok(())
        }

        /// Transfer to native token from one address to a wallet in CelerWallet Module.
        ///
        /// Parameters:
        /// `from`: the address which you want to transfer native token from
        /// `wallet_id`: Id of the wallet you want to deposit native token into
        /// `amount`: amount of native token to be transfered
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Wallets`
        ///   - 1 storage mutation `Wallets`
        ///   - 1 storage reads `Balances`
        ///   - 1 storage mutation `Balances`
        ///   - 2 storage reads `Allowed`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(4, 2)]
        fn transfer_to_celer_wallet(
            origin,
            from: T::AccountId,
            wallet_id: T::Hash,
            amount: BalanceOf<T>
        ) -> DispatchResult {
            let (_wallet_id, _from, _amount): (T::Hash, T::AccountId, BalanceOf<T>)
                = Pool::<T>::transfer_to_celer_wallet(origin, from, wallet_id, amount)?;
            Self::deposit_event(RawEvent::TransferToCelerWallet(_wallet_id, _from, _amount));
            Ok(())
        }

        /// Increase the amount of native token that an owner allowed to a spender.
        ///
        /// Parameters:
        /// `spender`: the address which spend the funds.
        /// `added_value`: amount of native token to increase the allowance by
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn increase_allowance(
            origin,
            spender: T::AccountId,
            added_value: BalanceOf<T>
        ) -> DispatchResult {
            let (_owner, _spender, _added_value): (T::AccountId, T::AccountId, BalanceOf<T>)
                = Pool::<T>::increase_allowance(origin, spender, added_value)?;
            Self::deposit_event(RawEvent::Approval(_owner, _spender, _added_value));
            Ok(())
        }

        /// Decrease the amount of native token that an owner allowed to a spender.
        ///
        /// Parameters:
        /// `spender`: the address which will spend the funds
        /// `subtracted_value`: amount of native tokent o decrease the allowance by
        /// 
        /// # <weight>
        /// ## Weight
        /// - Complexity: `O(1)`
        /// - DB:
        ///   - 1 storage reads `Allowed`
        ///   - 1 storage mutation `Allowed`
        /// # </weight>
        #[weight = 100_000_000 + T::DbWeight::get().reads_writes(1, 1)]
        fn decrease_allowance(
            origin,
            spender: T::AccountId,
            subtracted_value: BalanceOf<T>
        ) -> DispatchResult {
            let (_owner, _spender, _subtracted_value): (T::AccountId, T::AccountId, BalanceOf<T>)
                = Pool::<T>::decrease_allowance(origin, spender, subtracted_value)?;
            Self::deposit_event(RawEvent::Approval(_owner, _spender, _subtracted_value));
            Ok(())
        }

        /// PayResolver
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
        ///   - 2 storage reads `PayRegistry`
        ///   - 1 storage mutation `PayRegistry`
        /// # </weight>
        #[weight = (
            weight_for::resolve_payment_by_conditions::<T>(
                resolve_pay_request.cond_pay.conditions.len() as Weight
            ),
            DispatchClass::Operational
        )]
        fn resolve_payment_by_conditions(
            origin,
            resolve_pay_request: ResolvePaymentConditionsRequestOf<T>
        ) -> DispatchResultWithPostInfo {
            let _ = ensure_signed(origin)?;
            let (_pay_id, _amount, _resolve_deadline): (T::Hash, BalanceOf<T>, T::BlockNumber)
                = PayResolver::<T>::resolve_payment_by_conditions(resolve_pay_request.clone())?;
            Self::deposit_event(RawEvent::ResolvePayment(_pay_id, _amount, _resolve_deadline));
            
            Ok(Some(weight_for::resolve_payment_by_conditions::<T>(
                resolve_pay_request.cond_pay.conditions.len() as Weight, // N
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
        ///   - 2 storage reads `PayRegistry`
        ///   - 1 storage mutation `PayRegistry`
        /// # </weight>
        #[weight = (
            weight_for::resolve_payment_by_vouched_result::<T>(
                vouched_pay_result.cond_pay_result.cond_pay.conditions.len() as Weight
            ),
            DispatchClass::Operational
        )]
        fn resolve_payment_by_vouched_result(
            origin,
            vouched_pay_result: VouchedCondPayResultOf<T>
        ) -> DispatchResultWithPostInfo {
            let _ = ensure_signed(origin)?;
            let (_pay_id, _amount, _resolve_deadline): (T::Hash, BalanceOf<T>, T::BlockNumber)
                = PayResolver::<T>::resolve_payment_vouched_result(vouched_pay_result.clone())?;
            Self::deposit_event(RawEvent::ResolvePayment(_pay_id, _amount, _resolve_deadline));
            
            Ok(Some(weight_for::resolve_payment_by_vouched_result::<T>(
                vouched_pay_result.cond_pay_result.cond_pay.conditions.len() as Weight, // N
            )).into())
        }

        fn on_runtime_upgrade() -> Weight {
            migration::on_runtime_upgrade::<T>();
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
        /// Deposit(channel_id, chanel_peers, deposits, withdrawals)
        Deposit(Hash, Vec<AccountId>, Vec<Balance>, Vec<Balance>),
        /// SnapshotStates(channel_id,seq_nums)
        SnapshotStates(Hash, Vec<u128>),
        /// IntendWithdraw(channel_id, receiver, amount)
        IntendWithdraw(Hash, AccountId, Balance),
        /// ConfirmWithdraw(channel_id, withdrawn_amount, receiver, receipient_channel_id, deposits, withdrawals)
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
        /// PoolDeposit(receiver, amount)
        PoolDeposit(AccountId, Balance),
        /// WithdrawFromPool(receiver, amount)
        WithdrawFromPool(AccountId, Balance),
        /// Transfer(sender, receiver, amount)
        Transfer(AccountId, AccountId, Balance),
        /// TransferToCelerWallet(wallet_id, from, amount)
        TransferToCelerWallet(Hash, AccountId, Balance),
        /// Approval(channel_id, owner, spender)
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
        // channel is not exist
        ChannelNotExist,
        // withdrraw_intent is not exist
        WithdrawIntentNotExist,
        // who is not channel peer
        NotChannelPeer,
        // confrom_settle fail
        ConfirmSettleFail,
        // Balances is not exist
        BalancesNotExist,
        // Wallet is not exist
        WalletNotExist,
        // Allowed is not exist
        AllowedNotExist,
        // PayInfo is not exist
        PayInfoNotExist,
        // hash_lock is not exit
        HashLockNotExist,
        // condition_address is not exit
        ConditionAddressNotExist,
    }
}

impl<T: Trait> Module<T> {
    /// CelerLedger
    /// Get channel settle open time
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_settle_finalized_time(channel_id: T::Hash) -> Option<T::BlockNumber> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return c.settle_finalized_time;
    }

    /// Get channel status
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_channel_status(channel_id: T::Hash) -> ChannelStatus {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return ChannelStatus::Uninitialized,
        };
        return c.status;
    }

    /// Get cooperative withdraw seq_num
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_cooperative_withdraw_seq_num(channel_id: T::Hash) -> Option<u128> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return c.cooperative_withdraw_seq_num;
    }

    /// Return one channel's total balance amount
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_total_balance(channel_id: T::Hash) -> Result<BalanceOf<T>, DispatchError> {
        let c: ChannelOf<T> = Self::channel_map(channel_id).unwrap();
        let zero_balance: BalanceOf<T> = Zero::zero();
        let mut balance: BalanceOf<T> = c.peer_profiles[0].deposit;
        balance = balance
            .checked_add(&c.peer_profiles[1].deposit)
            .ok_or(Error::<T>::OverFlow)?;
        balance = balance
            .checked_sub(
                &c.peer_profiles[0]
                    .clone()
                    .withdrawal
                    .unwrap_or(zero_balance),
            )
            .ok_or(Error::<T>::UnderFlow)?;
        balance = balance
            .checked_sub(
                &c.peer_profiles[1]
                    .clone()
                    .withdrawal
                    .unwrap_or(zero_balance),
            )
            .ok_or(Error::<T>::UnderFlow)?;
        return Ok(balance);
    }

    /// Return one channel's balance info
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_balance_map(
        channel_id: T::Hash,
    ) -> (Vec<T::AccountId>, Vec<BalanceOf<T>>, Vec<BalanceOf<T>>) {
        let c = Self::channel_map(channel_id).unwrap();
        let zero_balance: BalanceOf<T> = Zero::zero();
        return (
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![c.peer_profiles[0].deposit, c.peer_profiles[1].deposit],
            vec![
                c.peer_profiles[0]
                    .clone()
                    .withdrawal
                    .unwrap_or(zero_balance),
                c.peer_profiles[1]
                    .clone()
                    .withdrawal
                    .unwrap_or(zero_balance),
            ],
        );
    }

    /// Return channel's dispute timeout    
    ///
    /// Parameter:
    /// `channel_id: Id of channel
    pub fn get_dispute_time_out(channel_id: T::Hash) -> Option<T::BlockNumber> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return Some(c.dispute_timeout);
    }

    /// Return state seq_num map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_state_seq_num_map(channel_id: T::Hash) -> Option<(Vec<T::AccountId>, Vec<u128>)> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return Some((
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0].state.seq_num,
                c.peer_profiles[1].state.seq_num,
            ],
        ));
    }

    /// Return transfer_out map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_transfer_out_map(
        channel_id: T::Hash,
    ) -> Option<(Vec<T::AccountId>, Vec<BalanceOf<T>>)> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return Some((
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0].state.transfer_out,
                c.peer_profiles[1].state.transfer_out,
            ],
        ));
    }

    /// Return next_pay_id_list_hash map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_next_pay_id_list_hash_map(
        channel_id: T::Hash,
    ) -> Option<(Vec<T::AccountId>, Vec<T::Hash>)> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };

        let hash_zero = Self::zero_hash();
        return Some((
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0]
                    .state
                    .next_pay_id_list_hash
                    .unwrap_or(hash_zero),
                c.peer_profiles[1]
                    .state
                    .next_pay_id_list_hash
                    .unwrap_or(hash_zero),
            ],
        ));
    }

    /// Return last_pay_resolve_deadline map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_last_pay_resolve_deadline_map(
        channel_id: T::Hash,
    ) -> Option<(Vec<T::AccountId>, Vec<T::BlockNumber>)> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return Some((
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0].state.last_pay_resolve_deadline,
                c.peer_profiles[1].state.last_pay_resolve_deadline,
            ],
        ));
    }

    /// Return pending_pay_out map of a duplex channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_pending_pay_out_map(
        channel_id: T::Hash,
    ) -> Option<(Vec<T::AccountId>, Vec<BalanceOf<T>>)> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return Some((
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![
                c.peer_profiles[0].state.pending_pay_out,
                c.peer_profiles[1].state.pending_pay_out,
            ],
        ));
    }

    /// Return the withdraw intent info of the channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_withdraw_intent(
        channel_id: T::Hash,
    ) -> Option<(T::AccountId, BalanceOf<T>, T::BlockNumber, T::Hash)> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };

        let zero_balance: BalanceOf<T> = Zero::zero();
        let zero_block_number: T::BlockNumber = Zero::zero();
        let zero_channel_id: T::Hash = Self::zero_hash();
        let withdraw_intent = c.withdraw_intent;
        return Some((
            withdraw_intent.receiver,
            withdraw_intent.amount.unwrap_or(zero_balance),
            withdraw_intent.request_time.unwrap_or(zero_block_number),
            withdraw_intent
                .recipient_channel_id
                .unwrap_or(zero_channel_id),
        ));
    }

    /// Get the seq_num of two simplex channel states
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_channel_status_num(channel_status: u8) -> Option<u8> {
        return <ChannelStatusNums>::get(channel_status);
    }

    /// Return balance limit
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_balance_limit(channel_id: T::Hash) -> Option<BalanceOf<T>> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return c.balance_limits;
    }

    /// Return balanceLimitsEnabled
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_balance_limits_enabled(channel_id: T::Hash) -> Option<bool> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        return Some(c.balance_limits_enabled);
    }

    /// Return migration info of the peers in the channel
    ///
    /// Parameter:
    /// `channel_id`: Id of channel
    pub fn get_peers_migration_info(
        channel_id: T::Hash,
    ) -> Option<(
        Vec<T::AccountId>,
        Vec<BalanceOf<T>>,
        Vec<BalanceOf<T>>,
        Vec<u128>,
        Vec<BalanceOf<T>>,
        Vec<BalanceOf<T>>,
    )> {
        let c = match Self::channel_map(channel_id) {
            Some(channel) => channel,
            None => return None,
        };
        let zero_balance: BalanceOf<T> = Zero::zero();

        return Some((
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            vec![c.peer_profiles[0].deposit, c.peer_profiles[1].deposit],
            vec![
                c.peer_profiles[0].withdrawal.unwrap_or(zero_balance),
                c.peer_profiles[1].withdrawal.unwrap_or(zero_balance),
            ],
            vec![
                c.peer_profiles[0].state.seq_num,
                c.peer_profiles[1].state.seq_num,
            ],
            vec![
                c.peer_profiles[0].state.transfer_out,
                c.peer_profiles[1].state.transfer_out,
            ],
            vec![
                c.peer_profiles[0].state.pending_pay_out,
                c.peer_profiles[1].state.pending_pay_out,
            ],
        ));
    }

    /// Celer Wallet
    /// Return wallet owner conrresponding tp wallet_id
    ///
    /// Parameter:
    /// `wallet_id`: Id of the wallet
    pub fn get_wallet_owners(wallet_id: T::Hash) -> Option<Vec<T::AccountId>> {
        let w: WalletOf<T> = match Self::wallet(wallet_id) {
            Some(wallet) => wallet,
            None => return None,
        };

        let owners = w.owners;
        return Some(owners);
    }

    /// Return balance in a given wallet
    ///
    /// Parameter:
    /// `wallet_id`: Id of the wallet
    pub fn get_balance(wallet_id: T::Hash) -> Option<BalanceOf<T>> {
        let w: WalletOf<T> = match Self::wallet(wallet_id) {
            Some(wallet) => wallet,
            None => return None,
        };

        let balance = w.balance;
        return Some(balance);
    }

    /// Pool
    /// Return balnce in pooled Pool
    ///
    /// Prameter:
    /// `owner`: the address of query balance of
    pub fn balance_of(owner: T::AccountId) -> Option<BalanceOf<T>> {
        return Self::balances(owner);
    }

    /// Return amount of owner allowed to a spender
    ///
    /// Parameters:
    /// `owner`: the address which owns the funds
    /// `spender`: the address which will spend the funds
    pub fn allowance(owner: T::AccountId, spender: T::AccountId) -> Option<BalanceOf<T>> {
        return Self::allowed(owner, spender);
    }

    /// PayRegistry
    /// Calculate pay id
    ///
    /// Parameter:
    /// `pay_hash`: hash of serialized cond_pay
    pub fn calculate_pay_id(pay_hash: T::Hash) -> T::Hash {
        let pay_id = PayRegistry::<T>::calculate_pay_id(pay_hash);
        return pay_id;
    }

    /// Helper
    pub fn valid_signers(
        signatures: Vec<<T as Trait>::Signature>,
        encoded: &[u8],
        signers: Vec<T::AccountId>,
    ) -> Result<(), DispatchError> {
        let signature1 = &signatures[0];
        let signature2 = &signatures[1];
        ensure!(
            (signature1.verify(encoded, &signers[0]) && signature2.verify(encoded, &signers[1]))
                || (signature1.verify(encoded, &signers[1])
                    && signature2.verify(encoded, &signers[0])),
            "Check co-sigs failed"
        );

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

    pub fn zero_hash() -> T::Hash {
        let zero_vec = vec![0 as u8];
        let zero_hash = T::Hashing::hash(&zero_vec);
        return zero_hash;
    }
}

