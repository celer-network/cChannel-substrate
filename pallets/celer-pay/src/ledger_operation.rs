use super::{
    BalanceOf, ChannelMap, ChannelStatusNums, Error, 
    Module as CelerPayModule, RawEvent
};
use crate::traits::Trait;
use crate::celer_wallet::CelerWallet;
use crate::pay_registry::PayRegistry;
use crate::pay_resolver::{AccountAmtPair, TokenInfo, TokenTransfer, TokenType};
use crate::pool::Pool;
use codec::{Decode, Encode};
use frame_support::traits::Currency;
use frame_support::{ensure, storage::StorageMap};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{CheckedAdd, CheckedSub, Hash, Zero};
use sp_runtime::{ModuleId, RuntimeDebug, DispatchError};
use sp_std::{vec, vec::Vec};
use celer_pay_module_rpc_runtime_api::BalanceInfo;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum ChannelStatus {
    Uninitialized = 0,
    Operable = 1,
    Settling = 2,
    Closed = 3,
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PeerState<Hash, BlockNumber, Balance> {
    pub seq_num: u128,
    pub transfer_out: Balance,
    pub next_pay_id_list_hash: Option<Hash>,
    pub last_pay_resolve_deadline: BlockNumber,
    pub pending_pay_out: Balance,
}

pub type PeerStateOf<T> =
    PeerState<<T as system::Trait>::Hash, <T as system::Trait>::BlockNumber, BalanceOf<T>>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PeerProfile<AccountId, Balance, BlockNumber, Hash> {
    pub peer_addr: AccountId,
    pub deposit: Balance,
    pub withdrawal: Option<Balance>,
    pub state: PeerState<Hash, BlockNumber, Balance>,
}

pub type PeerProfileOf<T> = PeerProfile<
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::Hash,
>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct WithdrawIntent<AccountId, Balance, BlockNumber, Hash> {
    pub receiver: AccountId,
    pub amount: Option<Balance>,
    pub request_time: Option<BlockNumber>,
    pub recipient_channel_id: Option<Hash>,
}

pub type WithdrawIntentOf<T> = WithdrawIntent<
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::Hash,
>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Channel<AccountId, BlockNumber, Balance, Hash> {
    pub balance_limits_enabled: bool,
    pub balance_limits: Option<Balance>,
    pub settle_finalized_time: Option<BlockNumber>,
    pub dispute_timeout: BlockNumber,
    pub token: TokenInfo,
    pub status: ChannelStatus,
    pub peer_profiles: Vec<PeerProfile<AccountId, Balance, BlockNumber, Hash>>,
    pub cooperative_withdraw_seq_num: Option<u128>,
    pub withdraw_intent: WithdrawIntent<AccountId, Balance, BlockNumber, Hash>,
}

pub type ChannelOf<T> = Channel<
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
    <T as system::Trait>::Hash,
>;

// ================================= LedgerOperation =============================
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenDistribution<AccountId, Balance> {
    pub token: TokenInfo,
    pub distribution: Vec<AccountAmtPair<AccountId, Balance>>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PaymentChannelInitializer<AccountId, BlockNumber, Balance> {
    pub balance_limits_enabled: bool,
    pub balance_limits: Option<Balance>,
    pub init_distribution: TokenDistribution<AccountId, Balance>,
    pub open_deadline: BlockNumber,
    pub dispute_timeout: BlockNumber,
    pub msg_value_receiver: u8,
}

pub type PaymentChannelInitializerOf<T> = PaymentChannelInitializer<
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct OpenChannelRequest<AccountId, BlockNumber, Balance, Signature> {
    pub channel_initializer: PaymentChannelInitializer<AccountId, BlockNumber, Balance>,
    pub sigs: Vec<Signature>,
}

pub type OpenChannelRequestOf<T> = OpenChannelRequest<
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PayIdList<Hash> {
    pub pay_ids: Vec<Hash>,
    pub next_list_hash: Option<Hash>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SimplexPaymentChannel<Hash, AccountId, BlockNumber, Balance> {
    pub channel_id: Hash,
    pub peer_from: Option<AccountId>,
    pub seq_num: u128,
    pub transfer_to_peer: Option<TokenTransfer<AccountId, Balance>>,
    pub pending_pay_ids: Option<PayIdList<Hash>>,
    pub last_pay_resolve_deadline: Option<BlockNumber>,
    pub total_pending_amount: Option<Balance>,
}

pub type SimplexPaymentChannelOf<T> = SimplexPaymentChannel<
    <T as system::Trait>::Hash,
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SignedSimplexState<Hash, AccountId, BlockNumber, Balance, Signature> {
    pub simplex_state: SimplexPaymentChannel<Hash, AccountId, BlockNumber, Balance>,
    pub sigs: Vec<Signature>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SignedSimplexStateArray<Hash, AccountId, BlockNumber, Balance, Signature> {
    pub signed_simplex_states: Vec<SignedSimplexState<Hash, AccountId, BlockNumber, Balance, Signature>>,
}

pub type SignedSimplexStateArrayOf<T> = SignedSimplexStateArray<
    <T as system::Trait>::Hash,
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeWithdrawInfo<Hash, BlockNumber, AccountId, Balance> {
    pub channel_id: Hash,
    pub seq_num: u128,
    pub withdraw: AccountAmtPair<AccountId, Balance>,
    pub withdraw_deadline: BlockNumber,
    pub recipient_channel_id: Hash,
}

pub type CooperativeWithdrawInfoOf<T> = CooperativeWithdrawInfo<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeWithdrawRequest<Hash, BlockNumber, AccountId, Balance, Signature> {
    pub withdraw_info: CooperativeWithdrawInfo<Hash, BlockNumber, AccountId, Balance>,
    pub sigs: Vec<Signature>,
}

pub type CooperativeWithdrawRequestOf<T> = CooperativeWithdrawRequest<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeSettleInfo<Hash, BlockNumber, AccountId, Balance> {
    pub channel_id: Hash,
    pub seq_num: u128,
    pub settle_balance: Vec<AccountAmtPair<AccountId, Balance>>,
    pub settle_deadline: BlockNumber,
}

pub type CooperativeSettleInfoOf<T> = CooperativeSettleInfo<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeSettleRequest<Hash, BlockNumber, AccountId, Balance, Signature> {
    pub settle_info: CooperativeSettleInfo<Hash, BlockNumber, AccountId, Balance>,
    pub sigs: Vec<Signature>,
}

pub type CooperativeSettleRequestOf<T> = CooperativeSettleRequest<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

pub const CELER_LEDGER_ID: ModuleId = ModuleId(*b"_ledger_");

pub struct LedgerOperation<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> LedgerOperation<T> {
    // Set the balance limits
    pub fn set_balance_limits(
        origin: T::Origin,
        channel_id: T::Hash,
        limits: BalanceOf<T>,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let mut c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            LedgerOperation::<T>::is_peer(c.clone(), caller) == true,
            "caller is not channel peer"
        );

        <ChannelMap<T>>::mutate(&channel_id, |channel| {
            c.balance_limits = Some(limits);
            *channel = Some(c)
        });

        // Emit SetBalanceLimits event
        CelerPayModule::<T>::deposit_event(RawEvent::SetBalanceLimits(
            channel_id,
            limits
        ));
        Ok(())
    }

    // Disable balance limits
    pub fn disable_balance_limits(
        origin: T::Origin,
        channel_id: T::Hash,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let mut c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            LedgerOperation::<T>::is_peer(c.clone(), caller) == true,
            "caller is not channel peer"
        );

        <ChannelMap<T>>::mutate(&channel_id, |channel| {
            c.balance_limits_enabled = false;
            *channel = Some(c)
        });
        
        // Emit DisableBalanceLimits event
        CelerPayModule::<T>::deposit_event(RawEvent::DisableBalanceLimits(
            channel_id
        ));
        Ok(())
    }

    // Enable balance limits
    pub fn enable_balance_limits(
        origin: T::Origin,
        channel_id: T::Hash,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let mut c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            LedgerOperation::<T>::is_peer(c.clone(), caller) == true,
            "caller is not channel peer"
        );
    
        <ChannelMap<T>>::mutate(&channel_id, |channel| {
            c.balance_limits_enabled = true;
            *channel = Some(c)
        });
        
        // Emit EnableBalanceLimits event
        CelerPayModule::<T>::deposit_event(RawEvent::EnableBalanceLimits(
            channel_id
        ));
        Ok(())
    }

    // Open a state channel through auth withdraw message
    pub fn open_channel(
        origin: T::Origin,
        open_request: OpenChannelRequestOf<T>,
        msg_value: BalanceOf<T>,
    ) -> Result<T::Hash, DispatchError> {
        let caller = ensure_signed(origin.clone())?;
        ensure!(
            <T as Trait>::Currency::free_balance(&caller) >= msg_value,
            "caller does not have enough balances."
        );

        let channel_initializer = open_request.channel_initializer;

        ensure!(
            channel_initializer.init_distribution.distribution.len() == 2,
            "Wrong length",
        );

        ensure!(
            frame_system::Module::<T>::block_number() < channel_initializer.open_deadline,
            "Open deadline passed"
        );

        let token = channel_initializer.init_distribution.token.clone();
        let amounts: Vec<BalanceOf<T>> = vec![
            channel_initializer.init_distribution.distribution[0].amt.clone(),
            channel_initializer.init_distribution.distribution[1].amt.clone(),
        ];

        let mut peer_addrs: Vec<T::AccountId> = vec![];
        match channel_initializer.init_distribution.distribution[0].account.clone() {
            Some(account) => peer_addrs.push(account),
            None => return Err(Error::<T>::PeerNotExist)?,
        };
        match channel_initializer.init_distribution.distribution[1].account.clone() {
            Some(account) => peer_addrs.push(account),
            None => return Err(Error::<T>::PeerNotExist)?,
        };

        // Enforce asceding order of peer's addresses to simplyfy contract code
        ensure!(
            peer_addrs[0] < peer_addrs[1],
            "Peer addrs are not ascending"
        );

        let encoded = encode_channel_initializer::<T>(channel_initializer.clone());
        CelerPayModule::<T>::valid_signers(open_request.sigs, &encoded, peer_addrs.clone())?;

        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        let h = T::Hashing::hash(&encoded);
        let channel_id = CelerWallet::<T>::create_wallet(
            frame_system::RawOrigin::Signed(celer_ledger_account).into(),
            peer_addrs.clone(),
            h
        )?;

        let mut peer_profiles: Vec<PeerProfileOf<T>> = vec![];
        for i in 0..2 {
            peer_profiles.push(PeerProfileOf::<T> {
                peer_addr: peer_addrs[i].clone(),
                deposit: amounts[i],
                withdrawal: None,
                state: default_peer_state::<T>(),
            });
        }

        let channel = ChannelOf::<T> {
            balance_limits_enabled: channel_initializer.balance_limits_enabled,
            balance_limits: channel_initializer.balance_limits,
            settle_finalized_time: None,
            dispute_timeout: channel_initializer.dispute_timeout,
            token: token.clone(),
            status: ChannelStatus::Operable,
            peer_profiles: peer_profiles,
            cooperative_withdraw_seq_num: None,
            withdraw_intent: default_withdraw_intent::<T>(),
        };

        let amt_sum: BalanceOf<T> = amounts[0].checked_add(&amounts[1]).ok_or(Error::<T>::OverFlow)?;
        // if total deposit is 0
        if amt_sum.is_zero() {
            ensure!(msg_value.is_zero(), "msg_value is not 0");

            ChannelMap::<T>::insert(channel_id, channel.clone());

            // Emit OpenChannel event
            CelerPayModule::<T>::deposit_event(RawEvent::OpenChannel(
                channel_id,
                vec![channel.peer_profiles[0].peer_addr.clone(), channel.peer_profiles[1].peer_addr.clone()],
                vec![Zero::zero(), Zero::zero()]
            ));
            return Ok(channel_id);
        }

        // if total deposit is larger than 0
        let balance_limits_enabled = channel_initializer.balance_limits_enabled;
        if balance_limits_enabled {
            let balance_limits = match channel_initializer.balance_limits {
                Some(limits) => limits,
                None => return Err(Error::<T>::BalanceLimitsNotExist)?,
            };

            ensure!(amt_sum <= balance_limits, "Balance exceeds limit");
            
            // Emit EnableBalanceLimits event
            CelerPayModule::<T>::deposit_event(RawEvent::EnableBalanceLimits(
                channel_id,
            ));

            // Emit SetBalanceLimits event
            CelerPayModule::<T>::deposit_event(RawEvent::SetBalanceLimits(
                channel_id,
                balance_limits
            ));
        }

        if token.token_type == TokenType::Celer {
            let msg_value_receiver = channel_initializer.msg_value_receiver as usize;
            ensure!(msg_value == amounts[msg_value_receiver], "amount mismatch");
            if amounts[msg_value_receiver] > Zero::zero() {
                CelerWallet::<T>::deposit_native_token(caller, channel_id, msg_value)?;
            }

            // peer ID of non-msg_value_receiver
            let pid: usize = 1 - msg_value_receiver;
            if amounts[pid] > Zero::zero() {
                let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
                Pool::<T>::transfer_to_celer_wallet_by_ledger(
                    frame_system::RawOrigin::Signed(celer_ledger_account).into(),
                    peer_addrs[pid].clone(),
                    channel_id,
                    amounts[pid],
                )?;
            }
        } else {
            Err(Error::<T>::Error)?
        }

        ChannelMap::<T>::insert(channel_id, channel.clone());
        
        // Emit OpenChannel event
        CelerPayModule::<T>::deposit_event(RawEvent::OpenChannel(
            channel_id,
            vec![channel.peer_profiles[0].peer_addr.clone(), channel.peer_profiles[1].peer_addr.clone()],
            vec![channel.peer_profiles[0].deposit, channel.peer_profiles[1].deposit]
        ));
        return Ok(channel_id);
    }

    // Deposit native token into the channel
    pub fn deposit(
        origin: T::Origin,
        channel_id: T::Hash,
        receiver: T::AccountId,
        msg_value: BalanceOf<T>,
        transfer_from_amount: BalanceOf<T>,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin.clone())?;
        let c: ChannelOf<T> = match ChannelMap::<T>::get(&channel_id) {
            Some(channel) => channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            <T as Trait>::Currency::free_balance(&caller) >= msg_value,
            "caller does not have enough balances."
        );
        let deposit_amount: BalanceOf<T> = msg_value.checked_add(&transfer_from_amount).ok_or(Error::<T>::OverFlow)?;
        add_deposit::<T>(channel_id, receiver.clone(), deposit_amount)?;

        if c.token.token_type == TokenType::Celer {
            if msg_value > Zero::zero() {
                CelerWallet::<T>::deposit_native_token(caller.clone(), channel_id, msg_value)?;
            }
            let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
            if transfer_from_amount > Zero::zero() {
                Pool::<T>::transfer_to_celer_wallet_by_ledger(
                    frame_system::RawOrigin::Signed(celer_ledger_account).into(),
                    caller,
                    channel_id,
                    transfer_from_amount,
                )?;
            }
        } else {
            Err(Error::<T>::Error)?
        }

        Ok(())
    }

    // Strore signed simplex states on-chain as checkpoints
    pub fn snapshot_states(
        signed_simplex_state_array: SignedSimplexStateArrayOf<T>,
    ) -> Result<(), DispatchError> {
        // snapshot each state
        let mut simplex_state = signed_simplex_state_array.signed_simplex_states[0].simplex_state.clone();
        let state_len = signed_simplex_state_array.signed_simplex_states.len();
        for i in 0..state_len {
            let current_channel_id: T::Hash = simplex_state.channel_id;
            let mut c: ChannelOf<T> = match ChannelMap::<T>::get(&current_channel_id) {
                Some(channel) => channel,
                None => Err(Error::<T>::ChannelNotExist)?,
            };

            ensure!(c.status == ChannelStatus::Operable, "Channel status error");

            // Check whether simplex_state contains all data
            check_simplex_state::<T>(simplex_state.clone())?;
            // Check Co-Signatures.
            let encoded = encode_simplex_state::<T>(simplex_state.clone());
            let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
            let channel_peer = vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ];
            CelerPayModule::<T>::valid_signers(sigs, &encoded, channel_peer)?;

            let pid = get_peer_id::<T>(c.clone(), simplex_state.peer_from.clone().unwrap())?;

            ensure!(simplex_state.seq_num > c.peer_profiles[pid].state.seq_num, "seq_num error");

            // No need to update nextPayIdListHash and lastPayResolveDeadline for snapshot purpose
            ChannelMap::<T>::mutate(&current_channel_id, |channel| {
                c.peer_profiles[pid].state.seq_num = simplex_state.seq_num;
                c.peer_profiles[pid].state.transfer_out = simplex_state.transfer_to_peer.as_ref().unwrap().receiver.amt;
                c.peer_profiles[pid].state.pending_pay_out = simplex_state.total_pending_amount.unwrap_or(Zero::zero());
                *channel = Some(c)
            });

            if i == state_len.checked_sub(1).ok_or(Error::<T>::UnderFlow)? {
                let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                CelerPayModule::<T>::deposit_event(RawEvent::SnapshotStates(
                    current_channel_id,
                    seq_nums,
                ));
            } else if i < state_len.checked_sub(1).ok_or(Error::<T>::UnderFlow)? {
                simplex_state = signed_simplex_state_array.signed_simplex_states[i + 1].simplex_state.clone();
                // enforce channel_ids of simplex states are ascending
                ensure!(
                    current_channel_id <= simplex_state.channel_id,
                    "Non-ascending channelIds"
                );
                if current_channel_id < simplex_state.channel_id {
                    let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                    CelerPayModule::<T>::deposit_event(RawEvent::SnapshotStates(
                        current_channel_id,
                        seq_nums,
                    ));
                }
            } else {
                Err(Error::<T>::Error)?
            }
        }

        Ok(())
    }

    // Intend to withdraw funds from channel.
    pub fn intend_withdraw(
        origin: T::Origin,
        channel_id: T::Hash,
        amount: BalanceOf<T>,
        recipient_channel_id: T::Hash,
    ) -> Result<(T::Hash, T::AccountId, BalanceOf<T>), DispatchError> {
        let receiver = ensure_signed(origin)?;
        let mut c: ChannelOf<T> = match ChannelMap::<T>::get(channel_id) {
            Some(channel) => channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };

        ensure!(c.status == ChannelStatus::Operable, "Channel status error");

        // withdraw_intent.receiver is ledger address if and  only if there is no pending withdraw_intent.
        // because withdraw_intent.receiver may only be set as caller address which can't be ledger address.
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(
            c.withdraw_intent.receiver == celer_ledger_account,
            "Pending withdraw intent exists"
        );

        ensure!(
            Self::is_peer(c.clone(), receiver.clone()),
            "Receirver is not channel peer."
        );

        ChannelMap::<T>::mutate(&channel_id, |channel| {
            c.withdraw_intent = WithdrawIntentOf::<T> {
                receiver: receiver.clone(),
                amount: Some(amount),
                request_time: Some(frame_system::Module::<T>::block_number()),
                recipient_channel_id: Some(recipient_channel_id),
            };
            *channel = Some(c)
        });

        // Emit IntendWithdraw event
        CelerPayModule::<T>::deposit_event(RawEvent::IntendWithdraw(
            channel_id,
            receiver.clone(),
            amount
        ));
        return Ok((channel_id, receiver, amount));
    }

    // Confirm channel withdrawal
    pub fn confirm_withdraw(
        channel_id: T::Hash,
    ) -> Result<(BalanceOf<T>, T::AccountId, T::Hash), DispatchError> {
        let mut c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(c.status == ChannelStatus::Operable, "Channel status error");
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(
            c.withdraw_intent.receiver != celer_ledger_account,
            "No pending withdraw intent"
        );

        let dispute_timeout = c.withdraw_intent.request_time.unwrap_or(Zero::zero())
                .checked_add(&c.dispute_timeout).ok_or(Error::<T>::OverFlow)?;
        let block_number = frame_system::Module::<T>::block_number();
        ensure!(block_number >= dispute_timeout, "Dispute not timeout");

        let zero_channel_id: T::Hash = CelerPayModule::<T>::get_zero_hash();
        let receiver = c.clone().withdraw_intent.receiver;
        let amount = c.clone().withdraw_intent.amount.unwrap_or(Zero::zero());
        let recipient_channel_id = c.withdraw_intent.recipient_channel_id.unwrap_or(zero_channel_id);
        let rid = get_peer_id::<T>(c.clone(), receiver.clone())?;

        // check withdraw limit
        let mut withdraw_limit: BalanceOf<T> = Zero::zero();
        if rid == 0 {
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[0].deposit).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[1].state.transfer_out).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[0].clone().withdrawal.unwrap_or(Zero::zero())).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[0].state.transfer_out).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[0].state.pending_pay_out).ok_or(Error::<T>::UnderFlow)?;
        } else {
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[1].deposit).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[0].state.transfer_out).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[1].clone().withdrawal.unwrap_or(Zero::zero())).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[1].state.transfer_out).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[1].state.pending_pay_out).ok_or(Error::<T>::UnderFlow)?;
        }
        ensure!(amount <= withdraw_limit, "Exceed withdraw limit");

        // Update record of one peer's withdrawal amount
        let new_amount: BalanceOf<T> = c.peer_profiles[rid as usize].clone().withdrawal.unwrap_or(Zero::zero())
                 .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        ChannelMap::<T>::mutate(&channel_id, |channel| {
            // Update record of one peer's withdrawal amount
            c.peer_profiles[rid].withdrawal = Some(new_amount);
            // Initialize c.wihdraw_intent
            c.withdraw_intent = default_withdraw_intent::<T>();
            *channel = Some(c.clone())
        });

        withdraw_funds::<T>(
            c,
            channel_id,
            receiver.clone(),
            amount,
            recipient_channel_id,
        )?;
        
        let (_, deposits, withdrawals): (Vec<T::AccountId>, Vec<BalanceInfo<BalanceOf<T>>>, Vec<BalanceInfo<BalanceOf<T>>>)
            = CelerPayModule::<T>::get_balance_map(channel_id);
        // Emit Confirmwithdraw event
        CelerPayModule::<T>::deposit_event(RawEvent::ConfirmWithdraw(
            channel_id,
            amount,
            receiver.clone(),
            recipient_channel_id,
            vec![deposits[0].amount, deposits[1].amount],
            vec![withdrawals[0].amount, withdrawals[1].amount]
        ));
        return Ok((amount, receiver, recipient_channel_id));
    }

    // Veto current withdrawal intent
    pub fn veto_withdraw(origin: T::Origin, channel_id: T::Hash) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;

        let mut c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(c.status == ChannelStatus::Operable, "Channel status error");

        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(c.withdraw_intent.receiver != celer_ledger_account, "No pending withdraw intent");
        ensure!(Self::is_peer(c.clone(), caller), "caller is not peer");

        ChannelMap::<T>::mutate(&channel_id, |channel| {
            // Initialize c.wihdraw_intent
            c.withdraw_intent = default_withdraw_intent::<T>();
            *channel = Some(c)
        });

        // Emit VetoWithdraw event
        CelerPayModule::<T>::deposit_event(RawEvent::VetoWithdraw(
            channel_id
        ));
        Ok(())
    }

    // Cooperatively withdraw specific amount of balance
    pub fn cooperative_withdraw(
        cooperative_withdraw_request: CooperativeWithdrawRequestOf<T>,
    ) -> Result<(T::Hash, BalanceOf<T>, T::AccountId, T::Hash, u128), DispatchError> {
        let withdraw_info = cooperative_withdraw_request.withdraw_info;
        let channel_id = withdraw_info.channel_id;
        let recipient_channel_id = withdraw_info.recipient_channel_id;

        let mut c = match ChannelMap::<T>::get(channel_id) {
            Some(channel) => channel,
            None => return Err(Error::<T>::ChannelNotExist)?,
        };

        ensure!(c.status == ChannelStatus::Operable, "Channel status error");

        // check signatures.
        let encoded = encode_withdraw_info::<T>(withdraw_info.clone());
        let signers = vec![
            c.peer_profiles[0].peer_addr.clone(),
            c.peer_profiles[1].peer_addr.clone(),
        ];
        CelerPayModule::<T>::valid_signers(cooperative_withdraw_request.sigs, &encoded, signers)?;

        // require an increment of exactly 1 for seq_num of each cooperative withdraw request
        let cal_seq = withdraw_info.seq_num
                .checked_sub(c.cooperative_withdraw_seq_num.unwrap_or(0)).ok_or(Error::<T>::UnderFlow)?;
        ensure!(cal_seq == 1, "seqNum error");
        ensure!(
            frame_system::Module::<T>::block_number() <= withdraw_info.withdraw_deadline,
            "Withdraw deadline passed"
        );

        let receiver = withdraw_info.clone().withdraw.account.unwrap();
        let amount = withdraw_info.withdraw.amt;

        let rid = get_peer_id::<T>(c.clone(), receiver.clone())?;

        let new_withdrawal_amount = c.peer_profiles[rid].clone().withdrawal.unwrap_or(Zero::zero())
                .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        ChannelMap::<T>::mutate(&channel_id, |channel| {
            c.peer_profiles[rid].withdrawal = Some(new_withdrawal_amount);
            c.cooperative_withdraw_seq_num = Some(withdraw_info.seq_num);
            *channel = Some(c.clone())
        });

        withdraw_funds::<T>(
            c,
            channel_id,
            receiver.clone(),
            amount,
            recipient_channel_id,
        )?;       

        let (_, deposits, withdrawals): (Vec<T::AccountId>, Vec<BalanceInfo<BalanceOf<T>>>, Vec<BalanceInfo<BalanceOf<T>>>)
            = CelerPayModule::<T>::get_balance_map(channel_id);
        // Emit CooperativeWithdraw event
        CelerPayModule::<T>::deposit_event(RawEvent::CooperativeWithdraw(
            channel_id,
            amount,
            receiver.clone(),
            recipient_channel_id,
            vec![deposits[0].amount, deposits[1].amount],
            vec![withdrawals[0].amount, withdrawals[1].amount],
            withdraw_info.seq_num
        ));

        return Ok((
            channel_id,
            amount,
            receiver,
            recipient_channel_id,
            withdraw_info.seq_num,
        ));
    }

    // Intend to settle channel(s) with an array of signed simplex states
    pub fn intend_settle(
        origin: T::Origin,
        signed_simplex_state_array: SignedSimplexStateArrayOf<T>,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;

        let state_len = signed_simplex_state_array.signed_simplex_states.len();
        let mut simplex_state = signed_simplex_state_array.signed_simplex_states[0].simplex_state.clone();
        for i in 0..state_len {
            let current_channel_id = simplex_state.channel_id;
            let mut c: ChannelOf<T> = match ChannelMap::<T>::get(&current_channel_id) {
                Some(channel) => channel,
                None => Err(Error::<T>::ChannelNotExist)?,
            };

            if Self::is_peer(c.clone(), caller.clone()) {
                ensure!(
                    c.status == ChannelStatus::Operable || c.status == ChannelStatus::Settling,
                    "Peer channel status error"
                );
            } else {
                // A nonpeer cannot be the first one to call intend_settle
                ensure!(
                    c.status == ChannelStatus::Settling,
                    "Nonpeer channel status error"
                );
            }

            ensure!(
                c.settle_finalized_time.unwrap_or(Zero::zero()).is_zero()
                    || frame_system::Module::<T>::block_number() < c.settle_finalized_time.unwrap(),
                "Settle has already finalized"
            );

            if simplex_state.seq_num > 0 {
                // Check whether simplex_state contains all data
                check_simplex_state::<T>(simplex_state.clone())?;
                // Check signatures
                let encoded = encode_simplex_state::<T>(simplex_state.clone());
                let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
                let channel_peer = vec![
                    c.peer_profiles[0].peer_addr.clone(),
                    c.peer_profiles[1].peer_addr.clone(),
                ];
                CelerPayModule::<T>::valid_signers(sigs, &encoded, channel_peer)?;

                let pid = get_peer_id::<T>(c.clone(), simplex_state.peer_from.clone().unwrap())?;

                // Ensure each state can be intend_settle at most once
                if c.status == ChannelStatus::Operable {
                    ensure!(simplex_state.seq_num >= c.peer_profiles[pid].state.seq_num, "seqNum error");
                } else if c.status == ChannelStatus::Settling {
                    ensure!(simplex_state.seq_num > c.peer_profiles[pid].state.seq_num, "seqNum error");
                } else {
                    Err(Error::<T>::Error)?
                }

                let zero_hash = CelerPayModule::<T>::get_zero_hash();
                let next_pay_id_list_hash = simplex_state.pending_pay_ids.clone().unwrap().next_list_hash.unwrap_or(zero_hash);
                
                if next_pay_id_list_hash == zero_hash {
                    // Update simplex_state-dependent fields
                    c.peer_profiles[pid].state.seq_num = simplex_state.seq_num;
                    c.peer_profiles[pid].state.transfer_out = simplex_state.transfer_to_peer.as_ref().unwrap().receiver.amt.clone();
                    c.peer_profiles[pid].state.next_pay_id_list_hash = None;
                    c.peer_profiles[pid].state.last_pay_resolve_deadline = simplex_state.last_pay_resolve_deadline.unwrap_or(Zero::zero()).clone();
                } else {
                    // Update simplex_state-dependent fields
                    c.peer_profiles[pid].state.seq_num = simplex_state.seq_num;
                    c.peer_profiles[pid].state.transfer_out = simplex_state.transfer_to_peer.as_ref().unwrap().receiver.amt.clone();
                    c.peer_profiles[pid].state.next_pay_id_list_hash = Some(next_pay_id_list_hash);
                    c.peer_profiles[pid].state.last_pay_resolve_deadline = simplex_state.last_pay_resolve_deadline.unwrap_or(Zero::zero()).clone();
                    c.peer_profiles[pid].state.pending_pay_out = simplex_state.total_pending_amount.clone().unwrap_or(Zero::zero());
                }
            
                _clear_pays::<T>(
                    c,
                    current_channel_id,
                    pid,
                    simplex_state.pending_pay_ids.clone().unwrap(),
                )?;
            } else if simplex_state.seq_num == 0 {
                // null state
                // Check signautre
                let encoded = encode_simplex_null_state::<T>(
                    simplex_state.clone()
                );
                let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
                CelerPayModule::<T>::check_single_signature(sigs[0].clone(), &encoded, c.peer_profiles[0].peer_addr.clone())?;
                
                // This implies both stored seq_nums are 0
                ensure!(
                    c.settle_finalized_time.unwrap_or(Zero::zero()).is_zero(),
                    "intend_settle before"
                );
                ensure!(sigs.len() == 1, "Invalid signatures length");
            } else {
                Err(Error::<T>::Error)?
            }

            if i == state_len - 1 {
                update_overall_states_by_intend_state::<T>(current_channel_id.clone())?;
            } else if i < state_len - 1 {
                simplex_state = signed_simplex_state_array.signed_simplex_states[i + 1].simplex_state.clone();
                ensure!(
                    current_channel_id <= simplex_state.channel_id,
                    "Non-ascending channedIds"
                );
                if current_channel_id < simplex_state.channel_id {
                    update_overall_states_by_intend_state::<T>(current_channel_id.clone())?;
                }
            } else {
                Err(Error::<T>::Error)?
            }
        }

        Ok(())
    }

    // Read payment results and add results to correspond simplex payment channel
    pub fn clear_pays(
        channel_id: T::Hash,
        peer_from: T::AccountId,
        pay_id_list: PayIdList<T::Hash>,
    ) -> Result<(), DispatchError> {
        let mut c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(c.status == ChannelStatus::Settling, "Channel status error");

        let mut encoded: Vec<u8> = vec![];
        pay_id_list.pay_ids.clone().into_iter().for_each(|pay_id| {
            encoded.extend(pay_id.encode());
        });
        encoded.extend(pay_id_list.next_list_hash.encode());
        let list_hash = T::Hashing::hash(&encoded);

        let pid = get_peer_id::<T>(c.clone(), peer_from)?;
        let state = c.peer_profiles[pid].state.clone();

        let zero_hash = CelerPayModule::<T>::get_zero_hash();
        let next_pay_id_list_hash = state.next_pay_id_list_hash.unwrap_or(zero_hash);
        if next_pay_id_list_hash != zero_hash {
            ensure!(next_pay_id_list_hash == list_hash, "List hash mismatch");
        }
        
        // Update next_pay_id_list_hash
        c.peer_profiles[pid].state.next_pay_id_list_hash = pay_id_list.next_list_hash;
        _clear_pays::<T>(c, channel_id, pid, pay_id_list)?;

        Ok(())
    }

    // confirm channel settlement
    pub fn confirm_settle(
        channel_id: T::Hash,
    ) -> Result<(T::Hash, Vec<BalanceOf<T>>), DispatchError> {
        let c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        
        let block_number = frame_system::Module::<T>::block_number();
        ensure!(c.status == ChannelStatus::Settling, "Channel status error");

        // require no new intend_settle can be called
        ensure!(
            block_number >= c.settle_finalized_time.unwrap_or(Zero::zero()),
            "Settle is not finalized"
        );

        // require channel status of current intend_settle has been finalized,
        // namely all payment have already been either cleared or expired
        // Note: this last PayResolveDeadline should use
        //      (the actual last resolve deadline of all pays + clear_pays safe margin)
        //      to ensure that peers have enough time to clear_pays before confirm_settle.
        //      However this only matters if there are multiple blocks of pending pay list
        //      i.e. the next_pay_id_list_hash after intend_settle is not zero_hash (defined in get_zero_hash()).
        // TODO: add an additonal clear_safe_margin param or change the semantics of
        // last_pay_resolve_deadline to also include clear_pays safe margin and rename it.
        let state_0 = c.peer_profiles[0].state.clone();
        let state_1 = c.peer_profiles[1].state.clone();
        let zero_hash = CelerPayModule::<T>::get_zero_hash();

        ensure!(
            (state_0.next_pay_id_list_hash.unwrap_or(zero_hash) == zero_hash
                || block_number > state_0.last_pay_resolve_deadline)
                && (state_1.next_pay_id_list_hash.unwrap_or(zero_hash) == zero_hash
                    || block_number > state_1.last_pay_resolve_deadline),
            "Payments are not finalized"
        );

        let (valid_balance, settle_balance): (bool, Vec<BalanceOf<T>>) =
            validate_settle_balance::<T>(c.clone())?;

        if valid_balance == false {
            reset_duplex_state::<T>(c.clone(), channel_id)?;
            CelerPayModule::<T>::deposit_event(RawEvent::ConfirmSettleFail(channel_id));
            Err(Error::<T>::ConfirmSettleFail)?
        }

        update_channel_status::<T>(c.clone(), channel_id, ChannelStatus::Closed)?;

        // Withdrawal from Contracts pattern is needles here,
        // because peers need sign messages which implies that they cannot be contracts
        batch_transfer_out::<T>(
            channel_id,
            vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ],
            settle_balance.clone(),
        )?;

        // Emit ConfirmSettle event
        CelerPayModule::<T>::deposit_event(RawEvent::ConfirmSettle(
            channel_id,
            settle_balance.clone()
        ));
        return Ok((channel_id, settle_balance));
    }

    // Cooperatively settle the channel
    pub fn cooperative_settle(
        settle_request: CooperativeSettleRequestOf<T>,
    ) -> Result<(T::Hash, Vec<BalanceOf<T>>), DispatchError> {
        let settle_info = settle_request.settle_info;
        let channel_id = settle_info.channel_id;
        let c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            c.status == ChannelStatus::Operable || c.status == ChannelStatus::Settling,
            "Channel status error"
        );

        // Check whether cooperative settle info contains all data
        check_settle_info::<T>(settle_info.clone())?;
        // Check co-signature
        let encoded = encode_settle_info::<T>(settle_info.clone());
        let signers = vec![
            settle_info.settle_balance[0].account.clone().unwrap(),
            settle_info.settle_balance[1].account.clone().unwrap(),
        ];
        CelerPayModule::<T>::valid_signers(settle_request.sigs, &encoded, signers)?;

        let state_0 = c.peer_profiles[0].state.clone();
        let state_1 = c.peer_profiles[1].state.clone();

        ensure!(
            settle_info.seq_num > state_0.seq_num && settle_info.seq_num > state_1.seq_num,
            "seq_num error"
        );
        ensure!(
            settle_info.settle_balance[0].clone().account.unwrap() == c.peer_profiles[0].peer_addr
                && settle_info.settle_balance[1].clone().account.unwrap() == c.peer_profiles[1].peer_addr,
            "Settle accounts mismatch"
        );

        let settle_balance = vec![
            settle_info.settle_balance[0].amt,
            settle_info.settle_balance[1].amt,
        ];
        let total_settle_balance = settle_balance[0]
                .checked_add(&settle_balance[1]).ok_or(Error::<T>::OverFlow)?;
        let total_balance = get_total_balance::<T>(channel_id)?;
        ensure!(
            total_settle_balance == total_balance,
            "Balance sum mismatch"
        );

        update_channel_status::<T>(c.clone(), channel_id, ChannelStatus::Closed)?;

        batch_transfer_out::<T>(
            channel_id, 
            vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()], 
            settle_balance.clone()
        )?;

        // Emit CooperativeSettle event
        CelerPayModule::<T>::deposit_event(RawEvent::CooperativeSettle(
            channel_id,
            settle_balance.clone()
        ));
        return Ok((channel_id, settle_balance));
    }

    // Check if addr is one of the peers in channel c
    pub fn is_peer(c: ChannelOf<T>, addr: T::AccountId) -> bool {
        return addr == c.peer_profiles[0].peer_addr || addr == c.peer_profiles[1].peer_addr;
    }
}

fn default_peer_state<T: Trait>() -> PeerStateOf<T> {
    PeerStateOf::<T> {
        seq_num: 0,
        transfer_out: Zero::zero(),
        next_pay_id_list_hash: None,
        last_pay_resolve_deadline: Zero::zero(),
        pending_pay_out: Zero::zero()
    }
}

fn default_withdraw_intent<T: Trait>() -> WithdrawIntentOf<T> {
    WithdrawIntentOf::<T> {
        receiver: CelerPayModule::<T>::get_celer_ledger_id(),
        amount: None,
        request_time: None,
        recipient_channel_id: None,
    }
}

// get peer's ID
fn get_peer_id<T: Trait>(
    c: ChannelOf<T>, 
    peer: T::AccountId
) -> Result<usize, DispatchError> {
    if c.peer_profiles[0].peer_addr == peer {
        Ok(0 as usize)
    } else if c.peer_profiles[1].peer_addr == peer {
        Ok(1 as usize)
    } else {
        Err(Error::<T>::NotChannelPeer)?
    }
}

fn get_total_balance<T: Trait>(
    channel_id: T::Hash
) -> Result<BalanceOf<T>, DispatchError> {
    let c = match ChannelMap::<T>::get(&channel_id) {
        Some(_channel) => _channel,
        None => Err(Error::<T>::ChannelNotExist)?,
    };
    let mut balance: BalanceOf<T> = c.peer_profiles[0].deposit;
    balance = balance.checked_add(&c.peer_profiles[1].deposit)
        .ok_or(Error::<T>::OverFlow)?;
    balance = balance.checked_sub(&c.peer_profiles[0].clone().withdrawal.unwrap_or(Zero::zero()))
        .ok_or(Error::<T>::UnderFlow)?;
    balance = balance.checked_sub(&c.peer_profiles[1].clone().withdrawal.unwrap_or(Zero::zero()))
        .ok_or(Error::<T>::UnderFlow)?;
    return Ok(balance);
}

// Internal function to add deposit of a channel
fn add_deposit<T: Trait>(
    channel_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    let mut c: ChannelOf<T> = match ChannelMap::<T>::get(&channel_id) {
        Some(channel) => channel,
        None => Err(Error::<T>::ChannelNotExist)?,
    };
    ensure!(c.status == ChannelStatus::Operable, "Channel status errror");

    if c.balance_limits_enabled == true {
        let total_balance = get_total_balance::<T>(channel_id.clone())?;
        let added_amount = amount.checked_add(&total_balance).ok_or(Error::<T>::OverFlow)?;
        let limits = match c.balance_limits {
            Some(limits) => limits,
            None => Err(Error::<T>::BalanceLimitsNotExist)?,
        };
        ensure!(added_amount <= limits, "Balance exceeds limit");
    }

    let rid = get_peer_id::<T>(c.clone(), receiver.clone())?;

    let new_deposit_balance = c.peer_profiles[rid].deposit.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
    c.peer_profiles[rid].deposit = new_deposit_balance;
    ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c.clone()));
    
    // Emit Deposit event
    CelerPayModule::<T>::deposit_event(RawEvent::DepositToChannel(
        channel_id,
        vec![
            c.peer_profiles[0].peer_addr.clone(),
            c.peer_profiles[1].peer_addr.clone(),
        ],
        vec![
            c.peer_profiles[0].deposit,
            c.peer_profiles[1].deposit,
        ],
        vec![
            c.peer_profiles[0].clone().withdrawal.unwrap_or(Zero::zero()),
            c.peer_profiles[1].clone().withdrawal.unwrap_or(Zero::zero()),
        ],
    ));

    Ok(())
}

// Internal function to transfer funds out in batch
fn batch_transfer_out<T: Trait>(
    channel_id: T::Hash,
    receivers: Vec<T::AccountId>,
    amounts: Vec<BalanceOf<T>>,
) -> Result<(), DispatchError> {
    let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
    for i in 0..2 {
        if amounts[i] == Zero::zero() {
            continue;
        }
        CelerWallet::<T>::withdraw(
            frame_system::RawOrigin::Signed(celer_ledger_account.clone()).into(),
            channel_id, 
            receivers[i].clone(), 
            amounts[i]
        )?;
    }

    Ok(())
}

// Internal functions to withdraw funds out of the channel
fn withdraw_funds<T: Trait>(
    c: ChannelOf<T>,
    channel_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>,
    recipient_channel_id: T::Hash,
) -> Result<(), DispatchError> {
    if amount == Zero::zero() {
        return Ok(());
    }

    let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
    let zero_channel_id: T::Hash = CelerPayModule::<T>::get_zero_hash();
    if recipient_channel_id == zero_channel_id {
        CelerWallet::<T>::withdraw(
            frame_system::RawOrigin::Signed(celer_ledger_account).into(),
            channel_id, 
            receiver,
            amount,
        )?;
    } else {
        let recipient_channel = ChannelMap::<T>::get(recipient_channel_id).unwrap();
        ensure!(
            c.token.token_type == recipient_channel.token.token_type,
            "Token mismatch of recipient channel"
        );
        add_deposit::<T>(recipient_channel_id, receiver.clone(), amount)?;

        // move funds from one channel's wallet to another channel's wallet
        CelerWallet::<T>::transfer_to_wallet(
            frame_system::RawOrigin::Signed(celer_ledger_account).into(),
            channel_id, 
            recipient_channel_id, 
            receiver, 
            amount
        )?;
    }

    Ok(())
}

// Reset the state of the channel
fn reset_duplex_state<T: Trait>(mut c: ChannelOf<T>, channel_id: T::Hash) -> Result<(), DispatchError> {
    // initialize settle_finalized_time
    c.settle_finalized_time = None;

    update_channel_status::<T>(c.clone(), channel_id, ChannelStatus::Operable)?;
    
    // initialize peer_state
    c.peer_profiles[0].state = default_peer_state::<T>();
    c.peer_profiles[1].state = default_peer_state::<T>();
    
    // reset possibly remaining WithdrawIntent freezed by previous intendSettle()
    c.withdraw_intent = default_withdraw_intent::<T>();

    ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c));

    Ok(())
}

// Clear payments by their hash array
fn _clear_pays<T: Trait>(
    mut c: ChannelOf<T>,
    channel_id: T::Hash,
    pid: usize,
    pay_id_list: PayIdList<T::Hash>,
) -> Result<(), DispatchError> { 
    let state = c.peer_profiles[pid].state.clone();
    let out_amts = PayRegistry::<T>::get_pay_amounts(
        pay_id_list.pay_ids.clone(),
        state.last_pay_resolve_deadline,
    )?;
    let mut total_amt_out: BalanceOf<T> = Zero::zero();
    for i in 0..out_amts.len() {
        total_amt_out = total_amt_out.checked_add(&out_amts[i])
            .ok_or(Error::<T>::OverFlow)?;
        // Emit ClearOnePay event
        CelerPayModule::<T>::deposit_event(RawEvent::ClearOnePay(
            channel_id,
            pay_id_list.pay_ids[i].clone(),
            c.peer_profiles[pid].clone().peer_addr,
            out_amts[i],
        ));
    }

    // updating pending_pay_out is only needed when migrating ledger during settling phrase,
    // which will affect the withdraw limit after the migration.
    let new_transfer_out = state.transfer_out.checked_add(&total_amt_out).ok_or(Error::<T>::OverFlow)?;
    let zero_hash = CelerPayModule::<T>::get_zero_hash();
    if pay_id_list.next_list_hash.unwrap_or(zero_hash) == zero_hash {
        // if there are not more uncleared pays in this state, the pending_pay_out must be 0
        ChannelMap::<T>::mutate(&channel_id, |channel| {
            c.peer_profiles[pid].state.transfer_out = new_transfer_out;
            c.peer_profiles[pid].state.pending_pay_out = Zero::zero();
            *channel = Some(c)
        });
    } else {
        // Note: if there are more uncleared pays in this state, because resolved pay amount
        //      is always less than or equal to the corresponding maximum amount counted in
        //      pending_pay_out, the updated pending_pay_out may be equal to or larger than the real
        //      pending_pay_out. This will lead to decreasing the maximum withdraw amount (withdraw_limit)
        //      from potentially maliciout non-cooperative withdraw.
        let new_pending_pay_out = state.pending_pay_out.checked_sub(&total_amt_out).ok_or(Error::<T>::OverFlow)?;
        ChannelMap::<T>::mutate(&channel_id, |channel| {
            c.peer_profiles[pid].state.transfer_out = new_transfer_out;
            c.peer_profiles[pid].state.pending_pay_out = new_pending_pay_out;
            *channel = Some(c)
        });
    }

    Ok(())
}

/// Update overall states of a duplex channel
fn update_overall_states_by_intend_state<T: Trait>(
    channel_id: T::Hash,
) -> Result<(), DispatchError> {
    let mut c = match ChannelMap::<T>::get(channel_id) {
        Some(channel) => channel,
        None => Err(Error::<T>::NotChannelPeer)?,
    };

    let new_setttle_finalized_time: T::BlockNumber = frame_system::Module::<T>::block_number()
            .checked_add(&c.dispute_timeout).ok_or(Error::<T>::OverFlow)?;
    ChannelMap::<T>::mutate(channel_id, |channel| {
        c.settle_finalized_time = Some(new_setttle_finalized_time);
        *channel = Some(c.clone())
    });
    update_channel_status::<T>(c, channel_id, ChannelStatus::Settling)?;

    let seq_nums = get_state_seq_nums::<T>(channel_id);
    // Emit IntendSettle event
    CelerPayModule::<T>::deposit_event(RawEvent::IntendSettle(channel_id, seq_nums));

    Ok(())
}

/// Update status of a channel
fn update_channel_status<T: Trait>(
    mut c: ChannelOf<T>,
    channel_id: T::Hash,
    new_status: ChannelStatus,
) -> Result<(), DispatchError> {
    // If status is new status, return.
    if c.status == new_status {
        return Ok(());
    }

    // update counter of old status
    if c.status != ChannelStatus::Uninitialized {
        let status_nums;
        status_nums = match CelerPayModule::<T>::channel_status_nums(c.status.clone() as u8) {
            Some(num) => num as u8,
            None => 0 as u8,
        };

        let nums: u8;
        if status_nums == 0 {
            nums = 0;
        } else {
            nums = status_nums - 1;
        }
        ChannelStatusNums::mutate(c.status.clone() as u8, |num| *num = Some(nums));
    }

    ChannelStatusNums::mutate(new_status.clone() as u8, |num| {
        let new_status_nums = match CelerPayModule::<T>::channel_status_nums(new_status.clone() as u8) {
            Some(num) => num as u8,
            None => 0 as u8,
        };
        *num = Some(new_status_nums + 1)
    });

    ChannelMap::<T>::mutate(channel_id, |channel| {
        c.status = new_status;
        *channel = Some(c)
    });

    Ok(())
}

// Validate channel final balance
fn validate_settle_balance<T: Trait>(
    c: ChannelOf<T>,
) -> Result<(bool, Vec<BalanceOf<T>>), DispatchError> {
    let mut settle_balance: Vec<BalanceOf<T>> = vec![
        c.peer_profiles[0].deposit.checked_add(&c.peer_profiles[1].clone().state.transfer_out).ok_or(Error::<T>::OverFlow)?,
        c.peer_profiles[1].deposit.checked_add(&c.peer_profiles[0].clone().state.transfer_out).ok_or(Error::<T>::OverFlow)?,
    ];

    for i in 0..2 {
        let sub_amt = c.peer_profiles[i as usize].clone().state.transfer_out
                .checked_add(&c.peer_profiles[i as usize].withdrawal.unwrap_or(Zero::zero())).ok_or(Error::<T>::OverFlow)?;
        if settle_balance[i as usize] < sub_amt {
            return Ok((false, vec![Zero::zero(), Zero::zero()]));
        }

        settle_balance[i as usize] = settle_balance[i as usize]
            .checked_sub(&sub_amt).ok_or(Error::<T>::UnderFlow)?;
    }

    return Ok((true, settle_balance));
}

/// Get the seqNums of two simplex channel states
fn get_state_seq_nums<T: Trait>(channel_id: T::Hash) -> Vec<u128> {
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    return vec![
        c.peer_profiles[0].clone().state.seq_num,
        c.peer_profiles[1].state.seq_num
    ];
}

pub fn encode_channel_initializer<T: Trait>(
    channel_initializer: PaymentChannelInitializerOf<T>,
) -> Vec<u8> {
    let mut encoded = channel_initializer.balance_limits_enabled.encode();
    encoded.extend(channel_initializer.balance_limits.encode());
    encoded.extend(channel_initializer.init_distribution.token.token_type.encode());
    encoded.extend(channel_initializer.init_distribution.distribution[0].account.encode());
    encoded.extend(channel_initializer.init_distribution.distribution[0].amt.encode());
    encoded.extend(channel_initializer.init_distribution.distribution[1].account.encode());
    encoded.extend(channel_initializer.init_distribution.distribution[1].amt.encode());
    encoded.extend(channel_initializer.open_deadline.encode());
    encoded.extend(channel_initializer.dispute_timeout.encode());
    encoded.extend(channel_initializer.msg_value_receiver.encode());

    return encoded;
}

pub fn check_simplex_state<T: Trait>(
    simplex_state: SimplexPaymentChannelOf<T>,
) -> Result<(), DispatchError> {
    ensure!(
        simplex_state.peer_from.is_some()
        && simplex_state.transfer_to_peer.is_some()
        && simplex_state.pending_pay_ids.is_some(),
        Error::<T>::InvalidSimplexState
    );

    Ok(())
}

pub fn encode_simplex_state<T: Trait>(
    simplex_state: SimplexPaymentChannelOf<T>
) -> Vec<u8> {
    let mut encoded = simplex_state.channel_id.encode();
    encoded.extend(simplex_state.peer_from.encode());
    encoded.extend(simplex_state.seq_num.encode());
    encoded.extend(simplex_state.transfer_to_peer.as_ref().unwrap().token.token_type.encode());
    encoded.extend(simplex_state.transfer_to_peer.as_ref().unwrap().receiver.account.encode());
    encoded.extend(simplex_state.transfer_to_peer.unwrap().receiver.amt.encode());
    simplex_state.pending_pay_ids.clone().unwrap().pay_ids.into_iter().for_each(|pay_id| {
        encoded.extend(pay_id.encode());
    });
    encoded.extend(simplex_state.pending_pay_ids.unwrap().next_list_hash.encode());
    encoded.extend(simplex_state.last_pay_resolve_deadline.encode());
    encoded.extend(simplex_state.total_pending_amount.encode());

    return encoded;
}

pub fn encode_simplex_null_state<T: Trait>(
     simplex_state: SimplexPaymentChannelOf<T>
) -> Vec<u8> {
    let mut encoded = simplex_state.channel_id.encode();
    encoded.extend(simplex_state.peer_from.encode());
    encoded.extend(simplex_state.seq_num.encode());
    encoded.extend(simplex_state.transfer_to_peer.encode());
    encoded.extend(simplex_state.pending_pay_ids.encode());
    encoded.extend(simplex_state.last_pay_resolve_deadline.encode());
    encoded.extend(simplex_state.total_pending_amount.encode());

    return encoded;
}

pub fn encode_withdraw_info<T: Trait>(withdraw_info: CooperativeWithdrawInfoOf<T>) -> Vec<u8> {
    let mut encoded = withdraw_info.channel_id.encode();
    encoded.extend(withdraw_info.seq_num.encode());
    encoded.extend(withdraw_info.withdraw.account.clone().encode());
    encoded.extend(withdraw_info.withdraw.amt.encode());
    encoded.extend(withdraw_info.withdraw_deadline.encode());
    encoded.extend(withdraw_info.recipient_channel_id.encode());

    return encoded;
}

pub fn check_settle_info<T: Trait>(settle_info: CooperativeSettleInfoOf<T>) -> Result<(), DispatchError> {
    ensure!(
        settle_info.settle_balance[0].clone().account.is_some()
        && settle_info.settle_balance[1].clone().account.is_some(),
        Error::<T>::InvalidCooperativeSettle
    );

    Ok(())
}

pub fn encode_settle_info<T: Trait>(settle_info: CooperativeSettleInfoOf<T>) -> Vec<u8> {
    let mut encoded = settle_info.channel_id.encode();
    encoded.extend(settle_info.seq_num.encode());
    encoded.extend(settle_info.settle_balance[0].clone().account.encode());
    encoded.extend(settle_info.settle_balance[0].clone().amt.encode());
    encoded.extend(settle_info.settle_balance[1].clone().account.encode());
    encoded.extend(settle_info.settle_balance[1].clone().amt.encode());
    encoded.extend(settle_info.settle_deadline.encode());

    return encoded;
}

