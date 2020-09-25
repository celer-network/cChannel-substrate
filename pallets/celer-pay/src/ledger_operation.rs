use super::{
    BalanceOf, ChannelMap, ChannelStatusNums, Error, 
    Module as CelerPayModule, Wallets, RawEvent
};
use crate::traits::Trait;
use crate::celer_wallet::{CelerWallet, WalletOf};
use crate::pay_registry::PayRegistry;
use crate::pay_resolver::{AccountAmtPair, TokenInfo, TokenTransfer, TokenType};
use crate::pool::Pool;
use codec::{Decode, Encode};
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_support::{ensure, storage::StorageMap};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{CheckedAdd, CheckedSub, Hash, Zero};
use sp_runtime::{ModuleId, RuntimeDebug, DispatchError};
use sp_std::{vec, vec::Vec};

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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum MathOperation {
    Add,
    Sub,
}

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

        c.balance_limits = Some(limits);
        <ChannelMap<T>>::mutate(&channel_id, |channel| *channel = Some(c));

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

        c.balance_limits_enabled = false;
        <ChannelMap<T>>::mutate(&channel_id, |channel| *channel = Some(c));
        
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
    
        c.balance_limits_enabled = true;
        <ChannelMap<T>>::mutate(&channel_id, |channel| *channel = Some(c));
        
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
            T::Currency::free_balance(&caller) >= msg_value,
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

        let account_0 = match channel_initializer.init_distribution.distribution[0].account.clone() {
            Some(account) => account,
            None => return Err(Error::<T>::PeerNotExist)?,
        };
        let account_1 = match channel_initializer.init_distribution.distribution[1].account.clone() {
            Some(account) => account,
            None => return Err(Error::<T>::PeerNotExist)?,
        };
        let peer_addrs: Vec<T::AccountId> = vec![account_0, account_1];

        // Enforce asceding order of peer's addresses to simplyfy contract code
        ensure!(
            peer_addrs[0] < peer_addrs[1],
            "Peer addrs are not ascending"
        );

        let encoded = encode_channel_initializer::<T>(channel_initializer.clone());
        let signers = vec![peer_addrs[0].clone(), peer_addrs[1].clone()];
        CelerPayModule::<T>::valid_signers(open_request.sigs, &encoded, signers)?;

        let owners = vec![peer_addrs[0].clone(), peer_addrs[1].clone()];
        let h = T::Hashing::hash(&encoded);
        let channel_id = create_wallet::<T>(owners, h)?;

        // Insert new Channel to ChannelMap.
        let peer_state = PeerStateOf::<T> {
            seq_num: 0,
            transfer_out: Zero::zero(),
            next_pay_id_list_hash: None,
            last_pay_resolve_deadline: Zero::zero(),
            pending_pay_out: Zero::zero(),
        };
        let peer_profiles_0 = PeerProfileOf::<T> {
            peer_addr: peer_addrs[0].clone(),
            deposit: amounts[0],
            withdrawal: None,
            state: peer_state.clone(),
        };
        let peer_profiles_1 = PeerProfileOf::<T> {
            peer_addr: peer_addrs[1].clone(),
            deposit: amounts[1],
            withdrawal: None,
            state: peer_state,
        };

        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        let withdraw_intent = WithdrawIntentOf::<T> {
            receiver: celer_ledger_account,
            amount: None,
            request_time: None,
            recipient_channel_id: None,
        };
        let channel = ChannelOf::<T> {
            balance_limits_enabled: channel_initializer.balance_limits_enabled,
            balance_limits: channel_initializer.balance_limits,
            settle_finalized_time: None,
            dispute_timeout: channel_initializer.dispute_timeout,
            token: token.clone(),
            status: ChannelStatus::Operable,
            peer_profiles: vec![peer_profiles_0, peer_profiles_1],
            cooperative_withdraw_seq_num: None,
            withdraw_intent: withdraw_intent,
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
                CelerWallet::<T>::deposit_native_token(origin, channel_id, msg_value)?;
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
            T::Currency::free_balance(&caller) >= msg_value,
            "caller does not have enough balances."
        );
        let deposit_amount: BalanceOf<T> = msg_value.checked_add(&transfer_from_amount).ok_or(Error::<T>::OverFlow)?;
        add_deposit::<T>(channel_id, receiver.clone(), deposit_amount)?;

        if c.token.token_type == TokenType::Celer {
            if msg_value > Zero::zero() {
                CelerWallet::<T>::deposit_native_token(origin, channel_id, msg_value)?;
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
        let state_len = signed_simplex_state_array.signed_simplex_states.len();

        // snapshot each state
        let mut simplex_state = signed_simplex_state_array.signed_simplex_states[0].simplex_state.clone();
        for i in 0..state_len {
            let current_channel_id: T::Hash = simplex_state.channel_id;
            let mut c: ChannelOf<T> = match ChannelMap::<T>::get(&current_channel_id) {
                Some(channel) => channel,
                None => Err(Error::<T>::ChannelNotExist)?,
            };

            ensure!(c.status == ChannelStatus::Operable, "Channel status error");

            // Check Co-Signatures.
            let encoded = encode_signed_simplex_state_array::<T>(signed_simplex_state_array.clone(), i as usize);
            let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
            let channel_peer = vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ];
            CelerPayModule::<T>::valid_signers(sigs, &encoded, channel_peer)?;

            let pid = get_peer_id::<T>(c.clone(), simplex_state.peer_from.clone().unwrap())?;
            let state = c.peer_profiles[pid].clone().state;

            ensure!(simplex_state.seq_num > c.peer_profiles[pid].state.seq_num, "seq_num error");

            // No need to update nextPayIdListHash and lastPayResolveDeadline for snapshot purpose
            let new_state = PeerStateOf::<T> {
                seq_num: simplex_state.seq_num,
                transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt,
                next_pay_id_list_hash: state.next_pay_id_list_hash,
                last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                pending_pay_out: simplex_state.total_pending_amount.unwrap(),
            };
            c.peer_profiles[pid].state = new_state;
            ChannelMap::<T>::mutate(&current_channel_id, |channel| {*channel = Some(c)});

            if i == state_len.checked_sub(1).ok_or(Error::<T>::UnderFlow)? {
                let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                CelerPayModule::<T>::deposit_event(RawEvent::SnapshotStates(
                    current_channel_id,
                    vec![seq_nums[0], seq_nums[1]],
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
                        vec![seq_nums[0], seq_nums[1]],
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
        let withdraw_intent = c.withdraw_intent.clone();

        ensure!(c.status == ChannelStatus::Operable, "Channel status error");

        // withdraw_intent.receiver is ledger address if and  only if there is no pending withdraw_intent.
        // because withdraw_intent.receiver may only be set as caller address which can't be ledger address.
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(
            withdraw_intent.receiver == celer_ledger_account,
            "Pending withdraw intent exists"
        );

        ensure!(
            Self::is_peer(c.clone(), receiver.clone()),
            "Receirver is not channel peer."
        );

        let new_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: receiver.clone(),
            amount: Some(amount),
            request_time: Some(frame_system::Module::<T>::block_number()),
            recipient_channel_id: Some(recipient_channel_id),
        };
        c.withdraw_intent = new_withdraw_intent;
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c));

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
        let withdraw_intent = c.clone().withdraw_intent;
        ensure!(
            withdraw_intent.receiver != celer_ledger_account,
            "No pending withdraw intent"
        );

        let dispute_timeout = withdraw_intent.request_time.unwrap_or(Zero::zero())
                .checked_add(&c.dispute_timeout).ok_or(Error::<T>::OverFlow)?;
        let block_number = frame_system::Module::<T>::block_number();
        ensure!(block_number >= dispute_timeout, "Dispute not timeout");

        let zero_channel_id: T::Hash = CelerPayModule::<T>::get_zero_hash();
        let receiver = withdraw_intent.receiver;
        let amount = withdraw_intent.amount.unwrap_or(Zero::zero());
        let recipient_channel_id = withdraw_intent.recipient_channel_id.unwrap_or(zero_channel_id);

        let rid = get_peer_id::<T>(c.clone(), receiver.clone())?;

        let state_0 = c.peer_profiles[0].state.clone();
        let state_1 = c.peer_profiles[1].state.clone();

        // check withdraw limit
        let mut withdraw_limit: BalanceOf<T> = Zero::zero();
        if rid == 0 {
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[0].deposit).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_add(&state_1.transfer_out).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[0].clone().withdrawal.unwrap_or(Zero::zero())).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_0.transfer_out).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_0.pending_pay_out).ok_or(Error::<T>::UnderFlow)?;
        } else {
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[1].deposit).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_add(&state_0.transfer_out).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[1].clone().withdrawal.unwrap_or(Zero::zero())).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_1.transfer_out).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_1.pending_pay_out).ok_or(Error::<T>::UnderFlow)?;
        }
        ensure!(amount <= withdraw_limit, "Exceed withdraw limit");

        // Update record of one peer's withdrawal amount
        let new_amount: BalanceOf<T> = c.peer_profiles[rid as usize].clone().withdrawal.unwrap_or(Zero::zero())
                 .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        c.peer_profiles[rid as usize].withdrawal = Some(new_amount);

        // Initialize c.wihdraw_intent
        let initialize_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: celer_ledger_account,
            amount: None,
            request_time: None,
            recipient_channel_id: None,
        };
        c.withdraw_intent = initialize_withdraw_intent;

        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c.clone()));

        withdraw_funds::<T>(
            c,
            channel_id,
            receiver.clone(),
            amount,
            recipient_channel_id,
        )?;
        
        let (_, deposits, withdrawals): (Vec<T::AccountId>, Vec<BalanceOf<T>>, Vec<BalanceOf<T>>)
            = CelerPayModule::<T>::get_balance_map(channel_id);
        // Emit Confirmwithdraw event
        CelerPayModule::<T>::deposit_event(RawEvent::ConfirmWithdraw(
            channel_id,
            amount,
            receiver.clone(),
            recipient_channel_id,
            deposits,
            withdrawals
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
        let intent = c.withdraw_intent.clone();
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();

        ensure!(intent.receiver != celer_ledger_account, "No pending withdraw intent");
        ensure!(Self::is_peer(c.clone(), caller), "caller is not peer");

        let initialize_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: celer_ledger_account,
            amount: None,
            request_time: None,
            recipient_channel_id: None,
        };
        c.withdraw_intent = initialize_withdraw_intent;
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c));

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

        let receiver = withdraw_info.withdraw.account.unwrap();
        let amount = withdraw_info.withdraw.amt;

        let rid = get_peer_id::<T>(c.clone(), receiver.clone())?;

        let new_withdrawal_amount = c.peer_profiles[rid].clone().withdrawal.unwrap_or(Zero::zero())
                .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        c.peer_profiles[rid].withdrawal = Some(new_withdrawal_amount);
        c.cooperative_withdraw_seq_num = Some(withdraw_info.seq_num);
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c.clone()));

        withdraw_funds::<T>(
            c,
            channel_id,
            receiver.clone(),
            amount,
            recipient_channel_id,
        )?;       

        let (_, deposits, withdrawals): (Vec<T::AccountId>, Vec<BalanceOf<T>>, Vec<BalanceOf<T>>)
            = CelerPayModule::<T>::get_balance_map(channel_id);
        // Emit CooperativeWithdraw event
        CelerPayModule::<T>::deposit_event(RawEvent::CooperativeWithdraw(
            channel_id,
            amount,
            receiver.clone(),
            recipient_channel_id,
            deposits,
            withdrawals,
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

            let zero_blocknumber: T::BlockNumber = Zero::zero();
            ensure!(
                c.settle_finalized_time.unwrap_or(zero_blocknumber) == zero_blocknumber
                    || frame_system::Module::<T>::block_number() < c.settle_finalized_time.unwrap(),
                "Settle has already finalized"
            );

            if simplex_state.seq_num > 0 {
                // Check signatures
                let encoded = encode_signed_simplex_state_array::<T>(signed_simplex_state_array.clone(), i as usize);
                let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
                let channel_peer = vec![
                    c.peer_profiles[0].peer_addr.clone(),
                    c.peer_profiles[1].peer_addr.clone(),
                ];
                CelerPayModule::<T>::valid_signers(sigs, &encoded, channel_peer)?;

                let pid = get_peer_id::<T>(c.clone(), simplex_state.peer_from.clone().unwrap())?;
                let state = c.peer_profiles[pid].clone().state;

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
                
                let new_state: PeerStateOf<T>;
                if next_pay_id_list_hash == zero_hash {
                    // Update simplex_state-dependent fields
                    new_state = PeerStateOf::<T> {
                        seq_num: simplex_state.seq_num,
                        transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt.clone(),
                        next_pay_id_list_hash: None,
                        last_pay_resolve_deadline: simplex_state.last_pay_resolve_deadline.unwrap().clone(),
                        pending_pay_out: state.pending_pay_out,
                    };
                } else {
                    // Update simplex_state-dependent fields
                    new_state = PeerStateOf::<T> {
                        seq_num: simplex_state.seq_num,
                        transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt.clone(),
                        next_pay_id_list_hash: Some(next_pay_id_list_hash),
                        last_pay_resolve_deadline: simplex_state.last_pay_resolve_deadline.unwrap().clone(),
                        pending_pay_out: simplex_state.total_pending_amount.clone().unwrap(),
                    };
                }

                c.peer_profiles[pid].state = new_state;
                ChannelMap::<T>::mutate(&current_channel_id, |channel| { *channel = Some(c.clone()) });
            
                _clear_pays::<T>(
                    c,
                    current_channel_id,
                    pid,
                    simplex_state.pending_pay_ids.clone().unwrap(),
                )?;
            } else if simplex_state.seq_num == 0 {
                // null state
                // Check signautre
                let encoded = encode_signed_simplex_null_state::<T>(
                    signed_simplex_state_array.clone(),
                    i as usize,
                );
                let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
                CelerPayModule::<T>::check_single_signature(sigs[0].clone(),&encoded,c.peer_profiles[0].peer_addr.clone())?;
                
                let zero_blocknumber = Zero::zero();
                // This implies both stored seq_nums are 0
                ensure!(
                    c.settle_finalized_time.unwrap_or(zero_blocknumber) == zero_blocknumber,
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
        let new_state: PeerStateOf<T>;

        let zero_hash = CelerPayModule::<T>::get_zero_hash();
        let next_pay_id_list_hash = state.next_pay_id_list_hash.unwrap_or(zero_hash);
        if next_pay_id_list_hash != zero_hash {
            ensure!(next_pay_id_list_hash == list_hash, "List hash mismatch");

            new_state = PeerStateOf::<T> {
                seq_num: state.seq_num,
                transfer_out: state.transfer_out,
                next_pay_id_list_hash: pay_id_list.next_list_hash,
                last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                pending_pay_out: state.pending_pay_out,
            };
        } else {
            new_state = PeerStateOf::<T> {
                seq_num: state.seq_num,
                transfer_out: state.transfer_out,
                next_pay_id_list_hash: pay_id_list.next_list_hash,
                last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                pending_pay_out: state.pending_pay_out,
            };
        }
        c.peer_profiles[pid].state = new_state;
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c.clone()));

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
        let peer_profiles = vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()];
        let block_number = frame_system::Module::<T>::block_number();
        ensure!(c.status == ChannelStatus::Settling, "Channel status error");

        // require no new intend_settle can be called
        ensure!(
            block_number >= c.settle_finalized_time.unwrap(),
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
        let state_0 = peer_profiles[0].state.clone();
        let state_1 = peer_profiles[1].state.clone();
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

        // Check co-signature
        let encoded = encode_settle_info::<T>(settle_info.clone());
        let signers = vec![
            settle_info.settle_balance[0].account.clone().unwrap(),
            settle_info.settle_balance[1].account.clone().unwrap(),
        ];
        CelerPayModule::<T>::valid_signers(settle_request.sigs, &encoded, signers)?;

        let peer_addrs = vec![
            c.peer_profiles[0].peer_addr.clone(),
            c.peer_profiles[1].peer_addr.clone(),
        ];
        let state_0 = c.peer_profiles[0].state.clone();
        let state_1 = c.peer_profiles[1].state.clone();

        ensure!(
            settle_info.seq_num > state_0.seq_num && settle_info.seq_num > state_1.seq_num,
            "seq_num error"
        );
        ensure!(
            settle_info.settle_balance[0].clone().account.unwrap() == peer_addrs[0]
                && settle_info.settle_balance[1].clone().account.unwrap() == peer_addrs[1],
            "Settle accounts mismatch"
        );

        let settle_balance = vec![
            settle_info.settle_balance[0].amt,
            settle_info.settle_balance[1].amt,
        ];
        let total_settle_balance = settle_balance[0]
                .checked_add(&settle_balance[1]).ok_or(Error::<T>::OverFlow)?;
        let total_balance = CelerPayModule::<T>::get_total_balance(channel_id)?;
        ensure!(
            total_settle_balance == total_balance,
            "Balance sum mismatch"
        );

        update_channel_status::<T>(c, channel_id, ChannelStatus::Closed)?;

        batch_transfer_out::<T>(channel_id, peer_addrs, settle_balance.clone())?;

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

// create a wallet for a new channel
fn create_wallet<T: Trait>(
    peers: Vec<T::AccountId>,
    nonce: T::Hash,
) -> Result<T::Hash, DispatchError> {
    let wallet_id: T::Hash = create_wallet_id::<T>(peers.clone(), nonce);

    // Check wallet_id is not exist.
    ensure!(
        Wallets::<T>::contains_key(&wallet_id) == false,
        "Occupied wallet id"
    );

    let new_balance = Zero::zero();
    let wallet = WalletOf::<T> {
        owners: peers,
        balance: new_balance,
    };

    // create new wallet
    Wallets::<T>::insert(&wallet_id, &wallet);

    return Ok(wallet_id);
}

// create wallet id
fn create_wallet_id<T: Trait>(peers: Vec<T::AccountId>, nonce: T::Hash) -> T::Hash {
    let mut encoded = peers[0].clone().encode();
    encoded.extend(peers[1].encode());
    encoded.extend(nonce.encode());
    let wallet_id = T::Hashing::hash(&encoded);

    // Emit CreateWallet event
    CelerPayModule::<T>::deposit_event(RawEvent::CreateWallet(
        wallet_id,
        vec![peers[0].clone(), peers[1].clone()]
    ));
    return wallet_id;
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
        let total_balance = CelerPayModule::<T>::get_total_balance(channel_id.clone())?;
        let added_amount = amount.checked_add(&total_balance).ok_or(Error::<T>::OverFlow)?;
        let limits = match c.balance_limits {
            Some(limits) => limits,
            None => Err(Error::<T>::BalanceLimitsNotExist)?,
        };
        ensure!(added_amount <= limits, "Balance exceeds limit");
    }

    let mut rid: usize = 0;
    if receiver == c.peer_profiles[0].peer_addr {
        rid = 0;
    } else if receiver == c.peer_profiles[1].peer_addr {
        rid = 1;
    } else {
        Err(Error::<T>::NotChannelPeer)?
    }

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
    for i in 0..2 {
        if amounts[i] == Zero::zero() {
            continue;
        }
        withdraw::<T>(channel_id, receivers[i].clone(), amounts[i])?;
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

    let zero_channel_id: T::Hash = CelerPayModule::<T>::get_zero_hash();
    if recipient_channel_id == zero_channel_id {
        withdraw::<T>(channel_id, receiver, amount)?;
    } else {
        let recipient_channel = ChannelMap::<T>::get(recipient_channel_id).unwrap();
        ensure!(
            c.token.token_type == recipient_channel.token.token_type,
            "Token mismatch of recipient channel"
        );
        add_deposit::<T>(recipient_channel_id, receiver.clone(), amount)?;

        // move funds from one channel's wallet to another channel's wallet
        transfer_to_wallet::<T>(channel_id, recipient_channel_id, receiver, amount)?;
    }

    Ok(())
}

// Reset the state of the channel
fn reset_duplex_state<T: Trait>(mut c: ChannelOf<T>, channel_id: T::Hash) -> Result<(), DispatchError> {
    // initialize settle_finalized_time
    c.settle_finalized_time = None;

    update_channel_status::<T>(c.clone(), channel_id, ChannelStatus::Operable)?;
    
    // initialize peer_state
    let initialize_state = PeerStateOf::<T> {
        seq_num: 0,
        transfer_out: Zero::zero(),
        next_pay_id_list_hash: None,
        last_pay_resolve_deadline: Zero::zero(),
        pending_pay_out: Zero::zero(),
    };
    c.peer_profiles[0].state = initialize_state.clone();
    c.peer_profiles[1].state = initialize_state;
    
    // reset possibly remaining WithdrawIntent freezed by previous intendSettle()
    let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
    let initialize_withdraw_intent = WithdrawIntentOf::<T> {
        receiver: celer_ledger_account,
        amount: None,
        request_time: None,
        recipient_channel_id: None,
    };
    c.withdraw_intent = initialize_withdraw_intent;

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
    let out_amts_len = out_amts.len();
    for i in 0..out_amts_len {
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
        let new_state = PeerStateOf::<T> {
            seq_num: state.seq_num,
            transfer_out: new_transfer_out,
            next_pay_id_list_hash: state.next_pay_id_list_hash,
            last_pay_resolve_deadline: state.last_pay_resolve_deadline,
            pending_pay_out: Zero::zero(),
        };
        c.peer_profiles[pid].state = new_state;
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c));
    } else {
        // Note: if there are more uncleared pays in this state, because resolved pay amount
        //      is always less than or equal to the corresponding maximum amount counted in
        //      pending_pay_out, the updated pending_pay_out may be equal to or larger than the real
        //      pending_pay_out. This will lead to decreasing the maximum withdraw amount (withdraw_limit)
        //      from potentially maliciout non-cooperative withdraw.
        let new_pending_pay_out = state.pending_pay_out.checked_sub(&total_amt_out).ok_or(Error::<T>::OverFlow)?;
        let new_state = PeerStateOf::<T> {
            seq_num: state.seq_num,
            transfer_out: new_transfer_out,
            next_pay_id_list_hash: state.next_pay_id_list_hash,
            last_pay_resolve_deadline: state.last_pay_resolve_deadline,
            pending_pay_out: new_pending_pay_out,
        };
        c.peer_profiles[pid].state = new_state;
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(c));
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
    c.settle_finalized_time = Some(new_setttle_finalized_time);
    ChannelMap::<T>::mutate(channel_id, |channel| *channel = Some(c.clone()));
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

        let new_nums_1: u8;
        if status_nums == 0 {
            new_nums_1 = 0;
        } else {
            new_nums_1 = status_nums - 1;
        }
        ChannelStatusNums::mutate(c.status.clone() as u8, |num| *num = Some(new_nums_1));
    }

    let new_status_nums;
    new_status_nums = match CelerPayModule::<T>::channel_status_nums(new_status.clone() as u8) {
        Some(num) => num as u8,
        None => 0 as u8,
    };
    let new_nums_2 = new_status_nums + 1;
    ChannelStatusNums::mutate(new_status.clone() as u8, |num| *num = Some(new_nums_2));

    c.status = new_status;
    ChannelMap::<T>::mutate(channel_id, |channel| *channel = Some(c));

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

    return Ok((true, vec![settle_balance[0], settle_balance[1]]));
}

/// Get the seqNums of two simplex channel states
fn get_state_seq_nums<T: Trait>(channel_id: T::Hash) -> Vec<u128> {
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    let state_0 = c.peer_profiles[0].clone().state;
    let state_1 = c.peer_profiles[1].clone().state;
    return vec![state_0.seq_num, state_1.seq_num];
}

// Celer Wallet
// function which modifier is onlyOperator
fn withdraw<T: Trait>(
    wallet_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    update_balance::<T>(receiver.clone(), wallet_id, MathOperation::Sub, amount)?;
    // Emit WithdrawFromWallet Event
    CelerPayModule::<T>::deposit_event(RawEvent::WithdrawFromWallet(
        wallet_id, 
        receiver, 
        amount
    ));
    Ok(())
}

fn is_wallet_owner<T: Trait>(wallet_id: T::Hash, addr: T::AccountId) -> bool {
    let w: WalletOf<T> = Wallets::<T>::get(wallet_id).unwrap();
    for i in 0..w.owners.len() {
        if addr == w.owners[i] {
            return true;
        }
    }
    return false;
}

fn update_balance<T: Trait>(
    caller: T::AccountId,
    wallet_id: T::Hash,
    op: MathOperation,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    let w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
        Some(_w) => _w,
        None => Err(Error::<T>::WalletNotExist)?,
    };

    let celer_wallet_account = CelerPayModule::<T>::get_celer_wallet_id();

    if op == MathOperation::Sub {
        ensure!(w.balance >= amount, "balance of amount is not deposited");
        let new_amount = w.balance.checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_amount,
        };

        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));

        T::Currency::transfer(
            &celer_wallet_account,
            &caller,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;
    } else if op == MathOperation::Add {
        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances."
        );
        let new_amount = w.balance.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_amount,
        };

        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));

        T::Currency::transfer(
            &caller,
            &celer_wallet_account,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;
    } else {
        Err(Error::<T>::Error)?
    }

    Ok(())
}

// Transfer funds from one wallet to another wallet with a same owner (as the receriver)
fn transfer_to_wallet<T: Trait>(
    from_wallet_id: T::Hash,
    to_wallet_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    ensure!(
        is_wallet_owner::<T>(from_wallet_id, receiver.clone())
            && is_wallet_owner::<T>(to_wallet_id, receiver),
        "receiver is not wallet owner"
    );

    let from_wallet = match Wallets::<T>::get(from_wallet_id) {
        Some(w) => w,
        None => Err(Error::<T>::WalletNotExist)?,
    };
    let to_wallet = match Wallets::<T>::get(to_wallet_id) {
        Some(w) => w,
        None => Err(Error::<T>::WalletNotExist)?,
    };

    let from_wallet_amount = from_wallet.balance.checked_sub(&amount).ok_or(Error::<T>::OverFlow)?;
    let new_from_wallet = WalletOf::<T> {
        owners: from_wallet.owners,
        balance: from_wallet_amount,
    };

    let to_wallet_amount = to_wallet.balance.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
    let new_to_wallet = WalletOf::<T> {
        owners: to_wallet.owners,
        balance: to_wallet_amount,
    };

    Wallets::<T>::mutate(&from_wallet_id, |wallet| *wallet = Some(new_from_wallet));
    Wallets::<T>::mutate(&to_wallet_id, |wallet| *wallet = Some(new_to_wallet));

    Ok(())
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

pub fn encode_signed_simplex_state_array<T: Trait>(
    signed_simplex_state_array: SignedSimplexStateArrayOf<T>,
    state_index: usize
) -> Vec<u8> {
    let mut encoded = signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.channel_id.encode();
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.peer_from.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.seq_num.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.transfer_to_peer.unwrap().token.token_type.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.transfer_to_peer.unwrap().receiver.account.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.transfer_to_peer.unwrap().receiver.amt.encode());
    signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.pending_pay_ids.unwrap().pay_ids.into_iter().for_each(|pay_id| {
        encoded.extend(pay_id.encode());
    });
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.pending_pay_ids.unwrap().next_list_hash.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.last_pay_resolve_deadline.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.total_pending_amount.encode());

    return encoded;
}

pub fn encode_signed_simplex_null_state<T: Trait>(
    signed_simplex_state_array: SignedSimplexStateArrayOf<T>,
    state_index: usize,
) -> Vec<u8> {
    let mut encoded = signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.channel_id.encode();
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.peer_from.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.seq_num.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.transfer_to_peer.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.pending_pay_ids.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.last_pay_resolve_deadline.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.total_pending_amount.encode());

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

