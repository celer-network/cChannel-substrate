use super::{BalanceOf, ChannelMap, ChannelStatusNums, Error, Module, Trait, Wallets};
use crate::celer_wallet::{CelerWallet, WalletOf, WALLET_ID};
use crate::pay_registry::PayRegistry;
use crate::pay_resolver::{AccountAmtPair, TokenInfo, TokenTransfer, TokenType};
use crate::pool::Pool;
use codec::{Decode, Encode};
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_support::{ensure, storage::StorageMap,
    dispatch::DispatchError
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{AccountIdConversion, CheckedAdd, CheckedSub, Hash, Zero};
use sp_runtime::{ModuleId, RuntimeDebug};
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
    pub signed_simplex_states:
        Vec<SignedSimplexState<Hash, AccountId, BlockNumber, Balance, Signature>>,
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
        let c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            LedgerOperation::<T>::is_peer(c.clone(), caller) == true,
            "caller is not channel peer"
        );
        let new_channel = ChannelOf::<T> {
            balance_limits_enabled: c.balance_limits_enabled,
            balance_limits: Some(limits),
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: c.peer_profiles,
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: c.withdraw_intent,
        };

        <ChannelMap<T>>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        Ok(())
    }

    // Disable balance limits
    pub fn disable_balance_limits(
        origin: T::Origin,
        channel_id: T::Hash,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            LedgerOperation::<T>::is_peer(c.clone(), caller) == true,
            "caller is not channel peer"
        );
        let new_channel = ChannelOf::<T> {
            balance_limits_enabled: false,
            balance_limits: c.balance_limits,
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: c.peer_profiles,
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: c.withdraw_intent,
        };
        <ChannelMap<T>>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        
        Ok(())
    }

    // Enable balance limits
    pub fn enable_balance_limits(
        origin: T::Origin,
        channel_id: T::Hash,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            LedgerOperation::<T>::is_peer(c.clone(), caller) == true,
            "caller is not channel peer"
        );
        let new_channel = ChannelOf::<T> {
            balance_limits_enabled: true,
            balance_limits: c.balance_limits,
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: c.peer_profiles,
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: c.withdraw_intent,
        };

        <ChannelMap<T>>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        Ok(())
    }

    // Open a state channel through auth withdraw message
    pub fn open_channel(
        origin: T::Origin,
        open_request: OpenChannelRequestOf<T>,
        amount: BalanceOf<T>,
    ) -> Result<T::Hash, DispatchError> {
        let caller = ensure_signed(origin.clone())?;
        ensure!(
            T::Currency::free_balance(&caller) >= amount,
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

        let account_1 = match channel_initializer.init_distribution.distribution[0].account.clone() {
            Some(account) => account,
            None => return Err(Error::<T>::PeerNotExist)?,
        };
        let account_2 = match channel_initializer.init_distribution.distribution[1].account.clone() {
            Some(account) => account,
            None => return Err(Error::<T>::PeerNotExist)?,
        };
        let peer_addrs: Vec<T::AccountId> = vec![account_1, account_2];

        // Enforce asceding order of peer's addresses to simplyfy contract code
        ensure!(
            peer_addrs[0] < peer_addrs[1],
            "Peer addrs are not ascending"
        );

        let encoded = encode_channel_initializer::<T>(channel_initializer.clone());
        let signers = vec![peer_addrs[0].clone(), peer_addrs[1].clone()];
        Module::<T>::valid_signers(open_request.sigs, &encoded, signers)?;

        let owners = vec![peer_addrs[0].clone(), peer_addrs[1].clone()];
        let h = T::Hashing::hash(&encoded);
        let channel_id = create_wallet::<T>(owners, h)?;

        // Insert new Channel to ChannelMap.
        let zero_balance: BalanceOf<T> = Zero::zero();
        let zero_blocknumber: T::BlockNumber = Zero::zero();
        let peer_state = PeerStateOf::<T> {
            seq_num: 0,
            transfer_out: zero_balance,
            next_pay_id_list_hash: None,
            last_pay_resolve_deadline: zero_blocknumber,
            pending_pay_out: zero_balance,
        };
        let peer_profiles_1 = PeerProfileOf::<T> {
            peer_addr: peer_addrs[0].clone(),
            deposit: amounts[0],
            withdrawal: None,
            state: peer_state.clone(),
        };
        let peer_profiles_2 = PeerProfileOf::<T> {
            peer_addr: peer_addrs[1].clone(),
            deposit: amounts[1],
            withdrawal: None,
            state: peer_state,
        };

        let ledger_addr = Self::ledger_account();
        let withdraw_intent = WithdrawIntentOf::<T> {
            receiver: ledger_addr,
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
            peer_profiles: vec![peer_profiles_1, peer_profiles_2],
            cooperative_withdraw_seq_num: None,
            withdraw_intent: withdraw_intent,
        };

        let amt_sum: BalanceOf<T> = amounts[0].checked_add(&amounts[1]).ok_or(Error::<T>::OverFlow)?;
        let zero_balance: BalanceOf<T> = Zero::zero();
        // if total deposit is 0
        if amt_sum == zero_balance {
            ensure!(amount == zero_balance, "amount is not 0");

            ChannelMap::<T>::insert(channel_id, channel);
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
        }

        if token.token_type == TokenType::CELER {
            let msg_value_receiver = channel_initializer.msg_value_receiver as usize;
            ensure!(amount == amounts[msg_value_receiver], "amount mismatch");
            if amounts[msg_value_receiver] > zero_balance {
                CelerWallet::<T>::deposit_native_token(origin, channel_id, amount)?;
            }

            // peer ID of non-msg_value_receiver
            let pid: usize = 1 - msg_value_receiver;
            if amounts[pid] > zero_balance {
                let ledger_addr = Self::ledger_account();
                Pool::<T>::transfer_to_celer_wallet_by_ledger(
                    ledger_addr,
                    peer_addrs[pid].clone(),
                    channel_id,
                    amounts[pid],
                )?;
            }
        } else {
            Err(Error::<T>::Error)?
        }

        ChannelMap::<T>::insert(channel_id, channel);

        return Ok(channel_id);
    }

    // Deposit native token into the channel
    pub fn deposit(
        origin: T::Origin,
        channel_id: T::Hash,
        receiver: T::AccountId,
        amount: BalanceOf<T>,
        transfer_from_amount: BalanceOf<T>,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin.clone())?;
        let c: ChannelOf<T> = match ChannelMap::<T>::get(&channel_id) {
            Some(channel) => channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances."
        );
        let deposit_amount: BalanceOf<T> = amount.checked_add(&transfer_from_amount).ok_or(Error::<T>::OverFlow)?;
        add_deposit::<T>(channel_id, receiver.clone(), deposit_amount)?;

        let zero_balance: BalanceOf<T> = Zero::zero();
        if c.token.token_type == TokenType::CELER {
            if amount > zero_balance {
                CelerWallet::<T>::deposit_native_token(origin, channel_id, amount)?;
            }
            let ledger_account = Self::ledger_account();
            if transfer_from_amount > zero_balance {
                Pool::<T>::transfer_to_celer_wallet_by_ledger(
                    ledger_account,
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
        let mut simplex_state = signed_simplex_state_array.signed_simplex_states[0]
            .simplex_state
            .clone();
        for i in 0..state_len {
            let current_channel_id: T::Hash = simplex_state.channel_id;
            let c: ChannelOf<T> = ChannelMap::<T>::get(current_channel_id).unwrap();

            ensure!(c.status == ChannelStatus::Operable, "Channel status error");

            // Check Co-Signatures.
            let pay_id_len = signed_simplex_state_array.signed_simplex_states[i].simplex_state.pending_pay_ids.clone().unwrap().pay_ids.len();
            let encoded = encode_signed_simplex_state_array::<T>(signed_simplex_state_array.clone(), i as usize, pay_id_len as usize);
            let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
            let channel_peer = vec![
                c.peer_profiles[0].peer_addr.clone(),
                c.peer_profiles[1].peer_addr.clone(),
            ];
            Module::<T>::valid_signers(sigs, &encoded, channel_peer)?;

            let state: PeerStateOf<T>;
            let peer_from_id: u8;
            if c.peer_profiles[0].peer_addr == simplex_state.peer_from.clone().unwrap() {
                state = c.peer_profiles[0].clone().state;
                peer_from_id = 0;
            } else {
                state = c.peer_profiles[1].clone().state;
                peer_from_id = 1;
            }

            ensure!(simplex_state.seq_num > state.seq_num, "seq_num error");

            // No need to update nextPayIdListHash and lastPayResolveDeadline for snapshot purpose
            if peer_from_id == 0 {
                let new_state = PeerStateOf::<T> {
                    seq_num: simplex_state.seq_num,
                    transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt,
                    next_pay_id_list_hash: state.next_pay_id_list_hash,
                    last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                    pending_pay_out: simplex_state.total_pending_amount.unwrap(),
                };
                let new_peer_profiles_1 = PeerProfileOf::<T> {
                    peer_addr: c.peer_profiles[0].peer_addr.clone(),
                    deposit: c.peer_profiles[0].deposit,
                    withdrawal: c.peer_profiles[0].withdrawal,
                    state: new_state,
                };
                let new_channel = ChannelOf::<T> {
                    balance_limits_enabled: c.balance_limits_enabled,
                    balance_limits: c.balance_limits,
                    settle_finalized_time: c.settle_finalized_time,
                    dispute_timeout: c.dispute_timeout,
                    token: c.token,
                    status: c.status,
                    peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                    cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                    withdraw_intent: c.withdraw_intent,
                };

                ChannelMap::<T>::mutate(&current_channel_id, |channel| {*channel = Some(new_channel)});
            } else {
                let new_state = PeerStateOf::<T> {
                    seq_num: simplex_state.seq_num,
                    transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt,
                    next_pay_id_list_hash: state.next_pay_id_list_hash,
                    last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                    pending_pay_out: simplex_state.total_pending_amount.unwrap(),
                };
                let new_peer_profiles_2 = PeerProfileOf::<T> {
                    peer_addr: c.peer_profiles[1].peer_addr.clone(),
                    deposit: c.peer_profiles[1].deposit,
                    withdrawal: c.peer_profiles[1].withdrawal,
                    state: new_state,
                };
                let new_channel = ChannelOf::<T> {
                    balance_limits_enabled: c.balance_limits_enabled,
                    balance_limits: c.balance_limits,
                    settle_finalized_time: c.settle_finalized_time,
                    dispute_timeout: c.dispute_timeout,
                    token: c.token,
                    status: c.status,
                    peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
                    cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                    withdraw_intent: c.withdraw_intent,
                };

                ChannelMap::<T>::mutate(&current_channel_id, |channel| {*channel = Some(new_channel)});
            }

            if i == state_len.checked_sub(1).ok_or(Error::<T>::UnderFlow)? {
                let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                Module::<T>::emit_snapshot_states(current_channel_id, seq_nums[0], seq_nums[1])?;
            } else if i < state_len.checked_sub(1).ok_or(Error::<T>::UnderFlow)? {
                simplex_state = signed_simplex_state_array.signed_simplex_states[i + 1].simplex_state.clone();
                // enforce channel_ids of simplex states are ascending
                ensure!(
                    current_channel_id <= simplex_state.channel_id,
                    "Non-ascending channelIds"
                );
                if current_channel_id < simplex_state.channel_id {
                    let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                    Module::<T>::emit_snapshot_states(current_channel_id,seq_nums[0],seq_nums[1])?;
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
        let c: ChannelOf<T> = match ChannelMap::<T>::get(channel_id) {
            Some(channel) => channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        let withdraw_intent = c.withdraw_intent.clone();

        ensure!(c.status == ChannelStatus::Operable, "Channel status error");

        // withdraw_intent.receiver is ledger address if and  only if there is no pending withdraw_intent.
        // because withdraw_intent.receiver may only be set as caller address which can't be ledger address.
        let ledger_addr = Self::ledger_account();
        ensure!(
            withdraw_intent.receiver == ledger_addr,
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

        let new_channel = ChannelOf::<T> {
            balance_limits_enabled: c.balance_limits_enabled,
            balance_limits: c.balance_limits,
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: c.peer_profiles,
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: new_withdraw_intent,
        };

        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));

        return Ok((channel_id, receiver, amount));
    }

    // Confirm channel withdrawal
    pub fn confirm_withdraw(
        channel_id: T::Hash,
    ) -> Result<(BalanceOf<T>, T::AccountId, T::Hash), DispatchError> {
        let c = match ChannelMap::<T>::get(&channel_id) {
            Some(_channel) => _channel,
            None => Err(Error::<T>::ChannelNotExist)?,
        };
        ensure!(c.status == ChannelStatus::Operable, "Channel status error");
        let ledger_addr = Self::ledger_account();
        let withdraw_intent = c.withdraw_intent;
        ensure!(
            withdraw_intent.receiver != ledger_addr,
            "No pending withdraw intent"
        );

        let zero_blocknumber: T::BlockNumber = Zero::zero();
        let dispute_timeout = withdraw_intent.request_time.unwrap_or(zero_blocknumber)
                .checked_add(&c.dispute_timeout).ok_or(Error::<T>::OverFlow)?;
        let block_number = frame_system::Module::<T>::block_number();
        ensure!(block_number >= dispute_timeout, "Dispute not timeout");

        let zero_balance: BalanceOf<T> = Zero::zero();
        let zero_channel_id: T::Hash = Module::<T>::zero_hash();
        let receiver = withdraw_intent.receiver;
        let amount = withdraw_intent.amount.unwrap_or(zero_balance);
        let recipient_channel_id = withdraw_intent.recipient_channel_id.unwrap_or(zero_channel_id);

        // Initialize c.wihdraw_intent
        let ledger_addr = Self::ledger_account();
        let initialize_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: ledger_addr,
            amount: None,
            request_time: None,
            recipient_channel_id: None,
        };

        // check withdraw limit
        let mut rid: u8 = 0;
        if receiver == c.peer_profiles[0].peer_addr {
            rid = 0;
        } else if receiver == c.peer_profiles[1].peer_addr {
            rid = 1;
        }
        let state_1 = c.peer_profiles[0].state.clone();
        let state_2 = c.peer_profiles[1].state.clone();
        let mut withdraw_limit: BalanceOf<T> = Zero::zero();
        let zero_balance: BalanceOf<T> = Zero::zero();
        if rid == 0 {
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[0].deposit).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_add(&state_2.transfer_out).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance)).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_1.transfer_out).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_1.pending_pay_out).ok_or(Error::<T>::UnderFlow)?;
        } else {
            withdraw_limit = withdraw_limit.checked_add(&c.peer_profiles[1].deposit).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_add(&state_1.transfer_out).ok_or(Error::<T>::OverFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&c.peer_profiles[1].clone().withdrawal.unwrap_or(zero_balance)).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_2.transfer_out).ok_or(Error::<T>::UnderFlow)?;
            withdraw_limit = withdraw_limit.checked_sub(&state_2.pending_pay_out).ok_or(Error::<T>::UnderFlow)?;
        }
        ensure!(amount <= withdraw_limit, "Exceed withdraw limit");

        // Update record of one peer's withdrawal amount
        if rid == 0 {
            let new_amount: BalanceOf<T> = c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance)
                .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: Some(new_amount),
                state: c.peer_profiles[0].clone().state,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: initialize_withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel.clone()));

            withdraw_funds::<T>(
                new_channel,
                channel_id,
                receiver.clone(),
                amount,
                recipient_channel_id,
            )?;
        } else {
            let new_amount: BalanceOf<T> = c.peer_profiles[1].clone().withdrawal.unwrap()
                .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: Some(new_amount),
                state: c.peer_profiles[1].clone().state,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: initialize_withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel.clone()));

            withdraw_funds::<T>(
                new_channel,
                channel_id,
                receiver.clone(),
                amount,
                recipient_channel_id,
            )?;
        }

        return Ok((amount, receiver, recipient_channel_id));
    }

    // Veto current withdrawal intent
    pub fn veto_withdraw(origin: T::Origin, channel_id: T::Hash) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;

        let c = ChannelMap::<T>::get(channel_id).unwrap();
        ensure!(c.status == ChannelStatus::Operable, "Channel status error");
        let intent = c.withdraw_intent.clone();
        let ledger_addr = Self::ledger_account();

        ensure!(intent.receiver != ledger_addr, "No pending withdraw intent");
        ensure!(Self::is_peer(c.clone(), caller), "caller is not peer");

        let initialize_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: ledger_addr,
            amount: None,
            request_time: None,
            recipient_channel_id: None,
        };
        let new_channel = ChannelOf::<T> {
            balance_limits_enabled: c.balance_limits_enabled,
            balance_limits: c.balance_limits,
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()],
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: initialize_withdraw_intent,
        };

        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));

        Ok(())
    }

    // Cooperatively withdraw specific amount of balance
    pub fn cooperative_withdraw(
        cooperative_withdraw_request: CooperativeWithdrawRequestOf<T>,
    ) -> Result<(T::Hash, BalanceOf<T>, T::AccountId, T::Hash, u128), DispatchError> {
        let withdraw_info = cooperative_withdraw_request.withdraw_info;
        let channel_id = withdraw_info.channel_id;
        let recipient_channel_id = withdraw_info.recipient_channel_id;

        let c = match ChannelMap::<T>::get(channel_id) {
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
        Module::<T>::valid_signers(cooperative_withdraw_request.sigs, &encoded, signers)?;

        // require an increment of exactly 1 for seq_num of each cooperative withdraw request
        let cal_seq = withdraw_info.seq_num
                .checked_sub(c.cooperative_withdraw_seq_num.unwrap_or(0)).ok_or(Error::<T>::UnderFlow)?;
        ensure!(cal_seq == 1, "seq_num error");
        ensure!(
            frame_system::Module::<T>::block_number() <= withdraw_info.withdraw_deadline,
            "Withdraw deadline passed"
        );

        let receiver = withdraw_info.withdraw.account.unwrap();
        let amount = withdraw_info.withdraw.amt;
        let zero_balance: BalanceOf<T> = Zero::zero();

        if receiver.clone() == c.peer_profiles[0].peer_addr {
            let new_withdrawal_amount = c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance)
                .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: Some(new_withdrawal_amount),
                state: c.peer_profiles[0].clone().state,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                cooperative_withdraw_seq_num: Some(withdraw_info.seq_num),
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel.clone()));

            withdraw_funds::<T>(
                new_channel,
                channel_id,
                receiver.clone(),
                amount,
                recipient_channel_id,
            )?;
        } else if receiver.clone() == c.peer_profiles[1].peer_addr {
            let new_withdrawal_amount = c.peer_profiles[1].clone().withdrawal.unwrap_or(zero_balance)
                    .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: Some(new_withdrawal_amount),
                state: c.peer_profiles[1].clone().state,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![c.peer_profiles[1].clone(), new_peer_profiles_2],
                cooperative_withdraw_seq_num: Some(withdraw_info.seq_num),
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel.clone()));

            withdraw_funds::<T>(
                new_channel,
                channel_id,
                receiver.clone(),
                amount,
                recipient_channel_id,
            )?;
        } else {
            Err(Error::<T>::NotChannelPeer)?
        }

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
        let zero_blocknumber: T::BlockNumber = Zero::zero();

        let mut simplex_state = signed_simplex_state_array.signed_simplex_states[0].simplex_state.clone();
        for i in 0..state_len {
            let current_channel_id = simplex_state.channel_id;
            let c: ChannelOf<T> = ChannelMap::<T>::get(current_channel_id).unwrap();

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
                let pay_id_len = simplex_state.pending_pay_ids.clone().unwrap().pay_ids.len();
                let encoded = encode_signed_simplex_state_array::<T>(signed_simplex_state_array.clone(),i as usize,pay_id_len as usize);
                let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
                let channel_peer = vec![
                    c.peer_profiles[0].peer_addr.clone(),
                    c.peer_profiles[1].peer_addr.clone(),
                ];
                Module::<T>::valid_signers(sigs, &encoded, channel_peer)?;

                let state: PeerStateOf<T>;
                let peer_from_id: u8;
                if c.peer_profiles[0].peer_addr == simplex_state.peer_from.clone().unwrap() {
                    state = c.peer_profiles[0].state.clone();
                    peer_from_id = 0;
                } else {
                    state = c.peer_profiles[1].state.clone();
                    peer_from_id = 1;
                }

                // Ensure each state can be intend_settle at most once
                if c.status == ChannelStatus::Operable {
                    ensure!(simplex_state.seq_num >= state.seq_num, "seqNum error");
                } else if c.status == ChannelStatus::Settling {
                    ensure!(simplex_state.seq_num > state.seq_num, "seqNum error");
                } else {
                    Err(Error::<T>::Error)?
                }

                let hash_zero = Module::<T>::zero_hash();
                let next_pay_id_list_hash = simplex_state.pending_pay_ids.clone().unwrap().next_list_hash.unwrap_or(hash_zero);
                
                if peer_from_id == 0 {
                    let new_state: PeerStateOf<T>;
                    // updating pending_pay_out is only needed when migrating ledger during settling phrase, which will
                    // affect the withdraw limit after the migration
                    if next_pay_id_list_hash == hash_zero {
                        // Update simplex_state-dependent fields
                        new_state = PeerStateOf::<T> {
                            seq_num: simplex_state.seq_num,
                            transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt.clone(),
                            next_pay_id_list_hash: None,
                            last_pay_resolve_deadline: simplex_state.last_pay_resolve_deadline.unwrap().clone(),
                            pending_pay_out: c.peer_profiles[0].clone().state.pending_pay_out,
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

                    let new_peer_profiles_1 = PeerProfileOf::<T> {
                        peer_addr: c.peer_profiles[0].peer_addr.clone(),
                        deposit: c.peer_profiles[0].deposit.clone(),
                        withdrawal: c.peer_profiles[0].clone().withdrawal.clone(),
                        state: new_state.clone(),
                    };
                    let new_channel = ChannelOf::<T> {
                        balance_limits_enabled: c.balance_limits_enabled,
                        balance_limits: c.balance_limits,
                        settle_finalized_time: c.settle_finalized_time.clone(),
                        dispute_timeout: c.dispute_timeout.clone(),
                        token: c.token.clone(),
                        status: c.status.clone(),
                        peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                        cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                        withdraw_intent: c.withdraw_intent,
                    };
                    ChannelMap::<T>::mutate(&current_channel_id, |channel| {
                        *channel = Some(new_channel.clone())
                    });

                    _clear_pays::<T>(
                        new_channel,
                        current_channel_id,
                        peer_from_id,
                        simplex_state.pending_pay_ids.clone().unwrap(),
                    )?;
                } else {
                    let new_state: PeerStateOf<T>;
                    // updating pending_pay_out is only needed when migrating ledger during settling phrase, which will
                    // affect the withdraw limit after the migration
                    if next_pay_id_list_hash == hash_zero {
                        // Update simplex_state-dependent fields
                        new_state = PeerStateOf::<T> {
                            seq_num: simplex_state.seq_num,
                            transfer_out: simplex_state.transfer_to_peer.clone().unwrap().receiver.amt.clone(),
                            next_pay_id_list_hash: None,
                            last_pay_resolve_deadline: simplex_state.last_pay_resolve_deadline.unwrap().clone(),
                            pending_pay_out: c.peer_profiles[1].clone().state.pending_pay_out,
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
                    let new_peer_profiles_2 = PeerProfileOf::<T> {
                        peer_addr: c.peer_profiles[1].peer_addr.clone(),
                        deposit: c.peer_profiles[1].deposit.clone(),
                        withdrawal: c.peer_profiles[1].clone().withdrawal.clone(),
                        state: new_state.clone(),
                    };

                    let new_channel = ChannelOf::<T> {
                        balance_limits_enabled: c.balance_limits_enabled,
                        balance_limits: c.balance_limits,
                        settle_finalized_time: c.settle_finalized_time.clone(),
                        dispute_timeout: c.dispute_timeout.clone(),
                        token: c.token.clone(),
                        status: c.status.clone(),
                        peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
                        cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                        withdraw_intent: c.withdraw_intent,
                    };
                    ChannelMap::<T>::mutate(&current_channel_id, |channel| {*channel = Some(new_channel.clone())});

                    _clear_pays::<T>(
                        new_channel,
                        current_channel_id,
                        peer_from_id,
                        simplex_state.pending_pay_ids.clone().unwrap(),
                    )?;
                }
            } else if simplex_state.seq_num == 0 {
                // null state
                // Check signautre
                let encoded = encode_signed_simplex_null_state::<T>(
                    signed_simplex_state_array.clone(),
                    i as usize,
                );
                let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
                Module::<T>::check_single_signature(sigs[0].clone(),&encoded,c.peer_profiles[0].peer_addr.clone())?;
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
        let c = ChannelMap::<T>::get(channel_id).unwrap();
        ensure!(c.status == ChannelStatus::Settling, "Channel status error");

        let pay_ids_len = pay_id_list.pay_ids.len();
        let mut encoded = pay_id_list.next_list_hash.encode();
        for i in 0..pay_ids_len {
            encoded.extend(pay_id_list.pay_ids[i].encode());
        }
        let list_hash = T::Hashing::hash(&encoded);

        if peer_from == c.peer_profiles[0].peer_addr {
            let state = c.peer_profiles[0].state.clone();
            let new_state: PeerStateOf<T>;

            let hash_zero = Module::<T>::zero_hash();
            let next_pay_id_list_hash = state.next_pay_id_list_hash.unwrap_or(hash_zero);

            if next_pay_id_list_hash != hash_zero {
                ensure!(next_pay_id_list_hash == list_hash, "List hash mismatch");

                new_state = PeerStateOf::<T> {
                    seq_num: state.seq_num,
                    transfer_out: state.transfer_out,
                    next_pay_id_list_hash: Some(next_pay_id_list_hash),
                    last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                    pending_pay_out: state.pending_pay_out,
                };
            } else {
                new_state = PeerStateOf::<T> {
                    seq_num: state.seq_num,
                    transfer_out: state.transfer_out,
                    next_pay_id_list_hash: None,
                    last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                    pending_pay_out: state.pending_pay_out,
                };
            }

            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: c.peer_profiles[0].clone().withdrawal,
                state: new_state,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel.clone()));

            _clear_pays::<T>(new_channel, channel_id, 0, pay_id_list)?;
        } else if peer_from == c.peer_profiles[1].peer_addr {
            let state = c.peer_profiles[1].clone().state;
            let new_state: PeerStateOf<T>;

            let hash_zero = Module::<T>::zero_hash();
            let next_pay_id_list_hash = state.next_pay_id_list_hash.unwrap_or(hash_zero);
            if next_pay_id_list_hash != hash_zero {
                ensure!(next_pay_id_list_hash == list_hash, "List hash mismatch");

                new_state = PeerStateOf::<T> {
                    seq_num: state.seq_num,
                    transfer_out: state.transfer_out,
                    next_pay_id_list_hash: Some(next_pay_id_list_hash),
                    last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                    pending_pay_out: state.pending_pay_out,
                };
            } else {
                new_state = PeerStateOf::<T> {
                    seq_num: state.seq_num,
                    transfer_out: state.transfer_out,
                    next_pay_id_list_hash: None,
                    last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                    pending_pay_out: state.pending_pay_out,
                };
            }

            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: c.peer_profiles[1].clone().withdrawal,
                state: new_state,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel.clone()));

            _clear_pays::<T>(new_channel, channel_id, 1, pay_id_list)?;
        }

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

        // require channel status of current intend_settle has benn finalized,
        // namely all payment have already been either cleared or expired
        // Note: this last PayResolveDeadline should use
        //      (the actual last resolve deadline of all pays + clear_pays safe margin)
        //      to ensure that peers have enough time to clear_pays before confirm_settle.
        //      Howener this only matters if there are multiple blocks of pending pay list
        //      i.e. the next_pay_id_list_hash after intend_settle is not Hash(0).
        // TODO: add an additonal clear_safe_margin param or change the semantics of
        // last_pay_resolve_deadline to also include clear_pays safe margin and rename it.
        let state_1 = peer_profiles[0].state.clone();
        let state_2 = peer_profiles[1].state.clone();
        let hash_zero = Module::<T>::zero_hash();

        ensure!(
            (state_1.next_pay_id_list_hash.unwrap_or(hash_zero) == hash_zero
                || block_number > state_1.last_pay_resolve_deadline)
                && (state_2.next_pay_id_list_hash.unwrap_or(hash_zero) == hash_zero
                    || block_number > state_2.last_pay_resolve_deadline),
            "Payments are not finalized"
        );

        let (valid_balance, settle_balance): (bool, Vec<BalanceOf<T>>) =
            validate_settle_balance::<T>(c.clone())?;

        if valid_balance == false {
            reset_duplex_state::<T>(c.clone(), channel_id);
            Module::<T>::emit_confirm_settle_fail(channel_id)?;
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

        return Ok((channel_id, settle_balance));
    }

    // Cooperatively settle the channel
    pub fn cooperative_settle(
        settle_request: CooperativeSettleRequestOf<T>,
    ) -> Result<(T::Hash, Vec<BalanceOf<T>>), DispatchError> {
        let settle_info = settle_request.settle_info;
        let channel_id = settle_info.channel_id;
        let c = ChannelMap::<T>::get(channel_id).unwrap();
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
        Module::<T>::valid_signers(settle_request.sigs, &encoded, signers)?;

        let peer_addrs = vec![
            c.peer_profiles[0].peer_addr.clone(),
            c.peer_profiles[1].peer_addr.clone(),
        ];
        let state_1 = c.peer_profiles[0].state.clone();
        let state_2 = c.peer_profiles[1].state.clone();

        ensure!(
            settle_info.seq_num > state_1.seq_num && settle_info.seq_num > state_2.seq_num,
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
            .checked_add(&settle_balance[1])
            .ok_or(Error::<T>::OverFlow)?;
        let total_balance = Module::<T>::get_total_balance(channel_id)?;
        ensure!(
            total_settle_balance == total_balance,
            "Balance sum mismatch"
        );

        update_channel_status::<T>(c, channel_id, ChannelStatus::Closed)?;

        batch_transfer_out::<T>(channel_id, peer_addrs, settle_balance.clone())?;

        return Ok((channel_id, settle_balance));
    }

    // Check if addr is one of the peers in channel c
    pub fn is_peer(c: ChannelOf<T>, addr: T::AccountId) -> bool {
        return addr == c.peer_profiles[0].peer_addr || addr == c.peer_profiles[1].peer_addr;
    }

    // Get address of ledger module
    pub fn ledger_account() -> T::AccountId {
        CELER_LEDGER_ID.into_account()
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

    let zero_balance: BalanceOf<T> = Zero::zero();
    let new_balance = zero_balance;
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

    return wallet_id;
}

// Internal function to add deposit of a channel
fn add_deposit<T: Trait>(
    channel_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    let c: ChannelOf<T> = match ChannelMap::<T>::get(&channel_id) {
        Some(channel) => channel,
        None => Err(Error::<T>::ChannelNotExist)?,
    };
    ensure!(c.status == ChannelStatus::Operable, "Channel status errror");

    if c.balance_limits_enabled == true {
        let total_balance = Module::<T>::get_total_balance(channel_id.clone())?;
        let added_amount = amount.checked_add(&total_balance).ok_or(Error::<T>::OverFlow)?;
        let limits = match c.balance_limits {
            Some(limits) => limits,
            None => Err(Error::<T>::BalanceLimitsNotExist)?,
        };
        ensure!(added_amount <= limits, "Balance exceeds limit");
    }

    let new_deposit_balance: BalanceOf<T>;
    let new_channel: ChannelOf<T>;
    if receiver == c.peer_profiles[0].peer_addr {
        new_deposit_balance = c.peer_profiles[0].deposit.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        let new_peer_profiles_1 = PeerProfileOf::<T> {
            peer_addr: c.peer_profiles[0].peer_addr.clone(),
            deposit: new_deposit_balance,
            withdrawal: c.peer_profiles[0].clone().withdrawal,
            state: c.peer_profiles[0].clone().state,
        };
        new_channel = ChannelOf::<T> {
            balance_limits_enabled: c.balance_limits_enabled,
            balance_limits: c.balance_limits,
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: c.withdraw_intent,
        };
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
    } else if receiver == c.peer_profiles[1].peer_addr {
        new_deposit_balance = c.peer_profiles[1].deposit.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        let new_peer_profiles_2 = PeerProfileOf::<T> {
            peer_addr: c.peer_profiles[1].peer_addr.clone(),
            deposit: new_deposit_balance,
            withdrawal: c.peer_profiles[1].clone().withdrawal,
            state: c.peer_profiles[1].clone().state,
        };
        new_channel = ChannelOf::<T> {
            balance_limits_enabled: c.balance_limits_enabled,
            balance_limits: c.balance_limits,
            settle_finalized_time: c.settle_finalized_time,
            dispute_timeout: c.dispute_timeout,
            token: c.token,
            status: c.status,
            peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
            cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
            withdraw_intent: c.withdraw_intent,
        };
        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
    } else {
        Err(Error::<T>::NotChannelPeer)?
    }

    // emit Deposit event
    Module::<T>::emit_deposit_event(channel_id)?;

    Ok(())
}

// Internal function to transfer funds out in batch
fn batch_transfer_out<T: Trait>(
    channel_id: T::Hash,
    receivers: Vec<T::AccountId>,
    amounts: Vec<BalanceOf<T>>,
) -> Result<(), DispatchError> {
    let zero_balance: BalanceOf<T> = Zero::zero();
    for i in 0..2 {
        if amounts[i] == zero_balance {
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
    let zero_balance: BalanceOf<T> = Zero::zero();
    if amount == zero_balance {
        return Ok(());
    }

    let zero_channel_id: T::Hash = Module::<T>::zero_hash();
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
fn reset_duplex_state<T: Trait>(c: ChannelOf<T>, channel_id: T::Hash) {
    let new_channel = ChannelOf::<T> {
        balance_limits_enabled: c.balance_limits_enabled,
        balance_limits: c.balance_limits,
        settle_finalized_time: None,
        dispute_timeout: c.dispute_timeout,
        token: c.token,
        status: c.status,
        peer_profiles: vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()],
        cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
        withdraw_intent: c.withdraw_intent,
    };

    ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
}

// Clear payments by their hash array
fn _clear_pays<T: Trait>(
    c: ChannelOf<T>,
    channel_id: T::Hash,
    peer_id: u8,
    pay_id_list: PayIdList<T::Hash>,
) -> Result<(), DispatchError> {
    let zero_balance: BalanceOf<T> = Zero::zero();
    let out_amts: Vec<BalanceOf<T>>;

    if peer_id == 0 {
        let state_1 = c.peer_profiles[0].state.clone();
        out_amts = PayRegistry::<T>::get_pay_amounts(
            pay_id_list.pay_ids.clone(),
            state_1.last_pay_resolve_deadline,
        )?;
        let mut total_amt_out: BalanceOf<T> = Zero::zero();
        let out_amts_len = out_amts.len();
        for i in 0..out_amts_len {
            total_amt_out = total_amt_out
                .checked_add(&out_amts[i])
                .ok_or(Error::<T>::OverFlow)?;
            // emit ClearOnePay event
            Module::<T>::emit_clear_one_pay(
                channel_id,
                pay_id_list.pay_ids[i].clone(),
                c.peer_profiles[peer_id as usize].clone().peer_addr,
                out_amts[i],
            )?;
        }

        // updating pending_pay_out is only needed when migrating ledger during settling phrase,
        // which will affect the withdraw limit after the migration.
        let new_transfer_out_1 = state_1.transfer_out.checked_add(&total_amt_out).ok_or(Error::<T>::OverFlow)?;
        let hash_zero = Module::<T>::zero_hash();
        if pay_id_list.next_list_hash.unwrap_or(hash_zero) == hash_zero {
            // if there are not more uncleared pays in this state, the pending_pay_out must be 0
            let new_state_1 = PeerStateOf::<T> {
                seq_num: state_1.seq_num,
                transfer_out: new_transfer_out_1,
                next_pay_id_list_hash: None,
                last_pay_resolve_deadline: state_1.last_pay_resolve_deadline,
                pending_pay_out: zero_balance,
            };
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: c.peer_profiles[0].clone().withdrawal,
                state: new_state_1,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else {
            // Note: if there are more uncleared pays in this state, because resolved pay amount
            //      is always less than or equal to the corresponding maximum amount counted in
            //      pending_pay_out, the updated pending_pay_out may be equal to or larger than the real
            //      pending_pay_out. This will lead to decreasing the maximum withdraw amount (withdraw_limit)
            //      from potentially maliciout non-cooperative withdraw.
            let new_pending_pay_out = state_1.pending_pay_out.checked_sub(&total_amt_out).ok_or(Error::<T>::OverFlow)?;
            let new_state_1 = PeerStateOf::<T> {
                seq_num: state_1.seq_num,
                transfer_out: new_transfer_out_1,
                next_pay_id_list_hash: state_1.next_pay_id_list_hash,
                last_pay_resolve_deadline: state_1.last_pay_resolve_deadline,
                pending_pay_out: new_pending_pay_out,
            };
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: c.peer_profiles[0].clone().withdrawal,
                state: new_state_1,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![new_peer_profiles_1, c.peer_profiles[1].clone()],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        }
    } else {
        let state_2 = c.peer_profiles[1].state.clone();
        out_amts = PayRegistry::<T>::get_pay_amounts(
            pay_id_list.pay_ids.clone(),
            state_2.last_pay_resolve_deadline,
        )?;
        let mut total_amt_out: BalanceOf<T> = Zero::zero();
        let out_amts_len = out_amts.len();
        for i in 0..out_amts_len {
            total_amt_out = total_amt_out.checked_add(&out_amts[i]).ok_or(Error::<T>::OverFlow)?;
            // emit ClearOnePay event
            Module::<T>::emit_clear_one_pay(
                channel_id,
                pay_id_list.pay_ids[i].clone(),
                c.peer_profiles[peer_id as usize].clone().peer_addr,
                out_amts[i],
            )?;
        }

        // updating pending_pay_out is only needed when migrating ledger during settling phrase,
        // which will affect the withdraw limit after the migration.
        let new_transfer_out_2 = state_2.transfer_out.checked_add(&total_amt_out).ok_or(Error::<T>::OverFlow)?;
        let hash_zero = Module::<T>::zero_hash();
        if pay_id_list.next_list_hash.unwrap_or(hash_zero) == hash_zero {
            // if there are not more uncleared pays in this state, the pending_pay_out must be 0
            let new_state_2 = PeerStateOf::<T> {
                seq_num: state_2.seq_num,
                transfer_out: new_transfer_out_2,
                next_pay_id_list_hash: None,
                last_pay_resolve_deadline: state_2.last_pay_resolve_deadline,
                pending_pay_out: zero_balance,
            };
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: c.peer_profiles[1].clone().withdrawal,
                state: new_state_2,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else {
            // Note: if there are more uncleared pays in this state, because resolved pay amount
            //      is always less than or equal to the corresponding maximum amount counted in
            //      pending_pay_out, the updated pending_pay_out may be equal to or larger than the real
            //      pending_pay_out. This will lead to decreasing the maximum withdraw amount (withdraw_limit)
            //      from potentially maliciout non-cooperative withdraw.
            let new_pending_pay_out = state_2.pending_pay_out.checked_sub(&total_amt_out).ok_or(Error::<T>::UnderFlow)?;
            let new_state_2 = PeerStateOf::<T> {
                seq_num: state_2.seq_num,
                transfer_out: new_transfer_out_2,
                next_pay_id_list_hash: state_2.next_pay_id_list_hash,
                last_pay_resolve_deadline: state_2.last_pay_resolve_deadline,
                pending_pay_out: new_pending_pay_out,
            };
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: c.peer_profiles[1].clone().withdrawal,
                state: new_state_2,
            };
            let new_channel = ChannelOf::<T> {
                balance_limits_enabled: c.balance_limits_enabled,
                balance_limits: c.balance_limits,
                settle_finalized_time: c.settle_finalized_time,
                dispute_timeout: c.dispute_timeout,
                token: c.token,
                status: c.status,
                peer_profiles: vec![c.peer_profiles[0].clone(), new_peer_profiles_2],
                cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                withdraw_intent: c.withdraw_intent,
            };
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        }
    }

    Ok(())
}

/// Update overall states of a duplex channel
fn update_overall_states_by_intend_state<T: Trait>(
    channel_id: T::Hash,
) -> Result<(), DispatchError> {
    let c = match ChannelMap::<T>::get(channel_id) {
        Some(channel) => channel,
        None => Err(Error::<T>::NotChannelPeer)?,
    };

    let new_setttle_finalized_time: T::BlockNumber = frame_system::Module::<T>::block_number().checked_add(&c.dispute_timeout).ok_or(Error::<T>::OverFlow)?;
    let new_channel = ChannelOf::<T> {
        balance_limits_enabled: c.balance_limits_enabled,
        balance_limits: c.balance_limits,
        settle_finalized_time: Some(new_setttle_finalized_time),
        dispute_timeout: c.dispute_timeout,
        token: c.token,
        status: c.status,
        peer_profiles: vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()],
        cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
        withdraw_intent: c.withdraw_intent,
    };
    ChannelMap::<T>::mutate(channel_id, |channel| *channel = Some(new_channel.clone()));
    update_channel_status::<T>(new_channel, channel_id, ChannelStatus::Settling)?;

    let seq_nums = get_state_seq_nums::<T>(channel_id);
    // emit IntendSettle event
    Module::<T>::emit_intend_settle(channel_id, seq_nums)?;

    Ok(())
}

/// Update status of a channel
fn update_channel_status<T: Trait>(
    c: ChannelOf<T>,
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
        status_nums = match Module::<T>::channel_status_nums(c.status.clone() as u8) {
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
    new_status_nums = match Module::<T>::channel_status_nums(new_status.clone() as u8) {
        Some(num) => num as u8,
        None => 0 as u8,
    };
    let new_nums_2 = new_status_nums + 1;
    ChannelStatusNums::mutate(new_status.clone() as u8, |num| *num = Some(new_nums_2));

    let new_channel = ChannelOf::<T> {
        balance_limits_enabled: c.balance_limits_enabled,
        balance_limits: c.balance_limits,
        settle_finalized_time: c.settle_finalized_time,
        dispute_timeout: c.dispute_timeout,
        token: c.token,
        status: new_status.clone(),
        peer_profiles: vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()],
        cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
        withdraw_intent: c.withdraw_intent,
    };

    ChannelMap::<T>::mutate(channel_id, |channel| *channel = Some(new_channel));

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

    let zero_balance: BalanceOf<T> = Zero::zero();

    for i in 0..2 {
        let sub_amt = c.peer_profiles[i as usize].clone().state.transfer_out
                .checked_add(&c.peer_profiles[i as usize].withdrawal.unwrap_or(zero_balance)).ok_or(Error::<T>::OverFlow)?;
        if settle_balance[i as usize] < sub_amt {
            return Ok((false, vec![zero_balance, zero_balance]));
        }

        settle_balance[i as usize] = settle_balance[i as usize]
            .checked_sub(&sub_amt).ok_or(Error::<T>::UnderFlow)?;
    }

    return Ok((true, vec![settle_balance[0], settle_balance[1]]));
}

/// Get the seqNums of two simplex channel states
fn get_state_seq_nums<T: Trait>(channel_id: T::Hash) -> Vec<u128> {
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    let state_1 = c.peer_profiles[0].clone().state;
    let state_2 = c.peer_profiles[1].clone().state;
    return vec![state_1.seq_num, state_2.seq_num];
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
    Module::<T>::emit_withdraw_from_wallet(wallet_id, receiver, amount)?;
    Ok(())
}

fn is_wallet_owner<T: Trait>(wallet_id: T::Hash, addr: T::AccountId) -> bool {
    let w: WalletOf<T> = Wallets::<T>::get(wallet_id).unwrap();
    let len = w.owners.len() - 1;
    for i in 0..len {
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

    let wallet_account = celer_wallet_account::<T>();

    let mut new_amount: BalanceOf<T> = Zero::zero();
    if op == MathOperation::Sub {
        ensure!(w.balance >= amount, "balance of amount is not deposited");
        new_amount = w.balance.checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_amount,
        };

        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));

        T::Currency::transfer(
            &wallet_account,
            &caller,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;
    } else if op == MathOperation::Add {
        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances."
        );
        new_amount = w.balance.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_amount,
        };

        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));

        T::Currency::transfer(
            &caller,
            &wallet_account,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;
    } else {
        Err(Error::<T>::Error)?
    }

    Ok(())
}

fn celer_wallet_account<T: Trait>() -> T::AccountId {
    WALLET_ID.into_account()
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
    state_index: usize,
    pay_id_len: usize,
) -> Vec<u8> {
    let mut encoded = signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.channel_id.encode();
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.peer_from.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.seq_num.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.transfer_to_peer.unwrap().token.token_type.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.transfer_to_peer.unwrap().receiver.account.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.transfer_to_peer.unwrap().receiver.amt.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.pending_pay_ids.unwrap().next_list_hash.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.last_pay_resolve_deadline.encode());
    encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].simplex_state.total_pending_amount.encode());
    for j in 0..pay_id_len {
        encoded.extend(signed_simplex_state_array.signed_simplex_states[state_index].clone().simplex_state.pending_pay_ids.unwrap().pay_ids[j].encode());
    }

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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::mock::*;
    use crate::pay_resolver::tests::*;
    use crate::pay_resolver::{
        Condition, ConditionalPay, PayResolver, ResolvePaymentConditionsRequest, TokenTransfer,
        TransferFunction, TransferFunctionType,
    };
    use crate::RawEvent;
    use frame_support::{assert_noop, assert_ok};
    use sp_core::{hashing, sr25519, Pair, H256};
    use sp_runtime::DispatchError;

    #[test]
    fn test_pass_return_uninitialized_status_for_an_inexistent_channel() {
        ExtBuilder::build().execute_with(|| {
            let random_channel_id: H256 = H256::from_low_u64_be(3);
            let status = CelerModule::get_channel_status(random_channel_id);
            assert_eq!(status, ChannelStatus::Uninitialized);
        })
    }

    #[test]
    fn test_fail_open_channel_after_open_deadline() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(false, 0, 0, 20, true, channel_peers.clone(), 0, peers_pair,);
            let err = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Open deadline passed"));
        })
    }

    #[test]
    fn test_fail_open_channel_with_deposits_with_deposits_before_setting_deposit_limits() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            approve(channel_peers[1], ledger_addr, 200);

            let open_channel_request = get_open_channel_request(true, 100, 5000000, 10, false, channel_peers.clone(), 1, peers_pair);
            let err = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Balance exceeds limit"));
        })
    }

    #[test]
    fn test_pass_open_channel_when_total_deposit_is_zero() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();
            let cal_channel_id = calculate_channel_id(open_channel_request, channel_peers);
            assert_eq!(channel_id, cal_channel_id);
        })
    }

    #[test]
    fn test_fail_open_channel_again_with_the_same_channel_id() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let _ = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            // Again open channel with same channel id
            let err = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Occupied wallet id"));
        })
    }

    #[test]
    fn test_fail_cooperative_withdraw_because_of_no_deposit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // Open channel zero deposit.
            let open_channel_request = get_open_channel_request(false, 0, 500000, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request = get_cooperative_withdraw_request(channel_id, 1, 100, channel_peers[1], 10, zero_channel_id, peers_pair,);
            let err =LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("balance of amount is not deposited")
            );
        })
    }

    #[test]
    fn test_pass_open_another_channel() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request_1 = get_open_channel_request(false, 0, 500000, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id_1 = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request_1.clone(),
                0,
            ).unwrap();
            let cal_channel_id_1 = calculate_channel_id(open_channel_request_1, channel_peers.clone());
            assert_eq!(channel_id_1, cal_channel_id_1);

            // Open channel with another channel id
            let open_channel_request_2 = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id_2 = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request_2.clone(),
                0,
            ).unwrap();
            let cal_channel_id_2 = calculate_channel_id(open_channel_request_2, channel_peers);
            assert_eq!(channel_id_2, cal_channel_id_2);
        })
    }

    #[test]
    fn test_fail_deposit_before_setting_deposit_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(false, 0, 50000, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(CelerModule::enable_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id
            ));

            assert_noop!(
                LedgerOperation::<TestRuntime>::deposit(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    channel_peers[0],
                    100,
                    0
                ),
                Error::<TestRuntime>::BalanceLimitsNotExist
            );
        })
    }

    #[test]
    fn test_fail_set_deposit_limits_if_not_owner() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let risa = account_key("Risa"); // not owner
            let err = CelerModule::set_balance_limits(Origin::signed(risa), channel_id, 200).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller is not channel peer"));
        })
    }

    #[test]
    fn test_pass_set_deposit_limits() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(CelerModule::set_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id,
                300
            ));
            let amount = CelerModule::get_balance_limit(channel_id).unwrap();
            assert_eq!(amount, 300);
        })
    }

    #[test]
    fn test_pass_open_channel_with_funds_correctly_after_setting_deposit_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // deposit celer to pool by channel_peers[1]
            let _ = Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[1]),
                channel_peers[1],
                200,
            ).unwrap();
            // approve ledger to spend
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            approve(channel_peers[1], ledger_addr, 200);
            let open_channel_request = get_open_channel_request(true, 10000, 500000, 10, false, channel_peers.clone(), 0, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request.clone(),
                100,
            ).unwrap();

            let cal_channel_id = calculate_channel_id(open_channel_request, channel_peers);
            assert_eq!(channel_id, cal_channel_id);
        })
    }

    #[test]
    fn test_pass_deposit_coorectly_with_caller_amount() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                100,
                0
            ));
        })
    }

    #[test]
    fn test_fail_deposit_when_new_deposit_sum_exceeds_the_deposit_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let err_1 = LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                1000,
                0,
            ).unwrap_err();
            assert_eq!(err_1, DispatchError::Other("Balance exceeds limit"));

            let err_2 = LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                100,
                0,
            ).unwrap_err();
            assert_eq!(err_2, DispatchError::Other("Balance exceeds limit"));
        })
    }

    #[test]
    fn test_fail_disable_balance_limits_by_not_owner() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let risa = account_key("Risa");
            let err =
                CelerModule::disable_balance_limits(Origin::signed(risa), channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller is not channel peer"));
        })
    }

    #[test]
    fn test_pass_disable_balance_limits() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(CelerModule::disable_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_pass_deposit_after_removing_deposit_limits() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();
            let _ = CelerModule::disable_balance_limits(Origin::signed(channel_peers[0]), channel_id).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                100,
                0
            ));
        })
    }

    #[test]
    fn test_fail_enable_balance_limits_by_not_owner() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let risa = account_key("Risa");
            let err = CelerModule::enable_balance_limits(Origin::signed(risa), channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller is not channel peer"));
        })
    }

    #[test]
    fn test_fail_deposit_after_balance_limits_reenabled_and_being_exceeded() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            // enable balance limit and set balance limit
            let _ = CelerModule::enable_balance_limits(Origin::signed(channel_peers[0]), channel_id).unwrap();
            let _ = CelerModule::set_balance_limits(Origin::signed(channel_peers[0]), channel_id, 10).unwrap();

            let err = LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                100,
                0,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Balance exceeds limit"));
        })
    }

    #[test]
    fn test_pass_deposit_via_pool() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 400, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            // deposit celer to pool by channel_peers[0]
            let _ = Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                200,
            ).unwrap();
            // approve ledger to spend
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            approve(channel_peers[0], ledger_addr, 200);

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                0,
                100
            ));
        })
    }

    #[test]
    fn test_pass_intend_withdraw_correctly() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let (_channel_id, _receiver, _amount) =
                LedgerOperation::<TestRuntime>::intend_withdraw(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    200,
                    zero_channel_id,
                ).unwrap();
            assert_eq!(channel_id, _channel_id);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_amount, 200);
        })
    }

    #[test]
    fn test_fail_intent_withdraw_when_there_is_a_pending_withdraw_intent() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();

            let err = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Pending withdraw intent exists"));
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_before_confirmable_time() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Dispute not timeout"));
        })
    }

    #[test]
    fn test_pass_veto_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::veto_withdraw(
                Origin::signed(channel_peers[1]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_after_veto_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let channel_id = veto_withdraw();

            System::set_block_number(System::block_number() + 11);

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("No pending withdraw intent"));
        })
    }

    #[test]
    fn test_pass_confirm_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();

            System::set_block_number(System::block_number() + 11);

            let (amount, receiver, recipient_channel_id) =
                LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap();
            assert_eq!(amount, 200);
            assert_eq!(receiver, channel_peers[0]);
            assert_eq!(recipient_channel_id, zero_channel_id);
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_again_after_confirm_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 11);
            let _ = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap();

            // Again call confirm_withdraw()
            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("No pending withdraw intent"));
        })
    }

    // TODO: test_fail_intend_withdraw_and_confrim_withdraw_from_celer_channel_to_another_channel()
    // Currently, Only support celer channel

    #[test]
    fn test_fail_cooperative_withdraw_after_withdraw_deadline() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            System::set_block_number(2);
            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                200,
                channel_peers[0],
                0,
                zero_channel_id,
                peers_pair,
            );
            let err =
                LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Withdraw deadline passed"));
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_receiver_has_enough_deposit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                200,
                channel_peers[0],
                9999999,
                zero_channel_id,
                peers_pair,
            );
            let (_channel_id, _amount, _receiver, _, _withdraw_info_seq_num) =
                LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();
            assert_eq!(_channel_id, channel_id);
            assert_eq!(_amount, 200);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_withdraw_info_seq_num, 1);
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_using_an_unexpected_seq_num() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));

            // smaller seq_num than expected one
            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                0,
                200,
                channel_peers[0],
                9999999,
                zero_channel_id,
                peers_pair.clone(),
            );
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("seq_num error"));

            // larger seq_num than expected one
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                2,
                200,
                channel_peers[0],
                9999999,
                zero_channel_id,
                peers_pair.clone(),
            );
            let err =
                LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("seq_num error"));

            // expected seq_num
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                200,
                channel_peers[0],
                9999999,
                zero_channel_id,
                peers_pair.clone(),
            );
            let (_channel_id, _amount, _receiver, _, _withdraw_info_seq_num) =
                LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();
            assert_eq!(_channel_id, channel_id);
            assert_eq!(_amount, 200);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_withdraw_info_seq_num, 1);
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_receiver_does_not_have_enough_deposit_but_the_whole_channel_does(
    ) {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                160,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                40,
                0
            ));

            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                200,
                channel_peers[0],
                9999999,
                zero_channel_id,
                peers_pair.clone(),
            );
            let (
                _channel_id,
                _withdrawn_amount,
                _receiver,
                _recipient_channel_id,
                _withdraw_info_seq_num,
            ) = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();

            let balance_amt = CelerModule::get_total_balance(channel_id).unwrap();
            let (_channel_peer, _deposits, _withdrawals): (
                Vec<AccountId>,
                Vec<Balance>,
                Vec<Balance>,
            ) = CelerModule::get_balance_map(channel_id);

            assert_eq!(_channel_id, channel_id);
            assert_eq!(_withdrawn_amount, 200);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_recipient_channel_id, zero_channel_id);
            assert_eq!(_withdraw_info_seq_num, 1);
            assert_eq!(balance_amt, 0);
            assert_eq!(_channel_peer, channel_peers);
            assert_eq!(_deposits, [160, 40]);
            assert_eq!(_withdrawals, [200, 0]);
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_to_another_channel() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let risa_pair = account_pair("Risa");
            let (channel_peers_1, peers_pair_1) =
                get_sorted_peer(alice_pair.clone(), risa_pair.clone());
            let (channel_peers_2, peers_pair_2) =
                get_sorted_peer(bob_pair.clone(), risa_pair.clone());

            let open_channel_request_1 = get_open_channel_request(true, 800, 500001, 10, true, channel_peers_1.clone(), 1, peers_pair_1.clone());
            let channel_id_1 = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers_1[1]),
                open_channel_request_1.clone(),
                0,
            ).unwrap();
            let open_channel_request_2 = get_open_channel_request(true, 800, 500001, 10, true, channel_peers_2.clone(), 1, peers_pair_2.clone());
            let channel_id_2 = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers_2[1]),
                open_channel_request_2.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers_1[0]),
                channel_id_1,
                channel_peers_1[0],
                200,
                0
            ));

            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id_1,
                1,
                200,
                channel_peers_1[0],
                9999999,
                channel_id_2,
                peers_pair_1.clone(),
            );
            let (
                _channel_id,
                _withdrawn_amount,
                _receiver,
                _recipient_channel_id,
                _withdraw_info_seq_num,
            ) = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();

            let _balance_amt_1 = CelerModule::get_total_balance(channel_id_1).unwrap();
            let (_channel_peer_1, _deposits_1, _withdrawals_1): (Vec<AccountId>, Vec<Balance>, Vec<Balance>) 
                = CelerModule::get_balance_map(channel_id_1);
            let _balance_amt_2 = CelerModule::get_total_balance(channel_id_2).unwrap();
            let (_channel_peer_2, _deposits_2, _withdrawals_2): (Vec<AccountId>, Vec<Balance>, Vec<Balance>) 
                = CelerModule::get_balance_map(channel_id_2);

            assert!(
                channel_peers_2[0] == channel_peers_1[0]
                    || channel_peers_2[1] == channel_peers_1[0]
            );
            let expected_deposits: Vec<Balance>;
            if channel_peers_2[0] == channel_peers_1[0] {
                expected_deposits = [200, 0].to_vec();
            } else {
                expected_deposits = [0, 200].to_vec();
            }

            assert_eq!(_channel_id, channel_id_1);
            assert_eq!(_withdrawn_amount, 200);
            assert_eq!(_receiver, channel_peers_1[0]);
            assert_eq!(_recipient_channel_id, channel_id_2);
            assert_eq!(_withdraw_info_seq_num, 1);
            assert_eq!(_balance_amt_1, 0);
            assert_eq!(_channel_peer_1, channel_peers_1);
            assert_eq!(_deposits_1, expected_deposits);
            assert_eq!(_withdrawals_1, [200, 0]);
            assert_eq!(_balance_amt_2, 200);
            assert_eq!(_channel_peer_2, channel_peers_2);
            assert_eq!(_deposits_2, expected_deposits);
            assert_eq!(_withdrawals_2, [0, 0]);
        })
    }

    #[test]
    fn test_fail_cooperative_withdraw_to_another_channel_without_such_a_receiver() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let risa_pair = account_pair("Risa");
            let carl_pair = account_pair("Carl");
            let (channel_peers, peers_pair_1) =
                get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let (different_peers, peers_pair_2) =
                get_sorted_peer(risa_pair.clone(), carl_pair.clone());

            let open_channel_request_1 = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair_1.clone());
            let channel_id_1 = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request_1.clone(),
                0,
            ).unwrap();
            let open_channel_request_2 = get_open_channel_request(true, 800, 500001, 10, true, different_peers.clone(), 1, peers_pair_2.clone());
            let channel_id_2 = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request_2.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id_1,
                channel_peers[0],
                200,
                0
            ));

            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id_1,
                1,
                200,
                different_peers[0],
                9999999,
                channel_id_2,
                peers_pair_1.clone(),
            );
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Module {
                    index: 0,
                    error: 7,
                    message: Some("NotChannelPeer")
                }
            );
        })
    }

    #[test]
    fn test_fail_intend_settle_when_some_pays_in_head_list_are_not_finalized_before_last_pay_resolve_deadline(
    ) {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![100, 200],     // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            // resolve only one payment
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pays[0][0][0].clone(),
                hash_preimages: vec![],
            };

            let (pay_id, _amount_1, _) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();

            System::set_block_number(System::block_number() + 6);

            let simplex_state = signed_simplex_state_array.signed_simplex_states[0].simplex_state.clone();
            let pay_id_list = simplex_state.pending_pay_ids.unwrap();
            assert_eq!(pay_id, pay_id_list.pay_ids[0]);

            let err = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Payment is not finalized"));
        })
    }

    #[test]
    fn test_pass_intend_settle_correctly_when_all_pays_in_head_list_are_finalized_before_last_pay_resolve_deadline(
    ) {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            // resolve the payments in head PayIdList
            // the head list of peer_from 0
            for i in 0..cond_pays[0][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // the head list of peer_from 1
            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            assert_eq!(settle_finalized_time, System::block_number() + 10);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Settling);

            let peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
            assert_eq!(peers_migration_info.4, vec![13, 31]);
            assert_eq!(peers_migration_info.5, vec![7, 15]);

            let amounts = vec![1, 2, 5, 6];
            for i in 0..2 {
                // for each simplex state
                for j in 0..2 {
                    // for each pays in head PayIdList
                    let log_index = i * 2 + j;
                    let encoded = encode_conditional_pay(cond_pays[i][0][j].clone());
                    let pay_hash = hashing::blake2_256(&encoded).into();
                    let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                    let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                        channel_id,
                        pay_id,
                        channel_peers[i as usize],
                        amounts[log_index],
                    ));
                    assert!(System::events().iter().any(|a| a.event == expected_event));
                }
            }
        })
    }

    #[test]
    fn test_fail_clear_pays_when_payments_are_not_finalized_before_last_pay_resolve_deadline() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            // resolve the payments in head PayIdList
            // the head list of peer_from 0
            for i in 0..cond_pays[0][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let pay_id_list_array = global_result.4;

            let mut err = PayRegistry::<TestRuntime>::get_pay_amounts(
                pay_id_list_array[0][1].pay_ids.clone(),
                10,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Payment is not finalized"));

            err = LedgerOperation::<TestRuntime>::clear_pays(
                channel_id,
                channel_peers[0],
                pay_id_list_array[0][1].clone(),
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Payment is not finalized"));
        })
    }

    #[test]
    fn test_pass_clear_pays_when_payments_are_fianized() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            for peer_index in 0..2 {
                for list_index in 0..cond_pays[peer_index as usize].len() {
                    for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                        let pay_request = ResolvePaymentConditionsRequest {
                            cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                            hash_preimages: vec![],
                        };
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                    }
                }
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let pay_id_list_array = global_result.4;
            let amounts = vec![vec![3, 4], vec![7, 8]];

            for peer_index in 0..2 {
                assert_ok!(CelerModule::clear_pays(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));

                let mut count = 0;
                for list_index in 1..cond_pays[peer_index as usize].len() {
                    for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                        let encoded = encode_conditional_pay(
                            cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                        );
                        let pay_hash = hashing::blake2_256(&encoded).into();
                        let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                        let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                            channel_id,
                            pay_id,
                            channel_peers[peer_index as usize],
                            amounts[peer_index as usize][count as usize],
                        ));
                        assert!(System::events().iter().any(|a| a.event == expected_event));
                        count += 1;
                    }
                }
            }
        })
    }

    #[test]
    fn test_fail_confirm_settle_due_to_not_reaching_settle_finalized_time() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            for peer_index in 0..2 {
                for list_index in 0..2 {
                    for pay_index in 0..2 {
                        let pay_request = ResolvePaymentConditionsRequest {
                            cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                            hash_preimages: vec![],
                        };
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                    }
                }
            }

            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let err = LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Settle is not finalized"));

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            assert!(System::block_number() <= settle_finalized_time);
        })
    }

    #[test]
    fn test_confirm_settle_fail_due_to_lack_of_deposit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                5,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            for peer_index in 0..2 {
                for list_index in 0..cond_pays[peer_index as usize].len() {
                    for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                        let pay_request = ResolvePaymentConditionsRequest {
                            cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                            hash_preimages: vec![],
                        };
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                    }
                }
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            );

            let pay_id_list_array = global_result.4;

            for peer_index in 0..2 {
                assert_ok!(LedgerOperation::<TestRuntime>::clear_pays(
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));
            }

            let (_, deposits, withdrawals): (Vec<AccountId>, Vec<Balance>, Vec<Balance>) =
                CelerModule::get_balance_map(channel_id);

            assert_eq!(deposits, [5, 0]);
            assert_eq!(withdrawals, [0, 0]);

            let (_, transfer_out) = CelerModule::get_transfer_out_map(channel_id).unwrap();
            assert_eq!(transfer_out, [20, 46]);

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(settle_finalized_time);

            let err = LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Module {
                    index: 0,
                    error: 8,
                    message: Some("ConfirmSettleFail")
                }
            );
        })
    }

    #[test]
    fn test_pass_clear_pays_after_settle_finalized_time() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            for peer_index in 0..2 {
                for list_index in 0..cond_pays[peer_index as usize].len() {
                    for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                        let pay_request = ResolvePaymentConditionsRequest {
                            cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                            hash_preimages: vec![],
                        };
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                    }
                }
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            // pass after settleFinalizedTime
            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(settle_finalized_time);

            let pay_id_list_array = global_result.4;
            let amounts = vec![vec![3, 4], vec![7, 8]];

            for peer_index in 0..2 {
                assert_ok!(CelerModule::clear_pays(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));

                let mut count = 0;
                for list_index in 1..cond_pays[peer_index as usize].len() {
                    for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                        let encoded = encode_conditional_pay(
                            cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                        );
                        let pay_hash = hashing::blake2_256(&encoded).into();
                        let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                        let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                            channel_id,
                            pay_id,
                            channel_peers[peer_index as usize],
                            amounts[peer_index as usize][count as usize],
                        ));
                        assert!(System::events().iter().any(|a| a.event == expected_event));
                        count += 1;
                    }
                }
            }
        })
    }

    #[test]
    fn test_fail_intend_settle_after_settle_finalized_time() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result_1: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts.clone(),
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result_1.0;
            let cond_pays = global_result_1.2;

            for peer_index in 0..2 {
                for list_index in 0..2 {
                    for pay_index in 0..2 {
                        let pay_request = ResolvePaymentConditionsRequest {
                            cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                            hash_preimages: vec![],
                        };
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                    }
                }
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(settle_finalized_time);

            let pay_id_list_array = global_result_1.4;

            for peer_index in 0..2 {
                //  for each simplex state
                assert_ok!(LedgerOperation::<TestRuntime>::clear_pays(
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));
            }

            let err = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Settle has already finalized"));
        })
    }

    #[test]
    fn test_pass_confirm_settle() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 2000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                500,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                500,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            for peer_index in 0..2 {
                for list_index in 0..cond_pays[peer_index as usize].len() {
                    for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                        let pay_request = ResolvePaymentConditionsRequest {
                            cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                            hash_preimages: vec![],
                        };
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                    }
                }
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let pay_id_list_array = global_result.4;

            let next_list_hash = pay_id_list_array[0][0].next_list_hash;
            let mut encoded = pay_id_list_array[0][1].next_list_hash.encode();
            encoded.extend(pay_id_list_array[0][1].pay_ids[0].encode());
            encoded.extend(pay_id_list_array[0][1].pay_ids[1].encode());

            let hash = hashing::blake2_256(&encoded).into();
            assert_eq!(next_list_hash.unwrap(), hash);

            for peer_index in 0..2 {
                assert_ok!(LedgerOperation::<TestRuntime>::clear_pays(
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));
            }

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(settle_finalized_time);

            let (_, deposits, withdrawals): (Vec<AccountId>, Vec<Balance>, Vec<Balance>) =
                CelerModule::get_balance_map(channel_id);
            assert_eq!(deposits, [500, 500]);
            assert_eq!(withdrawals, [0, 0]);

            let (_, transfer_out) = CelerModule::get_transfer_out_map(channel_id).unwrap();
            assert_eq!(transfer_out, [20, 46]);

            let (_, settle_balance) =
                LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [526, 474]);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Closed);
        })
    }

    #[test]
    fn test_pass_open_channel_when_total_deposit_is_larger_than_zero() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(false, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let (_, deposits, _): (Vec<AccountId>, Vec<Balance>, Vec<Balance>) =
                CelerModule::get_balance_map(channel_id);
            assert_eq!(deposits, [100, 200]);
        })
    }

    #[test]
    fn test_pass_open_channel_when_total_deposit_is_larger_than_zero_and_msg_value_receiver_is_1_and_caller_is_not_peers(
    ) {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let risa = account_key("Risa");

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);
            let open_channel_request = get_open_channel_request(true, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(risa),
                open_channel_request,
                200,
            ).unwrap();

            let (_, deposits, _): (Vec<AccountId>, Vec<Balance>, Vec<Balance>) =
                CelerModule::get_balance_map(channel_id);
            assert_eq!(deposits, [100, 200]);
        })
    }

    #[test]
    fn test_fail_cooperative_settle_when_submitted_sum_is_not_equal_to_deposit_sum() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                5,
                0
            ));

            let cooperative_settle_request = get_cooperative_settle_request(
                channel_id,
                2,
                channel_peers,
                vec![200, 200],
                500000,
                peers_pair,
            );

            let err = LedgerOperation::<TestRuntime>::cooperative_settle(cooperative_settle_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Balance sum mismatch"));
        })
    }

    #[test]
    fn test_pass_cooperative_settle() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            let cooperative_settle_request = get_cooperative_settle_request(
                channel_id,
                2,
                channel_peers,
                vec![150, 50],
                500000,
                peers_pair,
            );

            let total_balance = Module::<TestRuntime>::get_total_balance(channel_id).unwrap();
            assert_eq!(total_balance, 200);

            let (channel_id, settle_balance): (H256, Vec<Balance>) =
                LedgerOperation::<TestRuntime>::cooperative_settle(cooperative_settle_request).unwrap();
            assert_eq!(settle_balance, [150, 50]);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Closed);
        })
    }

    #[test]
    fn test_pass_intend_settle_when_time_is_after_last_pay_resolve_deadline() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 2000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                500,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                500,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],   // seq_nums
                vec![10, 20], // transfer amounts
                vec![2, 2],   // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            // ensure it passes the lat pay resolve deadline
            System::set_block_number(System::block_number() + 3);
            assert_eq!(System::block_number(), 3);

            // intend settle
            let _ = CelerModule::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            //System::set_block_number(System::block_number() + settle_finalized_time);
            let expected_settle_finalized_time = System::block_number() + 10;
            assert_eq!(settle_finalized_time, expected_settle_finalized_time);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Settling);

            for i in 0..2 {
                // for each simplex state
                for j in 0..2 {
                    // for each pays in head PayIdList
                    let encoded = encode_conditional_pay(cond_pays[i][0][j].clone());
                    let pay_hash = hashing::blake2_256(&encoded).into();
                    let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                    let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                        channel_id,
                        pay_id,
                        channel_peers[i as usize],
                        0,
                    ));
                    assert!(System::events().iter().any(|a| a.event == expected_event));
                }
            }

            let peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
            // updated transfer_out map with cleared pays in the head PayIdList
            assert_eq!(peers_migration_info.4, [10, 20]);
            assert_eq!(peers_migration_info.5, [10, 26]);
        })
    }

    #[test]
    fn test_confirm_settle_when_pay_proof_type_is_hash_array_and_time_is_after_last_pay_resolve_deadline(
    ) {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 2000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                100,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],   // seq_nums
                vec![10, 20], // transfer amounts
                vec![2, 2],   // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;

            // ensure it passes the lat pay resolve deadline
            System::set_block_number(System::block_number() + 3);
            assert_eq!(System::block_number(), 3);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(System::block_number() + settle_finalized_time);

            let (_, settle_balance) =
                LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [110, 190]);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Closed);
        })
    }

    #[test]
    fn test_pass_intend_settle_with_0_payment() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);
            let open_channel_request = get_open_channel_request(true, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());

            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let single_singed_null_state =
                get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair);
            let signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_singed_null_state],
            };

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            let expected_single_settle_finalized_time = 10 as BlockNumber + System::block_number();
            assert!(settle_finalized_time == expected_single_settle_finalized_time);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Settling);

            let peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
            // updated transfer_out map with cleared pays in the head PayIdList
            assert_eq!(peers_migration_info.4, [0, 0]);
            // updated pending_pay_out map without cleared pays in the head PayIdList
            assert_eq!(peers_migration_info.5, [0, 0]);
        })
    }

    #[test]
    fn test_fail_intend_settle_with_0_payment_again() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let single_singed_null_state =
                get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair);
            let signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_singed_null_state],
            };

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            // intend settle again
            let err = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("intend_settle before"));
        })
    }

    #[test]
    fn test_pass_confirm_settle_after_0_payment_intend_settle() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let single_singed_null_state = get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair);
            let signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_singed_null_state],
            };

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(settle_finalized_time);

            let (_, settle_balance) = LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [100, 200]);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Closed);
        })
    }

    #[test]
    fn test_pass_intend_settle_with_one_non_null_simplex_state() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let single_singed_null_state =
                get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair.clone());

            let mut signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_singed_null_state],
            };

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            let pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let signed_simplex_non_null_state = get_co_signed_simplex_state(
                channel_id,
                channel_peers[0],
                1,
                10,
                pay_id_list_info.0[0].clone(),
                99999,
                pay_id_list_info.3,
                channel_peers[0],
                peers_pair.clone(),
            );
            signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![signed_simplex_non_null_state],
            };

            let cond_pays = pay_id_list_info.2;
            let cond_pay_len = cond_pays[0].len();
            // resolve the payments in head PayIdList
            for i in 0..cond_pay_len as usize {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            let expected_single_settle_finalized_time = 10 + System::block_number();
            assert_eq!(settle_finalized_time, expected_single_settle_finalized_time);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Settling);

            let amounts = vec![1, 2];
            for i in 0..2 {
                // for each pays in head PayIdList
                let encoded = encode_conditional_pay(cond_pays[0][i].clone());
                let pay_hash = hashing::blake2_256(&encoded).into();
                let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                    channel_id,
                    pay_id,
                    channel_peers[0],
                    amounts[i],
                ));
                assert!(System::events().iter().any(|a| a.event == expected_event));
            }

            let peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
            assert_eq!(peers_migration_info.4, [13, 0]);
            assert_eq!(peers_migration_info.5, [0, 0]);
        })
    }

    #[test]
    fn test_pass_confirm_settle_with_one_non_null_simplex_state() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let single_singed_null_state =
                get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair.clone());

            let mut signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_singed_null_state],
            };

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            let pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let signed_simplex_non_null_state = get_co_signed_simplex_state(
                channel_id,
                channel_peers[0],
                1,
                10,
                pay_id_list_info.0[0].clone(),
                99999,
                pay_id_list_info.3,
                channel_peers[0],
                peers_pair.clone(),
            );
            signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![signed_simplex_non_null_state],
            };

            let cond_pays = pay_id_list_info.2;
            let cond_pay_len = cond_pays[0].len();
            // resolve the payments in head PayIdList
            for i in 0..cond_pay_len as usize {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            System::set_block_number(settle_finalized_time);

            let (_, settle_balance) =
                LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [87, 213]);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Closed);
        })
    }

    #[test]
    fn test_pass_intend_settle_with_multiple_cross_channel_simplex_states() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // 1 pair of simplex states + 1 non-null simplex state + 1 null simplex state
            approve(channel_peers[1], ledger_addr, 600);

            let mut unique_channel_ids: Vec<H256> = vec![];
            // open 3 new channel
            for i in 0..3 {
                let open_channel_request = get_open_channel_request(
                    true,
                    10000,
                    50000 + i,
                    10,
                    true,
                    channel_peers.clone(),
                    1,
                    peers_pair.clone(),
                );
                let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                    Origin::signed(channel_peers[0]),
                    open_channel_request,
                    0,
                ).unwrap();
                let _ = LedgerOperation::<TestRuntime>::deposit(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    channel_peers[0],
                    100,
                    0,
                ).unwrap();
                unique_channel_ids.push(channel_id);
            }
            let mut channel_ids = vec![
                unique_channel_ids[1],
                unique_channel_ids[1],
                unique_channel_ids[2],
            ];
            let sort_indices: Vec<usize> = get_sort_indices(channel_ids.clone());
            channel_ids = reorder_channel_id(channel_ids, sort_indices.clone());
            assert!(channel_ids[0] <= channel_ids[1] && channel_ids[1] <= channel_ids[2]);
            // push channel_id of null simplex state
            channel_ids.push(unique_channel_ids[0]);

            let peer_froms: Vec<AccountId> = reorder_account_id(
                vec![channel_peers[0], channel_peers[1], channel_peers[0]],
                sort_indices.clone(),
            );
            let mut pay_id_infos: Vec<(
                Vec<PayIdList<H256>>,
                Vec<H256>,
                Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
                Balance,
                Vec<PayIdList<H256>>,
            )> = vec![
                // 1 pair of simplex states
                get_pay_id_list_info(vec![vec![1, 2]], 1),
                get_pay_id_list_info(vec![vec![3, 4]], 1),
                // 1 non-null simplex state
                get_pay_id_list_info(vec![vec![1, 2]], 1),
            ];
            let mut pay_amounts: Vec<Vec<Balance>> = reorder_pay_amounts(
                vec![vec![1, 2], vec![3, 4], vec![1, 2]],
                sort_indices.clone(),
            );
            assert!(pay_amounts[0][0] < pay_amounts[1][0]);
            // push pay_amounts of null simplex states
            pay_amounts.push(vec![0, 0]);
            pay_id_infos = reorder_pay_id_list_infos(pay_id_infos, sort_indices.clone());
            let mut pay_id_lists: Vec<PayIdList<H256>> = vec![];
            for i in 0..3 {
                pay_id_lists.push(pay_id_infos[i].0[0].clone());
            }
            let mut seq_nums = reorder_seq_nums(vec![1, 1, 5], sort_indices.clone());
            // push seq_nums of null simplex states
            seq_nums.push(0);
            let mut seq_nums_array = reorder_seq_nums_array(
                vec![vec![1, 1], vec![1, 1], vec![5, 0]],
                sort_indices.clone(),
            );
            // push seq_nums_array of null simplex states
            seq_nums_array.push(vec![0, 0]);
            let transfer_amounts = reorder_transfer_amounts(vec![10, 20, 30], sort_indices.clone());

            let signed_simplex_state_array = get_signed_simplex_state_array(
                channel_ids.clone(),
                seq_nums,
                transfer_amounts,
                vec![99999, 99999, 99999],
                pay_id_lists,
                peer_froms.clone(),
                channel_peers.clone(),
                vec![
                    pay_amounts[0][0] + pay_amounts[0][1],
                    pay_amounts[1][0] + pay_amounts[1][1],
                    pay_amounts[2][0] + pay_amounts[2][1],
                    pay_amounts[3][0] + pay_amounts[3][1],
                ],
                channel_peers[0],
                peers_pair,
            );

            // resolve the payments in all head PayIdLists
            for i in 0..2 {
                let cond_pays = pay_id_infos[0].2.clone();
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }
            for i in 0..2 {
                let cond_pays = pay_id_infos[1].2.clone();
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let expected_settle_finalized_time = 10 + System::block_number();
            for i in 0..3 {
                let settle_finalized_time = CelerModule::get_settle_finalized_time(unique_channel_ids[i]).unwrap();
                assert_eq!(expected_settle_finalized_time, settle_finalized_time);
                let status = CelerModule::get_channel_status(unique_channel_ids[i]);
                assert_eq!(status, ChannelStatus::Settling);
            }

            // for each simplex state
            for i in 0..3 {
                // for each pays in head PayIdList
                let cond_pays = pay_id_infos[i].2[0].clone();
                for j in 0..cond_pays.len() {
                    let encoded = encode_conditional_pay(pay_id_infos[i].2[0][j].clone());
                    let pay_hash = hashing::blake2_256(&encoded).into();
                    let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                    let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                        channel_ids[i],
                        pay_id,
                        peer_froms[i],
                        pay_amounts[i][j],
                    ));
                    assert!(System::events().iter().any(|a| a.event == expected_event));
                }
            }

            let expected_event = TestEvent::celer(RawEvent::IntendSettle(unique_channel_ids[0], vec![0, 0]));
            assert!(System::events().iter().any(|a| a.event == expected_event));
        })
    }

    #[test]
    fn test_pass_confirm_settle_when_multiple_cross_channel_simplex_states() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // 1 pair of simplex states + 1 non-null simplex state + 1 null simplex state
            approve(channel_peers[1], ledger_addr, 600);

            let mut unique_channel_ids: Vec<H256> = vec![];
            // open 3 new channel
            for i in 0..3 {
                let open_channel_request = get_open_channel_request(
                    true,
                    10000,
                    50000 + i,
                    10,
                    true,
                    channel_peers.clone(),
                    1,
                    peers_pair.clone(),
                );
                let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                    Origin::signed(channel_peers[0]),
                    open_channel_request,
                    0,
                ).unwrap();
                let _ = LedgerOperation::<TestRuntime>::deposit(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    channel_peers[0],
                    100,
                    0,
                ).unwrap();
                let _ = LedgerOperation::<TestRuntime>::deposit(
                    Origin::signed(channel_peers[1]),
                    channel_id,
                    channel_peers[1],
                    200,
                    0,
                ).unwrap();
                unique_channel_ids.push(channel_id);
            }
            let mut channel_ids = vec![
                unique_channel_ids[1],
                unique_channel_ids[1],
                unique_channel_ids[2],
            ];
            let sort_indices: Vec<usize> = get_sort_indices(channel_ids.clone());
            channel_ids = reorder_channel_id(channel_ids, sort_indices.clone());
            assert!(channel_ids[0] <= channel_ids[1] && channel_ids[1] <= channel_ids[2]);
            // push channel_id of null simplex state
            channel_ids.push(unique_channel_ids[0]);

            let peer_froms: Vec<AccountId> = reorder_account_id(
                vec![channel_peers[0], channel_peers[1], channel_peers[0]],
                sort_indices.clone(),
            );
            let mut pay_id_infos: Vec<(
                Vec<PayIdList<H256>>,
                Vec<H256>,
                Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
                Balance,
                Vec<PayIdList<H256>>,
            )> = vec![
                // 1 pair of simplex states
                get_pay_id_list_info(vec![vec![1, 2]], 1),
                get_pay_id_list_info(vec![vec![3, 4]], 1),
                // 1 non-null simplex state
                get_pay_id_list_info(vec![vec![1, 2]], 1),
            ];
            let mut pay_amounts: Vec<Vec<Balance>> = reorder_pay_amounts(
                vec![vec![1, 2], vec![3, 4], vec![1, 2]],
                sort_indices.clone(),
            );
            assert!(pay_amounts[0][0] < pay_amounts[1][0]);
            // push pay_amounts of null simplex states
            pay_amounts.push(vec![0, 0]);
            pay_id_infos = reorder_pay_id_list_infos(pay_id_infos, sort_indices.clone());
            let mut pay_id_lists: Vec<PayIdList<H256>> = vec![];
            for i in 0..3 {
                pay_id_lists.push(pay_id_infos[i].0[0].clone());
            }
            let mut seq_nums = reorder_seq_nums(vec![1, 1, 5], sort_indices.clone());
            // push seq_nums of null simplex states
            seq_nums.push(0);
            let mut seq_nums_array = reorder_seq_nums_array(
                vec![vec![1, 1], vec![1, 1], vec![5, 0]],
                sort_indices.clone(),
            );
            // push seq_nums_array of null simplex states
            seq_nums_array.push(vec![0, 0]);
            let transfer_amounts = reorder_transfer_amounts(vec![10, 20, 30], sort_indices.clone());

            let signed_simplex_state_array = get_signed_simplex_state_array(
                channel_ids,
                seq_nums,
                transfer_amounts,
                vec![99999, 99999, 99999],
                pay_id_lists,
                peer_froms,
                channel_peers.clone(),
                vec![
                    pay_amounts[0][0] + pay_amounts[0][1],
                    pay_amounts[1][0] + pay_amounts[1][1],
                    pay_amounts[2][0] + pay_amounts[2][1],
                    pay_amounts[3][0] + pay_amounts[3][1],
                ],
                channel_peers[0],
                peers_pair,
            );

            // resolve the payments in all head PayIdLists
            for i in 0..2 {
                let cond_pays = pay_id_infos[0].2.clone();
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }
            for i in 0..2 {
                let cond_pays = pay_id_infos[1].2.clone();
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let mut settle_finalized_time: BlockNumber = 0;
            for i in 0..3 {
                let tmp = CelerModule::get_settle_finalized_time(unique_channel_ids[i]).unwrap();
                if tmp > settle_finalized_time {
                    settle_finalized_time = tmp;
                }
            }
            System::set_block_number(settle_finalized_time);

            let expected_settle_balances = vec![vec![100, 200], vec![114, 186], vec![67, 233]];
            for i in 0..3 {
                let (_, settle_balance) =
                    LedgerOperation::<TestRuntime>::confirm_settle(unique_channel_ids[i]).unwrap();
                assert_eq!(settle_balance, expected_settle_balances[i]);
                let status = CelerModule::get_channel_status(unique_channel_ids[i]);
                assert_eq!(status, ChannelStatus::Closed);
            }
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_more_funds_than_withdraw_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Exceed withdraw limit"));
        })
    }

    #[test]
    fn test_pass_snapshot_states_and_then_intend_withdraw_and_confirm_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            // snapshot_states()
            let pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let pay_id_list = pay_id_list_info.0[0].clone();
            let total_pending_amount = pay_id_list_info.3;
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![100],
                vec![99999],
                vec![pay_id_list],
                vec![channel_peers[1].clone()],
                channel_peers.clone(),
                vec![total_pending_amount],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );

            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            // intend withdraw
            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let (_channel_id, _receiver_1, _amount_1) =
                LedgerOperation::<TestRuntime>::intend_withdraw(
                    Origin::signed(channel_peers[0]),
                    channel_id,
                    100,
                    zero_channel_id,
                ).unwrap();
            assert_eq!(_channel_id, channel_id);
            assert_eq!(_receiver_1, channel_peers[0].clone());
            assert_eq!(_amount_1, 100);

            System::set_block_number(System::block_number() + 10);

            // confirm withdraw
            let (_amount_2, _reciever_2, _recipient_channel_id) =
                LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap();
            assert_eq!(_amount_2, 100);
            assert_eq!(_reciever_2, channel_peers[0].clone());
            assert_eq!(_recipient_channel_id, zero_channel_id);

            // get total balance
            let balance_amt = CelerModule::get_total_balance(channel_id).unwrap();
            assert_eq!(balance_amt, 200);

            // get balance map
            let (_channel_peers, _deposits, _withdrawals) =
                CelerModule::get_balance_map(channel_id);
            assert_eq!(_channel_peers, channel_peers);
            assert_eq!(_deposits, [100, 200]);
            assert_eq!(_withdrawals, [100, 0]);
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_more_funds_than_updated_withdraw_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Exceed withdraw limit"));
        })
    }

    #[test]
    fn test_pass_confirm_withdraw_for_funds_within_the_updated_withdraw_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                50,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            let (amount, _, _) =
                LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap();
            assert_eq!(amount, 50);

            let (_, _deposits, _withdrawals) = CelerModule::get_balance_map(channel_id);
            assert_eq!(_deposits, [50, 150]);
            assert_eq!(_withdrawals, [50, 0]);
        })
    }

    #[test]
    fn test_fail_intend_settle_with_smaller_seq_num_than_snapshot() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            // snapshot_states()
            let mut pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let pay_id_lists_1 = vec![pay_id_list_info.0[0].clone()];
            let total_pending_amount_1 = pay_id_list_info.3;
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![100],
                vec![99999],
                pay_id_lists_1,
                vec![channel_peers[1].clone()],
                channel_peers.clone(),
                vec![total_pending_amount_1],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );

            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            pay_id_list_info = get_pay_id_list_info(vec![vec![2, 4]], 1);
            let pay_id_lists_2 = vec![pay_id_list_info.0[0].clone()];
            let total_pending_amount_2 = pay_id_list_info.3;

            let local_signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![4],
                vec![10],
                vec![1],
                pay_id_lists_2,
                vec![channel_peers[1]],
                channel_peers.clone(),
                vec![total_pending_amount_2],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );

            let err = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                local_signed_simplex_state_array,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("seqNum error"));
        })
    }

    #[test]
    fn test_pass_intend_settle_when_same_seq_num_as_snapshot() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request = get_open_channel_request(true, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            // snapshot_states()
            let mut pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let pay_id_lists_1 = vec![pay_id_list_info.0[0].clone()];
            let total_pending_amount_1 = pay_id_list_info.3;
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![100],
                vec![99999],
                pay_id_lists_1,
                vec![channel_peers[1].clone()],
                channel_peers.clone(),
                vec![total_pending_amount_1],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );

            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let pay_id_lists_2 = vec![pay_id_list_info.0[0].clone()];
            let total_pending_amount_2 = pay_id_list_info.3;

            let local_signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![10],
                vec![1],
                pay_id_lists_2,
                vec![channel_peers[1]],
                channel_peers.clone(),
                vec![total_pending_amount_2],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );

            let cond_pays = pay_id_list_info.2;
            // resolve the payments in head PayIdList
            for i in 0..cond_pays[0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            assert_ok!(LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                local_signed_simplex_state_array
            ));

            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            let expected_settle_finalized_time = 10 + System::block_number();
            assert_eq!(settle_finalized_time, expected_settle_finalized_time);

            let status = CelerModule::get_channel_status(channel_id);
            assert_eq!(status, ChannelStatus::Settling);

            let amounts = vec![1, 2];
            for i in 0..2 {
                // for each pays in head PayIdList
                let encoded = encode_conditional_pay(cond_pays[0][i].clone());
                let pay_hash = hashing::blake2_256(&encoded).into();
                let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                    channel_id,
                    pay_id,
                    channel_peers[1],
                    amounts[i],
                ));
                assert!(System::events().iter().any(|a| a.event == expected_event));
            }

            let peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
            // updated transferOut map with clreared pays in the head PayIdList
            assert_eq!(peers_migration_info.4, vec![0, 13]);
            assert_eq!(peers_migration_info.5, vec![0, 0]);
        })
    }

    #[test]
    fn test_fail_intend_withdraw_after_intend_settle() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            // resolve the payments in head PayIdList
            // the head list of peer_from 0
            for i in 0..cond_pays[0][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // the head list of peer_from 1
            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            // intend withdraw
            let err = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                50,
                zero_channel_id,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Channel status error"));
        })
    }

    #[test]
    fn test_fail_cooperative_withdraw_after_intend_settle() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                200,
                0
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let global_result: (
                SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
                Vec<BlockNumber>,
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
                Vec<Vec<H256>>,
                Vec<Vec<PayIdList<H256>>>,
            ) = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],         // seq_nums
                vec![10, 20],       // transfer amounts
                vec![99999, 99999], // last_pay_resolve_deadlines
                vec![channel_peers[0], channel_peers[1]],
                vec![channel_peers[0], channel_peers[1]],
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
            let cond_pays = global_result.2;

            // resolve the payments in head PayIdList
            // the head list of peer_from 0
            for i in 0..cond_pays[0][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // the head list of peer_from 1
            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            // cooperative withdraw
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                50,
                channel_peers[0],
                0,
                zero_channel_id,
                peers_pair,
            );
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Channel status error"));
        })
    }

    #[test]
    fn test_pass_deposit_in_batch() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let deposit_account = account_key("Carl");

            approve(deposit_account, ledger_addr, 10000);

            let mut channel_ids: Vec<H256> = vec![];
            // open 2 new channel
            for i in 0..2 {
                let open_channel_request = get_open_channel_request(
                    true,
                    100000,
                    50000 + i,
                    10,
                    true,
                    channel_peers.clone(),
                    1,
                    peers_pair.clone(),
                );
                let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                    Origin::signed(channel_peers[0]),
                    open_channel_request,
                    0,
                ).unwrap();
                channel_ids.push(channel_id);
            }

            // a non peer address approve to ledger address
            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(deposit_account),
                deposit_account,
                10000,
            );
            approve(deposit_account, ledger_addr, 10000);
            let receivers = vec![channel_peers[0].clone(), channel_peers[1].clone()];
            let amounts = vec![100, 200];

            assert_ok!(CelerModule::deposit_in_batch(
                Origin::signed(deposit_account),
                channel_ids.clone(),
                receivers.clone(),
                vec![0, 0],
                amounts.clone()
            ));

            let (_, deposits_1, _) = CelerModule::get_balance_map(channel_ids[0].clone());
            let (_, deposits_2, _) = CelerModule::get_balance_map(channel_ids[1].clone());
            assert_eq!(deposits_1, [100, 0]);
            assert_eq!(deposits_2, [0, 200]);
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_after_withdraw_limit_is_updated_by_cooperative_withdraw() {
        ExtBuilder::build().execute_with(|| {
            // open a new channel and deposit some funds
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 2000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                45,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            // cooperative withdraw 10 to peer 0
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                10,
                channel_peers[0],
                30,
                zero_channel_id,
                peers_pair,
            );
            let _ = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Exceed withdraw limit"));
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_after_withdraw_limit_is_updated_by_snapshot_states_with_its_own_state(
    ) {
        ExtBuilder::build().execute_with(|| {
            // open a new channel and deposit some funds
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                35,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            // snapshotStates: peer 0 trnasfers out 10; pending amout 10
            let pay_id_list_info = get_pay_id_list_info(vec![vec![5, 5]], 1);
            let pay_id_list = pay_id_list_info.0[0].clone();
            let total_pending_amount = pay_id_list_info.3;
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![10],
                vec![99999],
                vec![pay_id_list],
                vec![channel_peers[0].clone()],
                channel_peers.clone(),
                vec![total_pending_amount],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );
            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Exceed withdraw limit"));
        })
    }

    #[test]
    fn test_pass_confirm_withdraw_after_withdraw_limit_is_updated_by_snapshot_states_with_peers_state(
    ) {
        ExtBuilder::build().execute_with(|| {
            // open a new channel and deposit some funds
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                60,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            // snapshotStates: peer 0 trnasfers out 10; pending amout 10
            let pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
            let pay_id_list = pay_id_list_info.0[0].clone();
            let total_pending_amount = pay_id_list_info.3;
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![10],
                vec![99999],
                vec![pay_id_list],
                vec![channel_peers[1].clone()],
                channel_peers.clone(),
                vec![total_pending_amount],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );
            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            let (amount, _, _) =
                LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap();
            assert_eq!(amount, 60);

            let (_, _deposits, _withdrawals) = CelerModule::get_balance_map(channel_id);
            assert_eq!(_deposits, [50, 150]);
            assert_eq!(_withdrawals, [60, 0]);
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_amount_including_peers_total_pending_amount_after_withdraw_limit_is_updated_by_snapshot_states_with_peers_state(
    ) {
        ExtBuilder::build().execute_with(|| {
            // open a new channel and deposit some funds
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                50,
                0
            ));
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[1]),
                channel_id,
                channel_peers[1],
                150,
                0
            ));

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                65,
                zero_channel_id,
            ).unwrap();
            System::set_block_number(System::block_number() + 10);

            // snapshotStates: peer 0 trnasfers out 10; pending amout 10
            let pay_id_list_info = get_pay_id_list_info(vec![vec![5, 5]], 1);
            let pay_id_list = pay_id_list_info.0[0].clone();
            let total_pending_amount = pay_id_list_info.3;
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![10],
                vec![99999],
                vec![pay_id_list],
                vec![channel_peers[1].clone()],
                channel_peers.clone(),
                vec![total_pending_amount],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );
            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Exceed withdraw limit"));
        })
    }

    #[test]
    fn test_pass_update_pending_pay_out_to_0_correctly_when_intend_settle_a_state_with_only_one_pay_id_list(
    ) {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 200);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                0,
                100
            ));

            let pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 0);
            let pay_id_list = vec![pay_id_list_info.0[0].clone()];
            let total_pending_amounts = vec![pay_id_list_info.3];
            let signed_simplex_state_array = get_signed_simplex_state_array(
                vec![channel_id],
                vec![5],
                vec![10],
                vec![99999],
                pay_id_list,
                vec![channel_peers[0]],
                channel_peers.clone(),
                total_pending_amounts,
                channel_peers[1],
                peers_pair,
            );

            let cond_pays = pay_id_list_info.2;
            // resolve the payments in head PayIdList
            for i in 0..cond_pays[0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            }

            // pass onchain resolve deadline ofall onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let expected_single_settle_finalized_time = 10 + System::block_number();
            let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
            assert_eq!(expected_single_settle_finalized_time, settle_finalized_time);

            for i in 0..2 {
                // for each pays in head PayIdList
                let encoded = encode_conditional_pay(cond_pays[0][i].clone());
                let pay_hash = hashing::blake2_256(&encoded).into();
                let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                let expected_event = TestEvent::celer(RawEvent::ClearOnePay(
                    channel_id,
                    pay_id,
                    channel_peers[0],
                    0,
                ));
                assert!(System::events().iter().any(|a| a.event == expected_event));
            }

            let peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
            // updated  transferOut  map  which  cleared pays in the head PayIdList
            assert_eq!(peers_migration_info.4, [10, 0]);
            // updated pendingPayOut map without cleared  pays  in the head PayIdList
            assert_eq!(peers_migration_info.5, [0, 0]);
        })
    }

    #[test]
    fn test_fail_intend_settle_operable_channel_for_a_non_peer() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let risa = account_key("Risa");

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 200);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                0,
                100
            ));

            let single_signed_null_state = get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair);
            let signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_signed_null_state],
            };

            let err = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(risa),
                signed_simplex_state_array,
            ).unwrap_err();
            assert_eq!(err, DispatchError::Other("Nonpeer channel status error"));
        })
    }

    #[test]
    fn test_pass_intend_settle_a_settling_channel_for_a_nonpeer() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let risa = account_key("Risa");

            Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            );
            approve(channel_peers[0], ledger_addr, 200);

            let open_channel_request = get_open_channel_request(true, 10000, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request,
                0,
            ).unwrap();
            assert_ok!(LedgerOperation::<TestRuntime>::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                0,
                100
            ));

            // the meaning of the index: [peer index][pay hash list index][pay index]
            let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
                vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

            let single_signed_null_state = get_single_signed_simplex_state(
                channel_id,
                channel_peers[0].clone(),
                peers_pair.clone(),
            );
            let signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_signed_null_state],
            };

            // peer intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            System::set_block_number(System::block_number() + 3);
            assert_eq!(System::block_number(), 3);

            // non peer intend settle
            let result = get_cosigned_intend_settle(
                vec![channel_id, channel_id],
                peers_pay_hash_lists_amts,
                vec![1, 1],   // seq_nums
                vec![10, 20], // transfer_amounts
                vec![2, 2],   // last_pay_resolve_deadline
                vec![channel_peers[0].clone(), channel_peers[1].clone()],
                channel_peers.clone(),
                channel_peers[1],
                peers_pair,
                1,
            );

            let signed_simplex_state_array = result.0;

            assert_ok!(LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(risa),
                signed_simplex_state_array
            ));
        })
    }

    // get the original indices of a sorted array
    fn get_sort_indices(to_sort: Vec<H256>) -> Vec<usize> {
        let mut tmp: Vec<(H256, usize)> = vec![];
        for i in 0..to_sort.len() {
            tmp.push((to_sort[i], i as usize));
        }
        tmp.sort_by(|a, b| a.0.cmp(&b.0));
        let mut sort_indices: Vec<usize> = vec![];
        for i in 0..tmp.len() as usize {
            sort_indices.push(tmp[i].1);
        }
        return sort_indices;
    }

    fn reorder_channel_id(to_order: Vec<H256>, sort_indices: Vec<usize>) -> Vec<H256> {
        let mut result: Vec<H256> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]]);
        }
        return result;
    }

    fn reorder_account_id(to_order: Vec<AccountId>, sort_indices: Vec<usize>) -> Vec<AccountId> {
        let mut result: Vec<AccountId> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]]);
        }
        return result;
    }

    fn reorder_pay_amounts(
        to_order: Vec<Vec<Balance>>,
        sort_indices: Vec<usize>,
    ) -> Vec<Vec<Balance>> {
        let mut result: Vec<Vec<Balance>> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]].clone());
        }
        return result;
    }

    fn reorder_pay_id_list_infos(
        to_order: Vec<(
            Vec<PayIdList<H256>>,
            Vec<H256>,
            Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
            Balance,
            Vec<PayIdList<H256>>,
        )>,
        sort_indices: Vec<usize>,
    ) -> Vec<(
        Vec<PayIdList<H256>>,
        Vec<H256>,
        Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
        Balance,
        Vec<PayIdList<H256>>,
    )> {
        let mut result: Vec<(
            Vec<PayIdList<H256>>,
            Vec<H256>,
            Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
            Balance,
            Vec<PayIdList<H256>>,
        )> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]].clone());
        }
        return result;
    }

    fn reorder_seq_nums(to_order: Vec<u128>, sort_indices: Vec<usize>) -> Vec<u128> {
        let mut result: Vec<u128> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]]);
        }
        return result;
    }

    fn reorder_seq_nums_array(
        to_order: Vec<Vec<u128>>,
        sort_indices: Vec<usize>,
    ) -> Vec<Vec<u128>> {
        let mut result: Vec<Vec<u128>> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]].clone());
        }
        return result;
    }

    fn reorder_transfer_amounts(to_order: Vec<Balance>, sort_indices: Vec<usize>) -> Vec<Balance> {
        let mut result: Vec<Balance> = vec![];
        for i in 0..to_order.len() as usize {
            result.push(to_order[sort_indices[i as usize]]);
        }
        return result;
    }

    pub fn get_sorted_peer(
        peer_1: sr25519::Pair,
        peer_2: sr25519::Pair,
    ) -> (Vec<AccountId>, Vec<sr25519::Pair>) {
        if peer_1.public() < peer_2.public() {
            return (
                vec![peer_1.clone().public(), peer_2.clone().public()],
                vec![peer_1, peer_2],
            );
        } else {
            return (
                vec![peer_2.clone().public(), peer_1.clone().public()],
                vec![peer_2, peer_1],
            );
        }
    }

    pub fn get_open_channel_request(
        balance_limits_enabled: bool,
        balance_limits: Balance,
        open_deadline: BlockNumber,
        dispute_timeout: BlockNumber,
        zero_total_deposit: bool,
        channel_peers: Vec<AccountId>,
        msg_value_receiver: u8,
        peers_sr25519_pairs: Vec<sr25519::Pair>,
    ) -> OpenChannelRequest<AccountId, BlockNumber, Balance, Signature> {
        let channel_initializer = get_payment_channel_initializer(
            balance_limits_enabled,
            balance_limits,
            open_deadline,
            dispute_timeout,
            zero_total_deposit,
            channel_peers.clone(),
            msg_value_receiver,
        );

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
        
        let sigs_1 = peers_sr25519_pairs[0].sign(&encoded);
        let sigs_2 = peers_sr25519_pairs[1].sign(&encoded);

        let open_channel_request = OpenChannelRequest {
            channel_initializer: channel_initializer,
            sigs: vec![sigs_1, sigs_2],
        };

        return open_channel_request;
    }

    pub fn get_payment_channel_initializer(
        balance_limits_enabled: bool,
        balance_limits: Balance,
        open_deadline: BlockNumber,
        dispute_timeout: BlockNumber,
        zero_total_deposit: bool,
        channel_peers: Vec<AccountId>,
        msg_value_receiver: u8,
    ) -> PaymentChannelInitializer<AccountId, BlockNumber, Balance> {
        let account_amt_pair_1: AccountAmtPair<AccountId, Balance>;
        let account_amt_pair_2: AccountAmtPair<AccountId, Balance>;
        let token_distribution: TokenDistribution<AccountId, Balance>;
        let token_info = TokenInfo {
            token_type: TokenType::CELER,
        };

        if zero_total_deposit == true {
            account_amt_pair_1 = AccountAmtPair {
                account: Some(channel_peers[0]),
                amt: 0,
            };
            account_amt_pair_2 = AccountAmtPair {
                account: Some(channel_peers[1]),
                amt: 0,
            };

            token_distribution = TokenDistribution {
                token: token_info,
                distribution: vec![account_amt_pair_1, account_amt_pair_2],
            };
        } else {
            account_amt_pair_1 = AccountAmtPair {
                account: Some(channel_peers[0]),
                amt: 100,
            };
            account_amt_pair_2 = AccountAmtPair {
                account: Some(channel_peers[1]),
                amt: 200,
            };

            token_distribution = TokenDistribution {
                token: token_info,
                distribution: vec![account_amt_pair_1, account_amt_pair_2],
            };
        }

        let initializer: PaymentChannelInitializer<AccountId, BlockNumber, Balance>;

        if balance_limits_enabled == true {
            initializer = PaymentChannelInitializer {
                balance_limits_enabled: true,
                balance_limits: Some(balance_limits),
                init_distribution: token_distribution,
                open_deadline: open_deadline,
                dispute_timeout: dispute_timeout,
                msg_value_receiver: msg_value_receiver,
            };
        } else {
            initializer = PaymentChannelInitializer {
                balance_limits_enabled: false,
                balance_limits: None,
                init_distribution: token_distribution,
                open_deadline: open_deadline,
                dispute_timeout: dispute_timeout,
                msg_value_receiver: msg_value_receiver,
            };
        }

        return initializer;
    }

    pub fn get_cooperative_withdraw_request(
        channel_id: H256,
        seq_num: u128,
        amount: Balance,
        receiver_account: AccountId,
        withdraw_deadline: BlockNumber,
        recipient_channel_id: H256,
        channel_pairs: Vec<sr25519::Pair>,
    ) -> CooperativeWithdrawRequest<H256, BlockNumber, AccountId, Balance, Signature> {
        let account_amt_pair = AccountAmtPair {
            account: Some(receiver_account.clone()),
            amt: amount,
        };
        let cooperative_withdraw_info = CooperativeWithdrawInfo {
            channel_id: channel_id,
            seq_num: seq_num,
            withdraw: account_amt_pair,
            withdraw_deadline: withdraw_deadline,
            recipient_channel_id: recipient_channel_id,
        };

        let mut encoded = cooperative_withdraw_info.channel_id.encode();
        encoded.extend(cooperative_withdraw_info.seq_num.encode());
        encoded.extend(cooperative_withdraw_info.withdraw.account.encode());
        encoded.extend(cooperative_withdraw_info.withdraw.amt.encode());
        encoded.extend(cooperative_withdraw_info.withdraw_deadline.encode());
        encoded.extend(cooperative_withdraw_info.recipient_channel_id.encode());
        let sig_1 = channel_pairs[0].sign(&encoded);
        let sig_2 = channel_pairs[1].sign(&encoded);

        let cooperative_withdraw_request = CooperativeWithdrawRequest {
            withdraw_info: cooperative_withdraw_info,
            sigs: vec![sig_1, sig_2],
        };

        return cooperative_withdraw_request;
    }

    pub fn approve(owner: AccountId, spender: AccountId, value: Balance) {
        let _ = Pool::<TestRuntime>::approve(Origin::signed(owner), spender, value).unwrap();
    }

    fn veto_withdraw() -> H256 {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let open_channel_request = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
        let channel_id = LedgerOperation::<TestRuntime>::open_channel(
            Origin::signed(channel_peers[1]),
            open_channel_request.clone(),
            0,
        ).unwrap();

        assert_ok!(LedgerOperation::<TestRuntime>::deposit(
            Origin::signed(channel_peers[0]),
            channel_id,
            channel_peers[0],
            300,
            0
        ));

        let zero_vec = vec![0 as u8];
        let zero_channel_id = hashing::blake2_256(&zero_vec).into();
        let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
            Origin::signed(channel_peers[0]),
            channel_id,
            200,
            zero_channel_id,
        ).unwrap();

        assert_ok!(LedgerOperation::<TestRuntime>::veto_withdraw(
            Origin::signed(channel_peers[1]),
            channel_id
        ));

        return channel_id;
    }

    pub fn get_cosigned_intend_settle(
        channel_ids: Vec<H256>,
        pay_amounts_array: Vec<Vec<Vec<Balance>>>,
        seq_nums: Vec<u128>,
        transfer_amounts: Vec<Balance>,
        last_pay_resolve_deadlines: Vec<BlockNumber>,
        peer_froms: Vec<AccountId>,
        signers: Vec<AccountId>,
        receiver_account: AccountId,
        peers_pair: Vec<sr25519::Pair>,
        conditions: u8,
    ) -> (
        SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature>,
        Vec<BlockNumber>,
        Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>>,
        Vec<Vec<H256>>,
        Vec<Vec<PayIdList<H256>>>,
    ) {
        // Initial value of pay id list
        let init_pay_id_list = PayIdList {
            pay_ids: vec![H256::from_low_u64_be(0)],
            next_list_hash: None,
        };
        let head_pay_id_lists: Vec<PayIdList<H256>> = vec![init_pay_id_list];

        // Initial value pf cond_pay
        let init_conditions = get_condition(1);
        let init_transfer_func = get_transfer_func_2(10);
        let init_cond_pay = ConditionalPay {
            pay_timestamp: 0,
            src: account_key("src"),
            dest: account_key("dest"),
            conditions: vec![init_conditions],
            transfer_func: init_transfer_func,
            resolve_deadline: 0,
            resolve_timeout: 0,
        };
        let mut cond_pays: Vec<
            Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
        > = vec![
            vec![
                vec![init_cond_pay.clone(), init_cond_pay.clone()],
                vec![init_cond_pay.clone(), init_cond_pay.clone()],
            ],
            vec![
                vec![init_cond_pay.clone(), init_cond_pay.clone()],
                vec![init_cond_pay.clone(), init_cond_pay.clone()],
            ],
        ];

        let mut pay_id_list_hash_array: Vec<Vec<H256>> = vec![vec![]];
        let mut total_pending_amounts: Vec<Balance> = vec![];

        let channel_id_len = channel_ids.len();
        let mut pay_info: (
            Vec<PayIdList<H256>>,
            Vec<H256>,
            Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
            Balance,
            Vec<PayIdList<H256>>,
        );

        // Initial value of pay id list
        let init_pay_id_list = PayIdList {
            pay_ids: vec![H256::from_low_u64_be(0)],
            next_list_hash: None,
        };
        let mut head_pay_id_lists: Vec<PayIdList<H256>> =
            vec![init_pay_id_list.clone(), init_pay_id_list.clone()];
        let mut _pay_id_lists: Vec<PayIdList<H256>> =
            vec![init_pay_id_list.clone(), init_pay_id_list.clone()];
        let mut _pay_id_list_hash_array: Vec<H256> =
            vec![H256::from_low_u64_be(0).clone(), H256::from_low_u64_be(0)];
        let mut _cond_pay_array: Vec<
            Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>,
        > = vec![vec![]];
        let mut pay_id_list_array: Vec<Vec<PayIdList<H256>>> = vec![
            vec![init_pay_id_list.clone(), init_pay_id_list.clone()],
            vec![init_pay_id_list.clone(), init_pay_id_list.clone()],
        ];
        for i in 0..channel_id_len {
            pay_info = get_pay_id_list_info(pay_amounts_array[i].clone(), conditions);
            _pay_id_lists[i] = pay_info.0[i].clone();
            _cond_pay_array = pay_info.2;

            head_pay_id_lists[i] = pay_info.0[0].clone();
            pay_id_list_hash_array.push(pay_info.1.clone());
            cond_pays[i] = _cond_pay_array;
            total_pending_amounts.push(pay_info.3);
            pay_id_list_array[i] = pay_info.4;
        }

        let init_signed_simplex_state = get_single_signed_simplex_state(
            channel_ids[0],
            receiver_account.clone(),
            peers_pair.clone(),
        );
        let mut signed_simplex_states: Vec<
            SignedSimplexState<H256, AccountId, BlockNumber, Balance, Signature>,
        > = vec![init_signed_simplex_state.clone(), init_signed_simplex_state];
        for i in 0..channel_id_len {
            if seq_nums[i] > 0 {
                // co-signed non-null state
                signed_simplex_states[i] = get_co_signed_simplex_state(
                    channel_ids[i],
                    peer_froms[i],
                    seq_nums[i],
                    transfer_amounts[i],
                    head_pay_id_lists[i].clone(),
                    last_pay_resolve_deadlines[i],
                    total_pending_amounts[i],
                    receiver_account,
                    peers_pair.clone(),
                );
            } else if seq_nums[i] == 0 {
                //  single-signed null state
                signed_simplex_states[i] = get_single_signed_simplex_state(
                    channel_ids[i],
                    receiver_account,
                    peers_pair.clone(),
                );
            }
        }
        let signed_simplex_state_array: SignedSimplexStateArray<
            H256,
            AccountId,
            BlockNumber,
            Balance,
            Signature,
        >;
        signed_simplex_state_array = SignedSimplexStateArray {
            signed_simplex_states: signed_simplex_states,
        };

        return (
            signed_simplex_state_array,
            last_pay_resolve_deadlines,
            cond_pays,
            pay_id_list_hash_array,
            pay_id_list_array,
        );
    }

    pub fn get_pay_id_list_info(
        pay_amounts: Vec<Vec<Balance>>,
        pay_conditions: u8,
    ) -> (
        Vec<PayIdList<H256>>,
        Vec<H256>,
        Vec<Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>>,
        Balance,
        Vec<PayIdList<H256>>,
    ) {
        // Initial value of pay id list
        let init_pay_id_list = PayIdList {
            pay_ids: vec![H256::from_low_u64_be(0)],
            next_list_hash: None,
        };
        // 1-d array PayIdList
        let mut pay_id_lists: Vec<PayIdList<H256>> =
            vec![init_pay_id_list.clone(), init_pay_id_list.clone()];

        // 1-d array PayIdList, for clearing pays in Celer Ledger
        let mut pay_id_list_array: Vec<PayIdList<H256>> =
            vec![init_pay_id_list.clone(), init_pay_id_list.clone()];

        let mut pay_id_list_hash_array: Vec<H256> =
            vec![H256::from_low_u64_be(0), H256::from_low_u64_be(0)];

        // Initial value pf cond_pay
        let init_conditions = get_condition(1);
        let init_transfer_func = get_transfer_func_2(1);
        let init_cond_pay = ConditionalPay {
            pay_timestamp: 0,
            src: account_key("src"),
            dest: account_key("dest"),
            conditions: vec![init_conditions],
            transfer_func: init_transfer_func,
            resolve_deadline: 0,
            resolve_timeout: 0,
        };
        // 2-d array list of PayIdList of a simplex channel,
        // for resolving pays with PayRegistry
        // Index is consistent with PayAmounts.
        let mut cond_pay_array: Vec<
            Vec<ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>>,
        > = vec![
            vec![init_cond_pay.clone(), init_cond_pay.clone()],
            vec![init_cond_pay.clone(), init_cond_pay.clone()],
        ];
        // total pending amount in payAmounts/this state
        let mut total_pending_amount: Balance = 0;

        let pay_amounts_len = pay_amounts.len();

        let mut i: usize = pay_amounts_len - 1;

        loop {
            let pay_amounts_len_2 = pay_amounts[i].len();
            let mut pay_ids: Vec<H256> = vec![H256::from_low_u64_be(0), H256::from_low_u64_be(0)];
            for j in 0..pay_amounts_len_2 {
                total_pending_amount += pay_amounts[i][j];
                let conditions: Condition<AccountId, H256>;
                if pay_conditions == 1 {
                    conditions = get_condition(1);
                } else {
                    conditions = get_condition(2);
                }

                let transfer_func = get_transfer_func_2(pay_amounts[i][j]);
                cond_pay_array[i][j] = ConditionalPay {
                    pay_timestamp: Timestamp::get() + j as u64,
                    src: account_key("src"),
                    dest: account_key("dest"),
                    conditions: vec![conditions],
                    transfer_func: transfer_func,
                    resolve_deadline: 999999,
                    resolve_timeout: 5,
                };
                let encoded_cond_pay = encode_conditional_pay(cond_pay_array[i][j].clone());
                let pay_hash = hashing::blake2_256(&encoded_cond_pay).into();
                pay_ids[j] = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
            }

            if i == pay_amounts_len - 1 {
                pay_id_lists[i] = PayIdList {
                    pay_ids: pay_ids,
                    next_list_hash: None,
                };
            } else {
                let k = i + 1;
                pay_id_lists[i] = PayIdList {
                    pay_ids: pay_ids,
                    next_list_hash: Some(pay_id_list_hash_array[k]),
                };
            }

            let pay_ids_len = pay_id_lists[i].pay_ids.len();
            let mut encoded = pay_id_lists[i].next_list_hash.encode();
            for q in 0..pay_ids_len {
                encoded.extend(pay_id_lists[i].pay_ids[q].encode());
            }
            pay_id_list_hash_array[i] = hashing::blake2_256(&encoded).into();

            pay_id_list_array[i] = pay_id_lists[i].clone();

            if i == 0 {
                break;
            }
            i = i - 1;
        }

        return (
            pay_id_lists,
            pay_id_list_hash_array,
            cond_pay_array,
            total_pending_amount,
            pay_id_list_array,
        );
    }

    pub fn get_signed_simplex_state_array(
        channel_ids: Vec<H256>,
        seq_nums: Vec<u128>,
        transfer_amounts: Vec<Balance>,
        last_pay_resolve_deadlines: Vec<BlockNumber>,
        pay_id_lists: Vec<PayIdList<H256>>,
        peer_froms: Vec<AccountId>,
        signers: Vec<AccountId>,
        total_pending_amounts: Vec<Balance>,
        receiver_account: AccountId,
        peers_pair: Vec<sr25519::Pair>,
    ) -> SignedSimplexStateArray<H256, AccountId, BlockNumber, Balance, Signature> {
        let mut signed_simplex_states: Vec<
            SignedSimplexState<H256, AccountId, BlockNumber, Balance, Signature>,
        > = vec![];
        let channel_id_len = channel_ids.len();
        for i in 0..channel_id_len {
            if seq_nums[i] > 0 {
                // co-signed non-null state
                signed_simplex_states.push(get_co_signed_simplex_state(
                    channel_ids[i],
                    peer_froms[i],
                    seq_nums[i],
                    transfer_amounts[i],
                    pay_id_lists[i].clone(),
                    last_pay_resolve_deadlines[i],
                    total_pending_amounts[i],
                    receiver_account,
                    peers_pair.clone(),
                ));
            } else if seq_nums[i] == 0 {
                //  single-signed null state
                signed_simplex_states.push(get_single_signed_simplex_state(
                    channel_ids[i],
                    receiver_account,
                    peers_pair.clone(),
                ));
            }
        }
        let signed_simplex_state_array: SignedSimplexStateArray<
            H256,
            AccountId,
            BlockNumber,
            Balance,
            Signature,
        >;
        signed_simplex_state_array = SignedSimplexStateArray {
            signed_simplex_states: signed_simplex_states,
        };

        return signed_simplex_state_array;
    }

    pub fn get_single_signed_simplex_state(
        channel_id: H256,
        signer: AccountId,
        peers_pair: Vec<sr25519::Pair>,
    ) -> SignedSimplexState<H256, AccountId, BlockNumber, Balance, Signature> {
        let simplex_payment_channel = SimplexPaymentChannel {
            channel_id: channel_id,
            peer_from: None,
            seq_num: 0,
            transfer_to_peer: None,
            pending_pay_ids: None,
            last_pay_resolve_deadline: None,
            total_pending_amount: None,
        };

        let mut encoded = simplex_payment_channel.channel_id.encode();
        encoded.extend(simplex_payment_channel.peer_from.encode());
        encoded.extend(simplex_payment_channel.seq_num.encode());
        encoded.extend(simplex_payment_channel.transfer_to_peer.encode());
        encoded.extend(simplex_payment_channel.pending_pay_ids.encode());
        encoded.extend(simplex_payment_channel.last_pay_resolve_deadline.encode());
        encoded.extend(simplex_payment_channel.total_pending_amount.encode());

        if signer == peers_pair[0].public() {
            let sig = peers_pair[0].sign(&encoded);
            let signed_simplex_state = SignedSimplexState {
                simplex_state: simplex_payment_channel,
                sigs: vec![sig],
            };
            return signed_simplex_state;
        } else {
            let sig = peers_pair[1].sign(&encoded);
            let signed_simplex_state = SignedSimplexState {
                simplex_state: simplex_payment_channel,
                sigs: vec![sig],
            };
            return signed_simplex_state;
        }
    }

    pub fn get_co_signed_simplex_state(
        channel_id: H256,
        peer_from: AccountId,
        seq_num: u128,
        transfer_amount: Balance,
        pending_pay_ids: PayIdList<H256>,
        last_pay_resolve_deadline: BlockNumber,
        total_pending_amount: Balance,
        receiver_account: AccountId,
        peers_pair: Vec<sr25519::Pair>,
    ) -> SignedSimplexState<H256, AccountId, BlockNumber, Balance, Signature> {
        let transfer_to_peer = get_token_transfer(receiver_account, transfer_amount);

        let simplex_payment_channel = SimplexPaymentChannel {
            channel_id: channel_id,
            peer_from: Some(peer_from),
            seq_num: seq_num,
            transfer_to_peer: Some(transfer_to_peer),
            pending_pay_ids: Some(pending_pay_ids),
            last_pay_resolve_deadline: Some(last_pay_resolve_deadline),
            total_pending_amount: Some(total_pending_amount),
        };
        let pay_id_len = simplex_payment_channel.clone().pending_pay_ids.unwrap().pay_ids.len();
        let mut encoded = simplex_payment_channel.channel_id.encode();
        encoded.extend(simplex_payment_channel.peer_from.encode());
        encoded.extend(simplex_payment_channel.seq_num.encode());
        encoded.extend(simplex_payment_channel.clone().transfer_to_peer.unwrap().token.token_type.encode());
        encoded.extend(simplex_payment_channel.clone().transfer_to_peer.unwrap().receiver.account.encode());
        encoded.extend(simplex_payment_channel.clone().transfer_to_peer.unwrap().receiver.amt.encode());
        encoded.extend(simplex_payment_channel.clone().pending_pay_ids.unwrap().next_list_hash.encode());
        encoded.extend(simplex_payment_channel.last_pay_resolve_deadline.encode());
        encoded.extend(simplex_payment_channel.total_pending_amount.encode());
        for i in 0..pay_id_len {
            encoded.extend(simplex_payment_channel.clone().pending_pay_ids.unwrap().pay_ids[i].encode());
        }
        let sig_1 = peers_pair[0].sign(&encoded);
        let sig_2 = peers_pair[1].sign(&encoded);
        let signed_simplex_state = SignedSimplexState {
            simplex_state: simplex_payment_channel,
            sigs: vec![sig_1, sig_2],
        };

        return signed_simplex_state;
    }

    pub fn get_cooperative_settle_request(
        channel_id: H256,
        seq_num: u128,
        channel_peers: Vec<AccountId>,
        settle_amounts: Vec<Balance>,
        settle_deadline: BlockNumber,
        peers_pairs: Vec<sr25519::Pair>,
    ) -> CooperativeSettleRequest<H256, BlockNumber, AccountId, Balance, Signature> {
        let account_amt_pair_1 = AccountAmtPair {
            account: Some(channel_peers[0]),
            amt: settle_amounts[0],
        };
        let account_amt_pair_2 = AccountAmtPair {
            account: Some(channel_peers[1]),
            amt: settle_amounts[1],
        };
        let settle_info = CooperativeSettleInfo {
            channel_id: channel_id,
            seq_num: seq_num,
            settle_balance: vec![account_amt_pair_1, account_amt_pair_2],
            settle_deadline: settle_deadline,
        };

        let mut encoded = settle_info.channel_id.encode();
        encoded.extend(settle_info.seq_num.encode());
        encoded.extend(settle_info.settle_balance[0].clone().account.encode());
        encoded.extend(settle_info.settle_balance[0].clone().amt.encode());
        encoded.extend(settle_info.settle_balance[1].clone().account.encode());
        encoded.extend(settle_info.settle_balance[1].clone().amt.encode());
        encoded.extend(settle_info.settle_deadline.encode());
        let sig_1 = peers_pairs[0].sign(&encoded);
        let sig_2 = peers_pairs[1].sign(&encoded);

        let cooperative_settle_request = CooperativeSettleRequest {
            settle_info: settle_info,
            sigs: vec![sig_1, sig_2],
        };

        return cooperative_settle_request;
    }

    pub fn get_token_transfer(
        account: AccountId,
        amount: Balance,
    ) -> TokenTransfer<AccountId, Balance> {
        let account_amt_pair = AccountAmtPair {
            account: Some(account),
            amt: amount,
        };

        let token_info = TokenInfo {
            token_type: TokenType::CELER,
        };

        let token_transfer = TokenTransfer {
            token: token_info,
            receiver: account_amt_pair,
        };

        return token_transfer;
    }

    pub fn get_transfer_func_2(amount: Balance) -> TransferFunction<AccountId, Balance> {
        let account_amt_pair = AccountAmtPair {
            account: None,
            amt: amount,
        };

        let token_info = TokenInfo {
            token_type: TokenType::CELER,
        };

        let token_transfer = TokenTransfer {
            token: token_info,
            receiver: account_amt_pair,
        };

        let transfer_func = TransferFunction {
            logic_type: TransferFunctionType::BooleanAnd,
            max_transfer: token_transfer,
        };

        return transfer_func;
    }

    pub fn calculate_channel_id(
        open_request: OpenChannelRequest<AccountId, BlockNumber, Balance, Signature>,
        channel_peers: Vec<AccountId>,
    ) -> H256 {
        let channel_initializer = open_request.channel_initializer;
        let encoded_1 = encode_channel_initializer::<TestRuntime>(channel_initializer);
        let nonce: H256 = hashing::blake2_256(&encoded_1).into();
        let mut encoded_2 = channel_peers[0].encode();
        encoded_2.extend(channel_peers[1].encode());
        encoded_2.extend(nonce.encode());
        let channel_id = hashing::blake2_256(&encoded_2).into();
        return channel_id;
    }
}
