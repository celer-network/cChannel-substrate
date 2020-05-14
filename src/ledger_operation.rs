
use codec::{Encode, Decode};
use frame_support::{ensure, storage::{StorageMap}};
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_system::{self as system, ensure_signed};
use sp_runtime::{ModuleId, DispatchError, RuntimeDebug};
use sp_runtime::traits::{Hash, Zero, AccountIdConversion};
use crate::celer_wallet::{CelerWallet, WALLET_ID, Wallet, WalletOf};
use crate::eth_pool::EthPool;
use crate::pay_registry::PayRegistry;
use super::{
    Trait, Module, Error, BalanceOf, ChannelMap, 
    ChannelStatusNums, Wallets, 
};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum ChannelStatus {
    Uninitialized = 0,
    Operable = 1,
    Settling = 2,
    Closed = 3,
    Migrated = 4,
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PeerState<Hash, BlockNumber, Balance> {
    pub seq_num: u128,
    pub transfer_out: Balance,
    pub next_pay_id_list_hash: Hash,
    pub last_pay_resolve_deadline: BlockNumber,
    pub pending_pay_out: Balance,
}

pub type PeerStateOf<T> = PeerState<<T as system::Trait>::Hash, <T as system::Trait>::BlockNumber, BalanceOf<T>>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PeerProfile<AccountId, Balance, BlockNumber, Hash> {
    pub peer_addr: AccountId,
    pub deposit: Balance,
    pub withdrawal: Option<Balance>,
    pub state: PeerState<Hash, BlockNumber, Balance>,
}

pub type PeerProfileOf<T> = PeerProfile<<T as system::Trait>::AccountId, BalanceOf<T>, <T as system::Trait>::BlockNumber, <T as system::Trait>::Hash>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct WithdrawIntent<AccountId, Balance, BlockNumber, Hash> {
    pub receiver: AccountId,
    pub amount: Option<Balance>,
    pub request_time: Option<BlockNumber>,
    pub recipient_channel_id: Option<Hash>,
}

pub type WithdrawIntentOf<T> = WithdrawIntent<<T as system::Trait>::AccountId, BalanceOf<T>, <T as system::Trait>::BlockNumber, <T as system::Trait>::Hash>;

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

pub type ChannelOf<T> = Channel<<T as system::Trait>::AccountId, <T as system::Trait>::BlockNumber, BalanceOf<T>, <T as system::Trait>::Hash>;

// ================================= LedgerOperation =============================
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum TokenType {
    INVALID,
    CELER,
    ERC20,
}

// Currently ETH is only uspported.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenInfo  {
    pub token_type: TokenType
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct AccountAmtPair<AccountId, Balance> {
    pub account: AccountId,
    pub amt: Balance,
}

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
    pub next_list_hash: Hash,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenTransfer<AccountId, Balance> {
    pub token: TokenInfo,
    pub receiver: AccountAmtPair<AccountId, Balance>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SimplexPaymentChannel<Hash, AccountId, BlockNumber, Balance> {
    pub channel_id: Hash,
    pub peer_from: AccountId,
    pub seq_num: u128,
    pub transfer_to_peer: TokenTransfer<AccountId, Balance>,
    pub pending_pay_ids: PayIdList<Hash>,
    pub last_pay_resolve_deadline: BlockNumber,
    pub total_pending_amount: Balance,
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

pub type CooperativeSettleInfoOf<T> = CooperativeSettleInfo<<T as system::Trait>::Hash, <T as system::Trait>::BlockNumber, <T as system::Trait>::AccountId, BalanceOf<T>>;

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
    // Open a state channel through auth withdraw message
    pub fn open_channel(
        origin: T::Origin,
        open_request: OpenChannelRequestOf<T>,
        amount: BalanceOf<T>
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
            <frame_system::Module<T>>::block_number() < channel_initializer.open_deadline,
            "Open deadline passed"
        );

        let token = channel_initializer.init_distribution.token.clone();
        let amounts: Vec<BalanceOf<T>> = vec![
            channel_initializer.init_distribution.distribution[0].amt.clone(),
            channel_initializer.init_distribution.distribution[1].amt.clone()
        ];
        let peer_addrs: Vec<T::AccountId> = vec![
            channel_initializer.init_distribution.distribution[0].account.clone(),
            channel_initializer.init_distribution.distribution[1].account.clone()
        ];
        /// Enforce asceding order of peer's addresses to simplyfy contract code
        ensure!(
            peer_addrs[0] < peer_addrs[1], 
            "Peer addrs are not ascending"
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
        let signers = vec![peer_addrs[0].clone(), peer_addrs[1].clone()];
        Module::<T>::valid_signers(open_request.sigs, &encoded, signers)?;

        let owners = vec![peer_addrs[0].clone(), peer_addrs[1].clone()];
        let h = T::Hashing::hash(&encoded);
        let channel_id = create_wallet::<T>(owners, h)?;

        /// Insert new Channel to ChannelMap.
        let zero_balance: BalanceOf<T> = Zero::zero();
        let zero_hash: T::Hash = zero_hash::<T>();
        let zero_blocknumber: T::BlockNumber = Zero::zero();
        let peer_state = PeerStateOf::<T> {
            seq_num: 0,
            transfer_out: zero_balance,
            next_pay_id_list_hash: zero_hash,
            last_pay_resolve_deadline: zero_blocknumber,
            pending_pay_out: zero_balance
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
            recipient_channel_id: None
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

        let amt_sum: BalanceOf<T> = amounts[0] + amounts[1];
        let zero_balance: BalanceOf<T> = Zero::zero();
        // if total deposit is 0
        if amt_sum == zero_balance {
            ensure!(
                amount == zero_balance,
                "amount is not 0"
            );

            ChannelMap::<T>::insert(channel_id, channel);
            return Ok(channel_id);
        }

        // if total deposit is larger than 0
        let balance_limits_enabled = channel_initializer.balance_limits_enabled;
        if balance_limits_enabled {
            let balance_limits = match channel_initializer.balance_limits {
                Some(limits) => limits,
                None => return Err(Error::<T>::BalanceLimitsNotExist)?
            };

            ensure!(
                amt_sum <= balance_limits,
                "Balance exceeds limit"
            );
        }

        if token.token_type == TokenType::CELER {
            let msg_value_receiver = channel_initializer.msg_value_receiver as usize;
            ensure!(
                amount == amounts[msg_value_receiver],
                "amount mismatch"
            );
            if amounts[msg_value_receiver] > zero_balance {
                CelerWallet::<T>::deposit_celer(origin, channel_id, amount)?;
            }

            // peer ID of non-msg_value_receiver
            let pid: usize = 1 - msg_value_receiver;
            if amounts[pid] > zero_balance {
                let ledger_addr = Self::ledger_account();
                EthPool::<T>::transfer_to_celer_wallet_by_ledger(
                    ledger_addr,
                    peer_addrs[pid].clone(),
                    channel_id,
                    amounts[pid]
                )?;
            }
        } else {
            Err(Error::<T>::Error)?
        }

        ChannelMap::<T>::insert(channel_id, channel);

        return Ok(channel_id);
    }

    // Deposit CELER or ERC20 tokens into the channel
    pub fn deposit(
        origin: T::Origin,
        channel_id: T::Hash,
        receiver: T::AccountId,
        amount: BalanceOf<T>,
        transfer_from_amount: BalanceOf<T> 
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin.clone())?;
        let c: ChannelOf<T> = match ChannelMap::<T>::get(&channel_id) {
            Some(channel) => channel,
            None => Err(Error::<T>::ChannelNotExist)?
        };
        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances."
        );
        let deposit_amount: BalanceOf<T> = amount + transfer_from_amount;
        add_deposit::<T>(channel_id, receiver.clone(), deposit_amount)?;

        let zero_balance: BalanceOf<T> = Zero::zero();
        if c.token.token_type == TokenType::CELER {
            if amount > zero_balance {
                CelerWallet::<T>::deposit_celer(origin, channel_id, amount)?;
            }
            let ledger_account = Self::ledger_account();
            if transfer_from_amount > zero_balance {
                EthPool::<T>::transfer_to_celer_wallet_by_ledger(
                    ledger_account,
                    caller,
                    channel_id,
                    transfer_from_amount
                )?;
            }
        } else {
            Err(Error::<T>::Error)?
        }
        
        Ok(())
    }

    /// Strore signed simplex states on-chain as checkpoints
    pub fn snapshot_states(
        signed_simplex_state_array: SignedSimplexStateArrayOf<T>
    ) -> Result<(), DispatchError> {
        let state_len = signed_simplex_state_array.signed_simplex_states.len();

        /// snapshot each state
        let mut simplex_state = signed_simplex_state_array.signed_simplex_states[0].simplex_state.clone();
        for i in 0..state_len {
            let current_channel_id: T::Hash = simplex_state.channel_id;
            let c: ChannelOf<T> = ChannelMap::<T>::get(current_channel_id).unwrap();

            ensure!(
                c.status == ChannelStatus::Operable,
                "Channel status error"
            );

            /// Check Co-Signatures.
            let mut encoded = signed_simplex_state_array.signed_simplex_states[i].simplex_state.channel_id.encode();
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.peer_from.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.seq_num.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.transfer_to_peer.token.token_type.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.transfer_to_peer.receiver.account.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.transfer_to_peer.receiver.amt.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.pending_pay_ids.pay_ids.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.pending_pay_ids.next_list_hash.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.last_pay_resolve_deadline.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.total_pending_amount.encode());
            let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
            let channel_peer = vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[0].peer_addr.clone()];
            Module::<T>::valid_signers(sigs, &encoded, channel_peer)?;

            let mut state: PeerStateOf<T>;
            if c.peer_profiles[0].peer_addr == simplex_state.peer_from {
                state = c.peer_profiles[0].clone().state;
            } else {
                state = c.peer_profiles[1].clone().state;
            }
            
            ensure!(
                simplex_state.seq_num > state.seq_num,
                "seqNum error"
            );

            // No need to update nextPayIdListHash and lastPayResolveDeadline for snapshot purpose
            state.seq_num = simplex_state.seq_num;
            state.transfer_out = simplex_state.transfer_to_peer.receiver.amt;
            state.pending_pay_out = simplex_state.total_pending_amount;

            if i == state_len {
                let current_channel: ChannelOf<T> = match ChannelMap::<T>::get(current_channel_id) {
                    Some(channel) => channel,
                    None => Err(Error::<T>::ChannelNotExist)?
                };
                
                let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                Module::<T>::emit_snapshot_states(current_channel_id, seq_nums[0], seq_nums[1])?;
               
            } else if i < state_len {
                simplex_state = signed_simplex_state_array.signed_simplex_states[i+1].simplex_state.clone();
                // enforce channel_ids of simplex states are ascending
                ensure!(
                    current_channel_id <= simplex_state.channel_id,
                    "Non-ascending channelIds"
                );
                if current_channel_id < simplex_state.channel_id {
                    let seq_nums = get_state_seq_nums::<T>(current_channel_id);
                    Module::<T>::emit_snapshot_states(current_channel_id, seq_nums[0], seq_nums[1])?;
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
        recipient_channel_id: T::Hash
    ) -> Result<(T::Hash, T::AccountId, BalanceOf<T>), DispatchError> {
        let receiver = ensure_signed(origin)?;
        let c: ChannelOf<T> = match ChannelMap::<T>::get(channel_id) {
            Some(channel) => channel,
            None => Err(Error::<T>::ChannelNotExist)?
        };
        let withdraw_intent =  c.withdraw_intent.clone();

        ensure!(
            c.status == ChannelStatus::Operable,
            "Channel status error"
        );
        
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
            request_time: Some(<frame_system::Module<T>>::block_number()),
            recipient_channel_id: Some(recipient_channel_id)
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
            withdraw_intent: new_withdraw_intent
        };

        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));

        return Ok((channel_id, receiver, amount));
    }

    // Confirm channel withdrawal
    pub fn confirm_withdraw(
        channel_id: T::Hash
    ) -> Result<(BalanceOf<T>, T::AccountId, T::Hash), DispatchError> {
        let c = ChannelMap::<T>::get(channel_id).unwrap();
        ensure!(
            c.status == ChannelStatus::Operable,
            "Channel status error"
        );
        let ledger_addr = Self::ledger_account();
        let withdraw_intent = c.withdraw_intent;     
        ensure!(
            withdraw_intent.receiver != ledger_addr,
            "No pending withdraw intent"
        );

        let zero_blocknumber: T::BlockNumber = Zero::zero();
        let dispute_timeout = withdraw_intent.request_time.unwrap_or(zero_blocknumber) + c.dispute_timeout;
        let block_number = <frame_system::Module<T>>::block_number();
        ensure!(
            block_number >= dispute_timeout,
            "Dispute not timeout"
        );


        let zero_balance: BalanceOf<T> = Zero::zero();
        let zero_channel_id: T::Hash = zero_hash::<T>(); 
        let receiver = withdraw_intent.receiver;
        let amount = withdraw_intent.amount.unwrap_or(zero_balance);
        let recipient_channel_id = withdraw_intent.recipient_channel_id.unwrap_or(zero_channel_id);

        // Initialize c.wihdraw_intent
        let ledger_addr = Self::ledger_account();
        let initialize_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: ledger_addr,
            amount: None,
            request_time: None,
            recipient_channel_id: None
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
            withdraw_limit += c.peer_profiles[0].deposit;
            withdraw_limit += state_2.transfer_out;
            withdraw_limit -= c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance);
            withdraw_limit -= state_1.transfer_out;
            withdraw_limit -= state_1.pending_pay_out;
        } else {
            withdraw_limit += c.peer_profiles[1].deposit;
            withdraw_limit += state_1.transfer_out;
            withdraw_limit -= c.peer_profiles[1].clone().withdrawal.unwrap_or(zero_balance);
            withdraw_limit -= state_2.transfer_out;
            withdraw_limit -= state_2.pending_pay_out;
        }
        ensure!(
            amount <= withdraw_limit,
            "Exceed withdraw limit"
        );

        // Update record of one peer's withdrawal amount
        if rid == 0 {
            let new_amount: BalanceOf<T> = c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance) + amount;
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: Some(new_amount),
                state: c.peer_profiles[0].clone().state 
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

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else {
            let new_amount: BalanceOf<T> = c.peer_profiles[1].clone().withdrawal.unwrap() + amount;
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: Some(new_amount),
                state: c.peer_profiles[1].clone().state 
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

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        }
        
        withdraw_funds::<T>(channel_id, receiver.clone(), amount, recipient_channel_id)?;

        return Ok((amount, receiver, recipient_channel_id));
    }

    // Veto current withdrawal intent
    pub fn veto_withdraw(
        origin: T::Origin,
        channel_id: T::Hash
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;

        let c = ChannelMap::<T>::get(channel_id).unwrap();
        ensure!(
            c.status == ChannelStatus::Operable,
            "Channel status error"
        );
        let intent = c.withdraw_intent.clone();
        let ledger_addr = Self::ledger_account();

        ensure!(
            intent.receiver != ledger_addr,
            "No pending withdraw intent"
        );
        ensure!(
            Self::is_peer(c.clone(), caller),
            "caller is not peer"    
        );

        let initialize_withdraw_intent = WithdrawIntentOf::<T> {
            receiver: ledger_addr,
            amount: None,
            request_time: None,
            recipient_channel_id: None
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
            withdraw_intent: initialize_withdraw_intent
        };

        ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));

        Ok(())
    }

    // Cooperatively withdraw specific amount of balance
    pub fn cooperative_withdraw(
        cooperative_withdraw_request: CooperativeWithdrawRequestOf<T>
    ) -> Result<(T::Hash, BalanceOf<T>, T::AccountId, T::Hash, u128), DispatchError> {
        let withdraw_info = cooperative_withdraw_request.withdraw_info;
        let channel_id = withdraw_info.channel_id;
        let recipient_channel_id = withdraw_info.recipient_channel_id;
        
        let c = match ChannelMap::<T>::get(channel_id) {
            Some(channel) => channel,
            None => return Err(Error::<T>::ChannelNotExist)?
        };

        ensure!(
            c.status == ChannelStatus::Operable,
            "Channel status error"
        );
        
        // check signatures.
        let mut encoded = withdraw_info.channel_id.encode();
        encoded.extend(withdraw_info.seq_num.encode());
        encoded.extend(withdraw_info.withdraw.account.clone().encode());
        encoded.extend(withdraw_info.withdraw.amt.encode());
        encoded.extend(withdraw_info.withdraw_deadline.encode());
        encoded.extend(withdraw_info.recipient_channel_id.encode());
        let signers = vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()];
        Module::<T>::valid_signers(
            cooperative_withdraw_request.sigs,
            &encoded,
            signers,
        )?;

        // require an increment of exactly 1 for seq_num of each cooperative withdraw request
        let cal_seq = withdraw_info.seq_num - c.cooperative_withdraw_seq_num.unwrap_or(0);
        ensure!(
            cal_seq == 1,
            "seq_num error"
        );
        ensure!(
            <frame_system::Module<T>>::block_number() <= withdraw_info.withdraw_deadline,
            "Withdraw deadline passed"
        );

        let receiver = withdraw_info.withdraw.account;
        let amount = withdraw_info.withdraw.amt;
        let zero_balance: BalanceOf<T> = Zero::zero();
        if receiver == c.peer_profiles[0].peer_addr {
            let new_withdrawal_amount = c.peer_profiles[0].clone().withdrawal.unwrap_or(zero_balance) + amount; 
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: Some(new_withdrawal_amount),
                state: c.peer_profiles[0].clone().state
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else if receiver == c.peer_profiles[1].peer_addr {
            let new_withdrawal_amount = c.peer_profiles[1].clone().withdrawal.unwrap_or(zero_balance) + amount; 
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: Some(new_withdrawal_amount),
                state: c.peer_profiles[1].clone().state
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else {
            Err(Error::<T>::NotChannelPeer)?
        }

        withdraw_funds::<T>(channel_id, receiver.clone(), amount, recipient_channel_id)?;

        return Ok((channel_id, amount, receiver, recipient_channel_id, withdraw_info.seq_num));
    }

    /// Intend to settle channel(s) with an array of signed simplex states
    pub fn intend_settle(
        origin: T::Origin,
        signed_simplex_state_array: SignedSimplexStateArrayOf<T>
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
                    c.status == ChannelStatus::Operable
                    || c.status == ChannelStatus::Settling,
                    "Peer channel status error"
                );
            } else {
                /// A nonpeer cannot be the first one to call intend_settle
                ensure!(c.status == ChannelStatus::Settling, "Nonpeer channel status error");
            }
            ensure!(
                c.settle_finalized_time.unwrap() == zero_blocknumber || <frame_system::Module<T>>::block_number() < c.settle_finalized_time.unwrap(),
                "Settle has already finalized"
            );

            let mut encoded = signed_simplex_state_array.signed_simplex_states[i].simplex_state.channel_id.encode();
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.peer_from.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.seq_num.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.transfer_to_peer.token.token_type.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.transfer_to_peer.receiver.account.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.transfer_to_peer.receiver.amt.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.pending_pay_ids.pay_ids.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.pending_pay_ids.next_list_hash.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.last_pay_resolve_deadline.encode());
            encoded.extend(signed_simplex_state_array.signed_simplex_states[i].simplex_state.total_pending_amount.encode());
            let sigs = signed_simplex_state_array.signed_simplex_states[i].sigs.clone();
            
            if simplex_state.seq_num > 0 {
                let channel_peer = vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()];
                Module::<T>::valid_signers(sigs, &encoded, channel_peer)?;
                /// Ensure each state can be intend_settle at most once
            
                let state: PeerStateOf<T>;
                let peer_from_id: u8;
                if c.peer_profiles[0].peer_addr == simplex_state.peer_from {
                    state = c.peer_profiles[0].state.clone();
                    peer_from_id = 0;
                } else {
                    state = c.peer_profiles[1].state.clone();
                    peer_from_id = 1;
                }
                
                if c.status == ChannelStatus::Operable {
                    ensure!(simplex_state.seq_num >= state.seq_num, "seqNum error");
                } else if c.status == ChannelStatus::Settling {
                    ensure!(simplex_state.seq_num > state.seq_num, "seqNum error");
                } else {
                    Err(Error::<T>::Error)?
                }

                /// Update simplex_state-dependent fields
                let new_state = PeerStateOf::<T> {
                    seq_num: simplex_state.seq_num,
                    transfer_out: simplex_state.transfer_to_peer.receiver.amt.clone(),
                    next_pay_id_list_hash: simplex_state.pending_pay_ids.clone().next_list_hash,
                    last_pay_resolve_deadline: simplex_state.last_pay_resolve_deadline.clone(),
                    pending_pay_out: simplex_state.total_pending_amount.clone(),
                };
                let new_peer_profiles_1 = PeerProfileOf::<T> {
                    peer_addr: c.peer_profiles[0].peer_addr.clone(),
                    deposit: c.peer_profiles[0].deposit.clone(),
                    withdrawal: c.peer_profiles[0].clone().withdrawal.clone(),
                    state: new_state.clone(),
                };
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
                    peer_profiles: vec![new_peer_profiles_1, new_peer_profiles_2],
                    cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
                    withdraw_intent: c.withdraw_intent,
                };

                ChannelMap::<T>::mutate(&current_channel_id, |channel| *channel = Some(new_channel));
                _clear_pays::<T>(current_channel_id, peer_from_id, simplex_state.pending_pay_ids.clone())?;                
            } else if simplex_state.seq_num == 0 { // null state
                // This implies both stored seq_nums are 0
                ensure!(
                    c.settle_finalized_time.unwrap() == zero_blocknumber,
                    "intend_settle before"
                );
                ensure!(
                    sigs.len() == 1,
                    "Invalid signatures length"
                );
                Module::<T>::check_single_signature(sigs[0].clone(), &encoded, c.peer_profiles[0].peer_addr.clone())?;
            } else {
                Err(Error::<T>::Error)?
            }

            if i == state_len {
                update_overall_states_by_intend_state::<T>(current_channel_id.clone())?;
            } else if i < state_len {
                simplex_state = signed_simplex_state_array.signed_simplex_states[i+1].simplex_state.clone();
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
        pay_id_list: PayIdList<T::Hash>
    ) -> Result<(), DispatchError> {
        let c = ChannelMap::<T>::get(channel_id).unwrap();
        ensure!(
            c.status == ChannelStatus::Settling,
            "Channel status error"
        );

        let mut encoded = pay_id_list.pay_ids.encode();
        encoded.extend(pay_id_list.next_list_hash.encode());
        let list_hash = T::Hashing::hash(&encoded);
        if peer_from == c.peer_profiles[0].peer_addr {
            let state = c.peer_profiles[0].state.clone();
            ensure!(
                state.next_pay_id_list_hash == list_hash,
                "List hash mismatch"    
            );
            let new_state = PeerStateOf::<T> {
                seq_num: state.seq_num,
                transfer_out: state.transfer_out,
                next_pay_id_list_hash: pay_id_list.next_list_hash,
                last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                pending_pay_out: state.pending_pay_out
            };
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: c.peer_profiles[0].clone().withdrawal,
                state: new_state
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
            _clear_pays::<T>(channel_id, 0, pay_id_list)?;
        } else if peer_from == c.peer_profiles[1].peer_addr {
            let state = c.peer_profiles[1].clone().state;
            ensure!(
                state.next_pay_id_list_hash == list_hash,
                "List hash mismatch"
            );
            let new_state = PeerStateOf::<T> {
                seq_num: state.seq_num,
                transfer_out: state.transfer_out,
                next_pay_id_list_hash: pay_id_list.next_list_hash,
                last_pay_resolve_deadline: state.last_pay_resolve_deadline,
                pending_pay_out: state.pending_pay_out
            };
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: c.peer_profiles[1].clone().withdrawal,
                state: new_state
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
                withdraw_intent: c.withdraw_intent
            };
            
            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
            _clear_pays::<T>(channel_id, 1, pay_id_list)?;
        }

        Ok(())
    }

    // confirm channel settlement
    pub fn confirm_settle(
        channel_id: T::Hash
    ) -> Result<(), DispatchError> {
        let c = ChannelMap::<T>::get(channel_id).unwrap();
        let peer_profiles = vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()];
        let block_number = <frame_system::Module<T>>::block_number();
        ensure!(
            c.status == ChannelStatus::Settling,
            "Channel status error"
        );
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
        let zero = zero_hash::<T>();
        ensure!(
            (state_1.next_pay_id_list_hash == zero ||
                block_number > state_1.last_pay_resolve_deadline) &&
            (state_2.next_pay_id_list_hash == zero ||
                block_number > state_2.last_pay_resolve_deadline),
            "Payments are not finalized"
        );

        let (valid_balance, settle_balance): (bool, Vec<BalanceOf<T>>) 
                = validate_settle_balance::<T>(channel_id);

        if valid_balance {
            reset_duplex_state::<T>(channel_id);
            Module::<T>::emit_confirm_settle_fail(channel_id)?;
            Err(Error::<T>::ConfirmSettleFail)?
        }

        update_channel_status::<T>(channel_id, ChannelStatus::Closed)?;
        
        Module::<T>::emit_confirm_settle(channel_id, settle_balance.clone())?;

        // Withdrawal from Contracts pattern is needles here,
        // because peers need sign messages which implies that they cannot be contracts
        batch_transfer_out::<T>(
            channel_id,
            vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()],
            settle_balance
        )?;

        return Ok(());
    }

    // Cooperatively settle the channel
    pub fn cooperative_settle(
        settle_request: CooperativeSettleRequestOf<T>
    ) -> Result<(T::Hash, Vec<BalanceOf<T>>), DispatchError> {
        let settle_info = settle_request.settle_info;
        let channel_id = settle_info.channel_id;
        let c = ChannelMap::<T>::get(channel_id).unwrap();
        ensure!(
            c.status == ChannelStatus::Operable ||
                c.status == ChannelStatus::Settling,
            "Channel status error"
        );

        // Check co-signature
        let mut encoded = settle_info.channel_id.encode();
        encoded.extend(settle_info.seq_num.encode());
        encoded.extend(settle_info.settle_balance[0].clone().account.encode());
        encoded.extend(settle_info.settle_balance[0].clone().amt.encode());
        encoded.extend(settle_info.settle_balance[1].clone().account.encode());
        encoded.extend(settle_info.settle_balance[1].clone().amt.encode());
        encoded.extend(settle_info.settle_deadline.encode());
        let signers = vec![settle_info.settle_balance[0].account.clone(), settle_info.settle_balance[1].account.clone()];
        Module::<T>::valid_signers(settle_request.sigs, &encoded, signers)?;
        
        let peer_addrs = vec![c.peer_profiles[0].peer_addr.clone(), c.peer_profiles[1].peer_addr.clone()];
        let state_1 = c.peer_profiles[0].state.clone(); 
        let state_2 = c.peer_profiles[1].state.clone(); 

        ensure!(
            settle_info.seq_num > state_1.seq_num &&
                settle_info.seq_num > state_2.seq_num,
            "seq_num error"
        );
        ensure!(
            settle_info.settle_balance[0].account == peer_addrs[0] &&
                settle_info.settle_balance[1].account == peer_addrs[1],
            "Settle accounts mismatch"
        );

        let settle_balance = vec![settle_info.settle_balance[0].amt, settle_info.settle_balance[1].amt];
        let total_settle_balance = settle_balance[0] + settle_balance[1];
        let total_balance = Module::<T>::get_total_balance(channel_id);
        ensure!(
            total_settle_balance == total_balance,
            "Balance sum mismatch"
        );

        update_channel_status::<T>(channel_id, ChannelStatus::Closed)?;

        /// TODO: Emit CoooperativeSettle event

        batch_transfer_out::<T>(channel_id, peer_addrs, settle_balance.clone())?;

        return Ok((channel_id, settle_balance));
    }

    /// Check if addr is one of the peers in channel c
    pub fn is_peer(c: ChannelOf<T>, addr: T::AccountId) -> bool {
        return addr == c.peer_profiles[0].peer_addr || addr == c.peer_profiles[1].peer_addr;
    }

    // Get address of ledger module
    pub fn ledger_account() -> T::AccountId {
        CELER_LEDGER_ID.into_account()
    }
}

/// create a wallet for a new channel
fn create_wallet<T: Trait>(
    peers: Vec<T::AccountId>,
    nonce: T::Hash
) -> Result<T::Hash, DispatchError> {
    let owners = vec![peers[0].clone(), peers[1].clone()];
    let mut encoded = owners[0].encode();
    encoded.extend(owners[1].encode());
    encoded.extend(nonce.encode());
    let wallet_id: T::Hash = T::Hashing::hash(&encoded);

    /// Check wallet_id is not exist.
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

    /// create new wallet
    Wallets::<T>::insert(&wallet_id, &wallet);

    return Ok(wallet_id);
}

// Internal function to add deposit of a channel
fn add_deposit<T: Trait>(
    channel_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>
) -> Result<(), DispatchError>{
    let c: ChannelOf<T> = ChannelMap::<T>::get(channel_id).unwrap();
    ensure!(
        c.status == ChannelStatus::Operable,
        "Channel status errror"
    );

    if c.balance_limits_enabled == true {
        let total_balance = Module::<T>::get_total_balance(channel_id.clone());
        let added_amount = amount + total_balance;
        let limits = match c.balance_limits {
            Some(limits) => limits,
            None => Err(Error::<T>::BalanceLimitsNotExist)?
        };
        ensure!(
            added_amount <= limits,
            "Balance exceeds limit"
        );
    }

    let new_deposit_balance: BalanceOf<T>;
    let new_channel: ChannelOf<T>;
    if receiver == c.peer_profiles[0].peer_addr {
        new_deposit_balance = c.peer_profiles[0].deposit + amount;
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
    } else if receiver == c.peer_profiles[1].peer_addr{
        new_deposit_balance = c.peer_profiles[1].deposit + amount;
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

    //TODO emit Deposit Event
    Ok(())
}

// Internal function to transfer funds out in batch
fn batch_transfer_out<T: Trait>(
    channel_id: T::Hash,
    receivers: Vec<T::AccountId>,
    amounts: Vec<BalanceOf<T>>
) -> Result<(), DispatchError> {
    let zero_balance: BalanceOf<T> = Zero::zero();
    for i in 0..1 {
        if amounts[i] == zero_balance {
            continue;
        }
        withdraw::<T>(
            channel_id,
            receivers[i].clone(),
            amounts[i]
        )?;
    }

    Ok(())
}

// Internal functions to withdraw funds out of the channel
fn withdraw_funds<T: Trait>(
    channel_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>,
    recipient_channel_id: T::Hash
) -> Result<(), DispatchError> {
    let zero_balance: BalanceOf<T> = Zero::zero();
    if amount == zero_balance {
        return Ok(());
    }

    let zero_channel_id: T::Hash = zero_hash::<T>();
    let c = ChannelMap::<T>::get(channel_id).unwrap();

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
        transfer_to_wallet::<T>(
            channel_id,
            recipient_channel_id,
            receiver,
            amount
        )?;
    }

    Ok(())
}

// Reset the state of the channel
fn reset_duplex_state<T: Trait>(
    channel_id: T::Hash
) {
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    let new_channel = ChannelOf::<T> {
        balance_limits_enabled: c.balance_limits_enabled,
        balance_limits: c.balance_limits,
        settle_finalized_time: None,
        dispute_timeout: c.dispute_timeout,
        token: c.token,
        status: c.status,
        peer_profiles: vec![c.peer_profiles[0].clone(), c.peer_profiles[1].clone()],
        cooperative_withdraw_seq_num: c.cooperative_withdraw_seq_num,
        withdraw_intent: c.withdraw_intent
    };

    ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
}

// Clear payments by their hash array
fn _clear_pays<T: Trait>(
    channel_id: T::Hash,
    peer_id: u8,
    pay_id_list: PayIdList<T::Hash>
) -> Result<(), DispatchError> { 
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    let zero_balance: BalanceOf<T> = Zero::zero();
    let out_amts: Vec<BalanceOf<T>>;
    if peer_id == 0 {
        // updating pending_pay_out is only needed when migrating ledger during settling phrase, 
        // which will affect the withdraw limit after the migration.
        let state_1 = c.peer_profiles[0].state.clone();
        out_amts = PayRegistry::<T>::get_pay_amounts(
            pay_id_list.pay_ids,
            state_1.last_pay_resolve_deadline
        )?;
        let mut total_amt_out: BalanceOf::<T> = Zero::zero();
        let out_amts_len = out_amts.len() - 1;
        for i in 0..out_amts_len {
            total_amt_out += out_amts[i];
            // TODO emit ClearOnePay event
        }
        let new_transfer_out_1 = state_1.transfer_out + total_amt_out;
        let hash_zero = zero_hash::<T>();
        if pay_id_list.next_list_hash == hash_zero {
            // if there are not more uncleared pays in this state, the pending_pay_out must be 0
            let new_state_1 = PeerStateOf::<T> {
                seq_num: state_1.seq_num,
                transfer_out: new_transfer_out_1,
                next_pay_id_list_hash: state_1.next_pay_id_list_hash,
                last_pay_resolve_deadline: state_1.last_pay_resolve_deadline,
                pending_pay_out: zero_balance
            };
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: c.peer_profiles[0].clone().withdrawal,
                state: new_state_1
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else {
            // Note: if there are more uncleared pays in this state, because resolved pay amount 
            //      is always less than or equal to the corresponding maximum amount counted in 
            //      pending_pay_out, the updated pending_pay_out may be equal to or larger than the real
            //      pending_pay_out. This will lead to decreasing the maximum withdraw amount (withdraw_limit)
            //      from potentially maliciout non-cooperative withdraw.
            let new_pending_pay_out = state_1.pending_pay_out - total_amt_out;
            let new_state_1 = PeerStateOf::<T> {
                seq_num: state_1.seq_num,
                transfer_out: new_transfer_out_1,
                next_pay_id_list_hash: state_1.next_pay_id_list_hash,
                last_pay_resolve_deadline: state_1.last_pay_resolve_deadline,
                pending_pay_out: new_pending_pay_out
            };
            let new_peer_profiles_1 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[0].peer_addr.clone(),
                deposit: c.peer_profiles[0].deposit,
                withdrawal: c.peer_profiles[0].clone().withdrawal,
                state: new_state_1
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        }
    } else {
        let state_2 = c.peer_profiles[1].state.clone();
        out_amts = PayRegistry::<T>::get_pay_amounts(
            pay_id_list.pay_ids,
            state_2.last_pay_resolve_deadline
        )?;
        let mut total_amt_out: BalanceOf::<T> = Zero::zero();
        let out_amts_len = out_amts.len() - 1;
        for i in 0..out_amts_len {
            total_amt_out += out_amts[i];
            // TODO emit ClearOnePay event
        }
        let new_transfer_out_2 = state_2.transfer_out + total_amt_out;
        let hash_zero = zero_hash::<T>();
        if pay_id_list.next_list_hash == hash_zero {
            // if there are not more uncleared pays in this state, the pending_pay_out must be 0
            let new_state_2 = PeerStateOf::<T> {
                seq_num: state_2.seq_num,
                transfer_out: new_transfer_out_2,
                next_pay_id_list_hash: state_2.next_pay_id_list_hash,
                last_pay_resolve_deadline: state_2.last_pay_resolve_deadline,
                pending_pay_out: zero_balance
            };
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: c.peer_profiles[1].clone().withdrawal,
                state: new_state_2
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        } else {
            // Note: if there are more uncleared pays in this state, because resolved pay amount 
            //      is always less than or equal to the corresponding maximum amount counted in 
            //      pending_pay_out, the updated pending_pay_out may be equal to or larger than the real
            //      pending_pay_out. This will lead to decreasing the maximum withdraw amount (withdraw_limit)
            //      from potentially maliciout non-cooperative withdraw.
            let new_pending_pay_out = state_2.pending_pay_out - total_amt_out;
            let new_state_2 = PeerStateOf::<T> {
                seq_num: state_2.seq_num,
                transfer_out: new_transfer_out_2,
                next_pay_id_list_hash: state_2.next_pay_id_list_hash,
                last_pay_resolve_deadline: state_2.last_pay_resolve_deadline,
                pending_pay_out: new_pending_pay_out
            };
            let new_peer_profiles_2 = PeerProfileOf::<T> {
                peer_addr: c.peer_profiles[1].peer_addr.clone(),
                deposit: c.peer_profiles[1].deposit,
                withdrawal: c.peer_profiles[1].clone().withdrawal,
                state: new_state_2
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
                withdraw_intent: c.withdraw_intent
            };

            ChannelMap::<T>::mutate(&channel_id, |channel| *channel = Some(new_channel));
        }
    }

    Ok(())
}

/// Update overall states of a duplex channel
fn update_overall_states_by_intend_state<T: Trait>(
    channel_id: T::Hash
) -> Result<(), DispatchError> {
    let c = match ChannelMap::<T>::get(channel_id) {
        Some(channel) => channel,
        None => Err(Error::<T>::NotChannelPeer)?
    };

    let new_setttle_finalized_time: T::BlockNumber = c.settle_finalized_time.unwrap() + c.dispute_timeout;
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
    ChannelMap::<T>::mutate(channel_id, |channel| *channel = Some(new_channel));
    update_channel_status::<T>(channel_id, ChannelStatus::Settling)?;

    let seq_nums = get_state_seq_nums::<T>(channel_id);
    // TODO emit IntendSettle event
    Ok(())
}


/// Update status of a channel
fn update_channel_status<T: Trait>(
    channel_id: T::Hash,
    new_status: ChannelStatus
) -> Result<(), DispatchError> {
    let c = ChannelMap::<T>::get(channel_id).unwrap();

    if c.status == new_status {
        return Ok(());
    }

    // update counter of old status
    if c.status != ChannelStatus::Uninitialized {
        let status_nums;
        status_nums = match Module::<T>::channel_status_nums(c.status.clone() as u8) {
            Some(num) => num as u8,
            None => 0 as u8
        };
        let new_nums_1: u8 = status_nums - 1;
        ChannelStatusNums::mutate(c.status as u8, |num| *num = Some(new_nums_1));
    }

    let new_status_nums;
    new_status_nums = match Module::<T>::channel_status_nums(new_status.clone() as u8) {
        Some(num) => num as u8,
        None => 0 as u8
    };
    let new_nums_2 = new_status_nums + 1;
    ChannelStatusNums::mutate(new_status as u8, |num| *num = Some(new_nums_2));

    Ok(())
}

/**
// Validate token info
fn validate_token_info<T: Trait>(
    token: TokenInfo<T::AccountId>
) -> TokenInfo<T::AccountId> {
    if token.token_type = TokenType::ETH {
        ensure!()
    }
}
*/

// Validate channel final balance
fn validate_settle_balance<T: Trait>(channel_id: T::Hash) -> (bool, Vec<BalanceOf<T>>) {
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    let state_1 = c.peer_profiles[0].clone().state;
    let state_2 = c.peer_profiles[1].clone().state;
    let mut settle_balance: Vec<BalanceOf<T>> = vec![
        c.peer_profiles[0].deposit + state_2.transfer_out,
        c.peer_profiles[1].deposit + state_1.transfer_out
    ];

    let zero_balance: BalanceOf<T> = Zero::zero();
    
    let sub_amt_1 = state_1.transfer_out + c.peer_profiles[0].clone().withdrawal.unwrap();
    if settle_balance[0] < sub_amt_1 {
        return (false, vec![zero_balance, zero_balance]);
    }
    settle_balance[0] = settle_balance[0] - sub_amt_1;

    let sub_amt_2 = state_2.transfer_out + c.peer_profiles[1].clone().withdrawal.unwrap();
    if settle_balance[1] < sub_amt_2 {
        return (false, vec![zero_balance, zero_balance]);
    }
    settle_balance[1] = settle_balance[1] - sub_amt_2;

    return (true, vec![settle_balance[0], settle_balance[1]]);
}


/// Get the seqNums of two simplex channel states
fn get_state_seq_nums<T: Trait>(channel_id: T::Hash) -> Vec<u128> {
    let c = ChannelMap::<T>::get(channel_id).unwrap();
    let state_1 = c.peer_profiles[0].clone().state;
    let state_2 = c.peer_profiles[1].clone().state;
    return vec![state_1.seq_num, state_2.seq_num];
}

/// Celer Wallet
/// function which modifier is onlyOperator
fn withdraw<T: Trait>(
    wallet_id: T::Hash,
    receiver: T::AccountId,
    amount: BalanceOf<T>
) -> Result<(), DispatchError> {
    update_balance::<T>(receiver, wallet_id, MathOperation::Sub, amount)?;
    Ok(())
    // TODO emit WidrawFromWallet Event
}

fn is_wallet_owner<T: Trait>(
    wallet_id: T::Hash, 
    addr: T::AccountId,
) -> bool {
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
    amount: BalanceOf<T>
) -> Result<(), DispatchError> {
    let w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
        Some(_w) => _w,
        None => Err(Error::<T>::WalletNotExist)?
    };

    let wallet_account = celer_wallet_account::<T>();

    let mut new_amount: BalanceOf<T> = Zero::zero();
    if op == MathOperation::Sub {
        ensure!(
            w.balance >= amount,
            "balance of amount is not deposited"
        );
        new_amount = w.balance - amount;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_amount,
        };

        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));
    
        T::Currency::transfer(&wallet_account, &caller, amount, ExistenceRequirement::AllowDeath)?;
    } else if op == MathOperation::Add {
        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances."
        );
        new_amount = w.balance + amount;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_amount,
        };

        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));
       
        T::Currency::transfer(&caller, &wallet_account, amount, ExistenceRequirement::AllowDeath)?;
    } else {
        Err(Error::<T>::Error)?
    }

    Ok(())
}

// Internal function to withdraw out one type of token
fn withdraw_token<T: Trait>(
    receiver: T::AccountId,
    amount: BalanceOf<T>
) -> Result<(), DispatchError> {
    let wallet_account = celer_wallet_account::<T>();
    T::Currency::transfer(&wallet_account, &receiver, amount, ExistenceRequirement::AllowDeath)?;
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
    amount: BalanceOf<T>
) -> Result<(), DispatchError> {
    ensure!(
        is_wallet_owner::<T>(from_wallet_id, receiver.clone())
        && is_wallet_owner::<T>(to_wallet_id, receiver),
        "receiver is not wallet owner"
    );
    
    let from_wallet = match Wallets::<T>::get(from_wallet_id) {
        Some(w) => w,
        None => Err(Error::<T>::WalletNotExist)?
    };
    let to_wallet = match Wallets::<T>::get(to_wallet_id) {
        Some(w) => w,
        None => Err(Error::<T>::WalletNotExist)?
    };

    let from_wallet_amount = from_wallet.balance - amount;
    let to_wallet_amount = to_wallet.balance + amount;

    Wallets::<T>::mutate(&from_wallet_id, |wallet| *wallet = Some(from_wallet));
    Wallets::<T>::mutate(&to_wallet_id, |wallet| *wallet = Some(to_wallet));

    Ok(())
}

pub fn zero_hash<T: Trait>() -> T::Hash {
    let zero_vec = vec![0 as u8];
    let zero_hash = T::Hashing::hash(&zero_vec);
    return zero_hash;
}

#[cfg(test)]
pub mod tests {
    use crate::mock::{self, *};
    use super::*;
    use frame_support::{assert_ok, assert_noop};
    use sp_runtime::DispatchError;
    use sp_core::{H256, hashing, sr25519, Pair};
    
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
            let (channel_peers, peers_pair)
                 = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(false, 0, 0, 20, true, channel_peers.clone(), 0, peers_pair);
            let err = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[0]), open_channel_request, 0).unwrap_err();
            assert_eq!(err, DispatchError::Other("Open deadline passed"));
        })
    }

    #[test]
    fn test_fail_open_channel_with_deposits_with_deposits_before() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            approve(channel_peers[1], ledger_addr, 200);

            let open_channel_request 
                = get_open_channel_request(true, 100, 5000000, 10, false, channel_peers.clone(), 1, peers_pair);
            let err = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request, 200).unwrap_err();
            assert_eq!(err, DispatchError::Other("Balance exceeds limit"));
        })
    }

    #[test]
    fn test_pass_open_channel_when_total_deposit_is_zero() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            let cal_channel_id = calculate_channel_id(channel_peers, open_channel_request);
            assert_eq!(channel_id, cal_channel_id);
        })
    }

    #[test]
    fn test_fail_open_channel_again_with_the_same_channel_id() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let _ = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            // Again open channel with same channel id
            let err = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap_err();
            assert_eq!(err, DispatchError::Other("Occupied wallet id"));
        })
    }

    #[test]
    fn test_fail_cooperative_withdraw_because_of_no_deposit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // Open channel zero deposit.
            let open_channel_request 
                = get_open_channel_request(false, 0, 500000, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 1, 100, channel_peers[1], 10, zero_channel_id, peers_pair);
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("balance of amount is not deposited"));
        })
    }

    #[test]
    fn test_pass_open_another_channel() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request_1 
                = get_open_channel_request(false, 0, 500000, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id_1 = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request_1.clone(), 0).unwrap();
            let cal_channel_id_1 = calculate_channel_id(channel_peers.clone(), open_channel_request_1);
            assert_eq!(channel_id_1, cal_channel_id_1);

            // Open channel with another channel id
            let open_channel_request_2 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id_2 = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request_2.clone(), 0).unwrap();
            let cal_channel_id_2 = calculate_channel_id(channel_peers.clone(), open_channel_request_2);
            assert_eq!(channel_id_2, cal_channel_id_2);
        })
    }

    #[test]
    fn test_failt_deposit_before_setting_deposit_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request
                = get_open_channel_request(false, 0, 50000, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request, 0).unwrap();
            assert_ok!(
                CelerModule::enable_balance_limits(Origin::signed(channel_peers[0]), channel_id)
            );

            assert_noop!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 100, 0),
                Error::<TestRuntime>::BalanceLimitsNotExist
            );
            
        })
    }

    #[test]
    fn test_fail_set_deposit_limits_if_not_owner() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request 
                = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request 
                = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                CelerModule::set_balance_limits(Origin::signed(channel_peers[0]), channel_id, 300)
            );
            let amount = CelerModule::get_balance_limit(channel_id).unwrap();
            assert_eq!(amount, 300);
        })
    }

    #[test]
    fn test_pass_open_channel_with_funds_correctly_after_setting_deposit_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            // deposit celer to pool by channel_peers[1]
            let _ = EthPool::<TestRuntime>::deposit_pool(Origin::signed(channel_peers[1]),  channel_peers[1], 200).unwrap();
            // approve ledger to spend
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            approve(channel_peers[1], ledger_addr, 200);
            let open_channel_request 
                = get_open_channel_request(true, 10000, 500000, 10, false, channel_peers.clone(), 0, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[0]), open_channel_request.clone(), 100).unwrap();
            
            let cal_channel_id = calculate_channel_id(channel_peers, open_channel_request);
            assert_eq!(channel_id, cal_channel_id);
        })
    }

    #[test]
    fn test_pass_deposit_coorectly_with_caller_amount() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)
            );
        })
    }

    #[test]
    fn test_fail_deposit_when_new_deposit_sum_exceeds_the_deposit_limit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            let err_1 = LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 1000, 0).unwrap_err();
            assert_eq!(err_1, DispatchError::Other("Balance exceeds limit"));

            let err_2 = LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[1]), channel_id, channel_peers[1], 100, 0).unwrap_err();
            assert_eq!(err_2, DispatchError::Other("Balance exceeds limit"));
        })
    }

    #[test]
    fn test_fail_disable_balance_limits_by_not_owner() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();

            let risa = account_key("Risa");
            let err = CelerModule::disable_balance_limits(Origin::signed(risa), channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller is not channel peer"));
        })
    }

    #[test]
    fn test_pass_disable_balance_limits() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                CelerModule::disable_balance_limits(Origin::signed(channel_peers[0]), channel_id)
            );
        })
    }

    #[test]
    fn test_pass_deposit_after_removing_deposit_limits() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 10, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            let _ = CelerModule::disable_balance_limits(Origin::signed(channel_peers[0]), channel_id).unwrap();

            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)
            );
        })
    }

    #[test]
    fn test_fail_enable_balance_limits_by_not_owner() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            // enable balance limit and set balance limit
            let _ = CelerModule::enable_balance_limits(Origin::signed(channel_peers[0]), channel_id).unwrap();
            let _ = CelerModule::set_balance_limits(Origin::signed(channel_peers[0]), channel_id, 10).unwrap();

            let err = LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 100, 0).unwrap_err();
            assert_eq!(err, DispatchError::Other("Balance exceeds limit"));
        })
    }

    #[test]
    fn test_pass_deposit_via_pool() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(true, 400, 500000, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            // deposit celer to pool by channel_peers[0]
            let _ = EthPool::<TestRuntime>::deposit_pool(Origin::signed(channel_peers[0]), channel_peers[0], 200).unwrap();
            // approve ledger to spend
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            approve(channel_peers[0], ledger_addr, 200);

            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 0, 100)
            );
        })
    }

    #[test]
    fn test_pass_intend_withdraw_correctly() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let (_channel_id, _receiver, _amount)
                = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();

            let err = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Pending withdraw intent exists"));
        })
    }

    #[test]
    fn test_fail_confirm_withdraw_before_confirmable_time() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();

            let err = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap_err();
            assert_eq!(err, DispatchError::Other("Dispute not timeout"));
        })
    }

    #[test]
    fn test_pass_veto_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();

            assert_ok!(
                LedgerOperation::<TestRuntime>::veto_withdraw(Origin::signed(channel_peers[1]), channel_id)
            );
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();

            System::set_block_number(System::block_number() + 11);

            let (amount, receiver, recipient_channel_id) 
                = LedgerOperation::<TestRuntime>::confirm_withdraw(channel_id).unwrap();
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            let open_channel_request 
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 1, 200, channel_peers[0], 0, zero_channel_id, peers_pair);
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Withdraw deadline passed"));
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_receiver_has_enough_deposit() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 1, 200, channel_peers[0], 9999999, zero_channel_id, peers_pair);
            let (_channel_id, _amount, _receiver, _, _withdraw_info_seq_num)
                = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();
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
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
            );

            // smaller seq_num than expected one
            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();
            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 0, 200, channel_peers[0], 9999999, zero_channel_id, peers_pair.clone());
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("seq_num error"));

            // larger seq_num than expected one
            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 2, 200, channel_peers[0], 9999999, zero_channel_id, peers_pair.clone());
            let err = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("seq_num error"));

            // expected seq_num
            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 1, 200, channel_peers[0], 9999999, zero_channel_id, peers_pair.clone());
            let (_channel_id, _amount, _receiver, _, _withdraw_info_seq_num)
                = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();
            assert_eq!(_channel_id, channel_id);
            assert_eq!(_amount, 200);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_withdraw_info_seq_num, 1);
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_receiver_does_not_have_enough_deposit_but_the_whole_channel_does() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let zero_vec = vec![0 as u8];
            let zero_channel_id = hashing::blake2_256(&zero_vec).into();

            let open_channel_request 
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 160, 0)
            );
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[1]), channel_id, channel_peers[1], 40, 0)
            );

            let cooperative_withdraw_request 
                = get_cooperative_withdraw_request(channel_id, 1, 200, channel_peers[0], 9999999, zero_channel_id, peers_pair.clone());
            let (_channel_id, _withdrawn_amount, _receiver, _recipient_channel_id, _withdraw_info_seq_num)
                = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();

            let balance_amt = CelerModule::get_total_balance(channel_id);
            let (_channel_peer, _deposits, _withdrawals): (Vec<AccountId>, Vec<Balance>, Vec<Balance>)
                = CelerModule::get_balance_map(channel_id);
             
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
            let (channel_peers_1, peers_pair_1)
                = get_sorted_peer(alice_pair.clone(), risa_pair.clone());
            let (channel_peers_2, peers_pair_2)
                = get_sorted_peer(bob_pair.clone(), risa_pair.clone());

            let open_channel_request_1
                = get_open_channel_request(true, 800, 500001, 10, true, channel_peers_1.clone(), 1, peers_pair_1.clone());
            let channel_id_1
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers_1[1]), open_channel_request_1.clone(), 0).unwrap();
            let open_channel_request_2 
                = get_open_channel_request(true, 800, 500000, 10, true, channel_peers_2.clone(), 1, peers_pair_2.clone());
            let channel_id_2    
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers_2[1]), open_channel_request_2.clone(), 0).unwrap();
            
            assert_ok!(
                LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers_1[0]), channel_id_1, channel_peers_1[0], 200, 0)
            );

            let cooperative_withdraw_request
                = get_cooperative_withdraw_request(channel_id_1, 1, 200, channel_peers_1[0], 9999999, channel_id_2, peers_pair_1.clone());
            let (_channel_id, _withdrawn_amount, _receiver, _recipient_channel_id, _withdraw_info_seq_num)
                = LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();

            let _balance_amt_1 = CelerModule::get_total_balance(channel_id_1);
            let (_channel_peer_1, _deposits_1, _withdrawals_1): (Vec<AccountId>, Vec<Balance>, Vec<Balance>)
                = CelerModule::get_balance_map(channel_id_1);
            let _balance_amt_2 = CelerModule::get_total_balance(channel_id_2);
            let (_channel_peer_2, _deposits_2, _withdrawals_2): (Vec<AccountId>, Vec<Balance>, Vec<Balance>)
                = CelerModule::get_balance_map(channel_id_2);

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

    pub fn get_sorted_peer(
        peer_1: sr25519::Pair,
        peer_2: sr25519::Pair
    ) -> (Vec<AccountId>, Vec<sr25519::Pair>) {
        if peer_1.public() < peer_2.public() {
            return (
                vec![peer_1.clone().public(), peer_2.clone().public()],
                vec![peer_1, peer_2]
            );
        } else {
            return (
                vec![peer_2.clone().public(), peer_1.clone().public()],
                vec![peer_2, peer_1]
            );
        }
    }

    pub fn calculate_channel_id(
        peers: Vec<AccountId>,
        open_channel_request: OpenChannelRequest<AccountId, BlockNumber, Balance, Signature>
    ) -> H256 {
        let channel_initializer = open_channel_request.channel_initializer;
        let mut encoded_1 = channel_initializer.balance_limits_enabled.encode();
        encoded_1.extend(channel_initializer.balance_limits.encode());
        encoded_1.extend(channel_initializer.init_distribution.token.token_type.encode());
        encoded_1.extend(channel_initializer.init_distribution.distribution[0].account.encode());
        encoded_1.extend(channel_initializer.init_distribution.distribution[0].amt.encode());
        encoded_1.extend(channel_initializer.init_distribution.distribution[1].account.encode());
        encoded_1.extend(channel_initializer.init_distribution.distribution[1].amt.encode());
        encoded_1.extend(channel_initializer.open_deadline.encode());
        encoded_1.extend(channel_initializer.dispute_timeout.encode());
        encoded_1.extend(channel_initializer.msg_value_receiver.encode());
        let nonce: H256 = hashing::blake2_256(&encoded_1).into();
        let mut encoded_2 = peers[0].encode();
        encoded_2.extend(peers[1].encode());
        encoded_2.extend(nonce.encode());
        let channel_id: H256 = hashing::blake2_256(&encoded_2).into();
        return channel_id;
    }

    pub fn get_open_channel_request(
        balance_limits_enabled: bool,
        balance_limits: Balance,
        open_deadline: BlockNumber,
        dispute_timeout: BlockNumber, 
        zero_total_deposit: bool,
        channel_peers: Vec<AccountId>,
        msg_value_receiver: u8,
        peers_sr25519_pairs: Vec<sr25519::Pair>  
    ) -> OpenChannelRequest<AccountId, BlockNumber, Balance, Signature> {
        let channel_initializer 
            = get_payment_channel_initializer(balance_limits_enabled, balance_limits, open_deadline, dispute_timeout, zero_total_deposit, channel_peers.clone(), msg_value_receiver);
        
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
            sigs: vec![sigs_1, sigs_2]
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
        msg_value_receiver: u8
    ) -> PaymentChannelInitializer<AccountId, BlockNumber, Balance> {
        let account_amt_pair_1: AccountAmtPair<AccountId, Balance>;
        let account_amt_pair_2: AccountAmtPair<AccountId, Balance>;
        let token_distribution: TokenDistribution<AccountId, Balance>;
        let token_info = TokenInfo {
            token_type: TokenType::CELER
        };

        if zero_total_deposit == true {
            account_amt_pair_1 = AccountAmtPair {
                account: channel_peers[0],
                amt: 0
            };
            account_amt_pair_2 = AccountAmtPair {
                account: channel_peers[1],
                amt: 0
            };

            token_distribution = TokenDistribution {
                token: token_info,
                distribution: vec![account_amt_pair_1, account_amt_pair_2]
            };
        } else {
            account_amt_pair_1 = AccountAmtPair {
                account: channel_peers[0],
                amt: 100
            };
            account_amt_pair_2 = AccountAmtPair {
                account: channel_peers[1],
                amt: 200
            };

            token_distribution = TokenDistribution {
                token: token_info,
                distribution: vec![account_amt_pair_1, account_amt_pair_2],
            };
        }

        let initializer: PaymentChannelInitializer<AccountId, BlockNumber, Balance>;

        if balance_limits_enabled  == true {
            initializer = PaymentChannelInitializer {
                balance_limits_enabled: true,
                balance_limits: Some(balance_limits),
                init_distribution: token_distribution,
                open_deadline: open_deadline,
                dispute_timeout: dispute_timeout,
                msg_value_receiver: msg_value_receiver
            };
        } else {
            initializer = PaymentChannelInitializer {
                balance_limits_enabled: false,
                balance_limits: None,
                init_distribution: token_distribution,
                open_deadline: open_deadline,
                dispute_timeout: dispute_timeout,
                msg_value_receiver:  msg_value_receiver
            };
        }

        return initializer;
    }

    fn get_cooperative_withdraw_request(
        channel_id: H256,
        seq_num: u128,
        amount: Balance,
        receiver_account: AccountId,
        withdraw_deadline: BlockNumber,
        recipient_channel_id: H256,
        channel_pairs: Vec<sr25519::Pair>
    ) -> CooperativeWithdrawRequest<H256, BlockNumber, AccountId, Balance, Signature> {
        let account_amt_pair = AccountAmtPair {
            account: receiver_account.clone(),
            amt: amount
        };
        let cooperative_withdraw_info = CooperativeWithdrawInfo {
            channel_id: channel_id,
            seq_num: seq_num,
            withdraw: account_amt_pair,
            withdraw_deadline: withdraw_deadline,
            recipient_channel_id: recipient_channel_id
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
            sigs: vec![sig_1, sig_2]
        };
        
        return cooperative_withdraw_request;
    }

    fn approve(owner: AccountId, spender: AccountId, value: Balance) {
        let _ = EthPool::<TestRuntime>::approve(Origin::signed(owner), spender, value).unwrap();
    }

    fn veto_withdraw() -> H256 {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (channel_peers, peers_pair)
            = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
        let open_channel_request 
            = get_open_channel_request(true, 300, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
        let channel_id 
            = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
        assert_ok!(
            LedgerOperation::<TestRuntime>::deposit(Origin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)
        );

        let zero_vec = vec![0 as u8];
        let zero_channel_id = hashing::blake2_256(&zero_vec).into();
        let _ = LedgerOperation::<TestRuntime>::intend_withdraw(Origin::signed(channel_peers[0]), channel_id, 200, zero_channel_id).unwrap();

        assert_ok!(
            LedgerOperation::<TestRuntime>::veto_withdraw(Origin::signed(channel_peers[1]), channel_id)
        );

        return channel_id;
    }

}
