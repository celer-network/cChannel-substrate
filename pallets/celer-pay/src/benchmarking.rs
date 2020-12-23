#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_system::{RawOrigin, Module as System};
use frame_benchmarking::{benchmarks, account};
use crate::Module as CelerModule;
use sp_std::vec::Vec;
use crate::ledger_operation::*;
use crate::pay_resolver::*;
use sp_runtime::traits::{Bounded, Saturating};
use mock_numeric_condition::{NumericArgsQueryFinalization, NumericArgsQueryOutcome};
use mock_boolean_condition::{BooleanArgsQueryFinalization, BooleanArgsQueryOutcome};
use crate::pay_registry::PayRegistry;

const SEED: u32 = 2;

fn activate_celer_pay_module<T: Trait>() {
    let pool_account = CelerModule::<T>::get_pool_id();
    let celer_wallet_account = CelerModule::<T>::get_celer_wallet_id();
    let value = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(1_000_000_000.into());
    <T as traits::Trait>::Currency::make_free_balance_be(&pool_account, value);
    <T as traits::Trait>::Currency::make_free_balance_be(&celer_wallet_account, value);
}

fn get_sorted_peer<T: Trait>(
    peers: Vec<T::AccountId>
 ) -> Vec<T::AccountId> {
    <T as traits::Trait>::Currency::make_free_balance_be(&peers[0], BalanceOf::<T>::max_value().saturating_sub(<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1000.into())));
    <T as traits::Trait>::Currency::make_free_balance_be(&peers[1], BalanceOf::<T>::max_value().saturating_sub(<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1000.into())));
    if peers[0] < peers[1] {
        return vec![peers[0].clone(), peers[1].clone()];
    } else {
        return vec![peers[1].clone(), peers[0].clone()];
    }
}

fn get_one_hash<T: Trait>() -> T::Hash {
    let one_vec = vec![1 as u8];
    let one_hash = T::Hashing::hash(&one_vec);
    return one_hash;
}

fn get_open_channel_request<T: Trait>(
    balance_limits_enabled: bool,
    balance_limits: BalanceOf<T>,
    open_deadline: T::BlockNumber,
    dispute_timeout: T::BlockNumber,
    zero_total_deposit: bool,
    channel_peers: Vec<T::AccountId>,
    msg_value_receiver: u8,
) -> OpenChannelRequest<T::AccountId, T::BlockNumber, BalanceOf<T>> {
    let channel_initializer = get_payment_channel_initializer::<T>(
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
    
    let open_channel_request = OpenChannelRequestOf::<T> {
        channel_initializer: channel_initializer,
    };

    return open_channel_request;
}
    
fn get_payment_channel_initializer<T: Trait>(
    balance_limits_enabled: bool,
    balance_limits: BalanceOf<T>,
    open_deadline: T::BlockNumber,
    dispute_timeout: T::BlockNumber,
    zero_total_deposit: bool,
    channel_peers: Vec<T::AccountId>,
    msg_value_receiver: u8,
) -> PaymentChannelInitializer<T::AccountId, T::BlockNumber, BalanceOf<T>> {
    let account_amt_pair_1: AccountAmtPair<T::AccountId, BalanceOf<T>>;
    let account_amt_pair_2: AccountAmtPair<T::AccountId, BalanceOf<T>>;
    let token_distribution: TokenDistribution<T::AccountId, BalanceOf<T>>;
    let token_info = TokenInfo {
        token_type: TokenType::Celer,
    };

    if zero_total_deposit == true {
        account_amt_pair_1 = AccountAmtPairOf::<T> {
            account: Some(channel_peers[0].clone()),
            amt: 0.into(),
        };
        account_amt_pair_2 = AccountAmtPairOf::<T> {
            account: Some(channel_peers[1].clone()),
            amt: 0.into(),
        };

        token_distribution = TokenDistributionOf::<T> {
            token: token_info,
            distribution: vec![account_amt_pair_1, account_amt_pair_2],
        };
    } else {
        account_amt_pair_1 = AccountAmtPairOf::<T> {
            account: Some(channel_peers[0].clone()),
            amt: <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()),
            };
        account_amt_pair_2 = AccountAmtPairOf::<T> {
            account: Some(channel_peers[1].clone()),
            amt:<T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()),
        };

        token_distribution = TokenDistributionOf::<T> {
            token: token_info,
            distribution: vec![account_amt_pair_1, account_amt_pair_2],
        };
    }

    let initializer: PaymentChannelInitializerOf::<T>;

    if balance_limits_enabled == true {
        initializer = PaymentChannelInitializerOf::<T> {
            balance_limits_enabled: true,
            balance_limits: Some(balance_limits),
            init_distribution: token_distribution,
            open_deadline: open_deadline,
            dispute_timeout: dispute_timeout,
            msg_value_receiver: msg_value_receiver,
        };
    } else {
        initializer = PaymentChannelInitializerOf::<T> {
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

fn get_cooperative_withdraw_request<T:Trait>(
    channel_id: T::Hash,
    seq_num: u128,
    amount: BalanceOf<T>,
    receiver_account: T::AccountId,
    withdraw_deadline: T::BlockNumber,
    recipient_channel_id: T::Hash,
) -> CooperativeWithdrawRequest<T::Hash, T::BlockNumber, T::AccountId, BalanceOf<T>> {
    let account_amt_pair = AccountAmtPairOf::<T> {
        account: Some(receiver_account.clone()),
        amt: amount,
    };
    let cooperative_withdraw_info = CooperativeWithdrawInfoOf::<T> {
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

    let cooperative_withdraw_request = CooperativeWithdrawRequestOf::<T> {
        withdraw_info: cooperative_withdraw_info,
    };

    return cooperative_withdraw_request;
}

pub fn get_cosigned_intend_settle<T: Trait>(
    channel_ids: Vec<T::Hash>,
    pay_amounts_array: Vec<Vec<Vec<BalanceOf<T>>>>,
    seq_nums: Vec<u128>,
    transfer_amounts: Vec<BalanceOf<T>>,
    last_pay_resolve_deadlines: Vec<T::BlockNumber>,
    peer_froms: Vec<T::AccountId>,
    receiver_account: T::AccountId,
    conditions: u8,
) -> (
    SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>>,
    Vec<T::BlockNumber>,
    Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
    Vec<Vec<T::Hash>>,
    Vec<Vec<PayIdList<T::Hash>>>,
 ) {
    // Initial value pf cond_pay
    let init_conditions = get_condition::<T>(1);
    let init_transfer_func = get_transfer_func_2::<T>(10.into());
    let init_cond_pay = ConditionalPayOf::<T> {
        pay_timestamp: 0.into(),
        src: account("src", 0, SEED),
        dest: account("dest", 0, SEED),
        conditions: vec![init_conditions],
        transfer_func: init_transfer_func,
        resolve_deadline: 0.into(),
        resolve_timeout: 0.into(),
    };
    let mut cond_pays: Vec<
    Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber,  T::AccountId, T::Hash, BalanceOf<T>>>>,
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

    let mut pay_id_list_hash_array: Vec<Vec<T::Hash>> = vec![vec![]];
    let mut total_pending_amounts: Vec<BalanceOf<T>> = vec![];

    let channel_id_len = channel_ids.len();
    let mut pay_info: (
        Vec<PayIdList<T::Hash>>,
        Vec<T::Hash>,
        Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber,  T::AccountId, T::Hash, BalanceOf<T>>>>,
        BalanceOf<T>,
        Vec<PayIdList<T::Hash>>,
    );

    let zero_hash = CelerModule::<T>::get_zero_hash();
    // Initial value of pay id list
    let init_pay_id_list = PayIdList::<T::Hash> {
        pay_ids: vec![zero_hash],
        next_list_hash: None,
    };
    let mut head_pay_id_lists: Vec<PayIdList<T::Hash>> =
        vec![init_pay_id_list.clone(), init_pay_id_list.clone()];
    let mut _pay_id_lists: Vec<PayIdList<T::Hash>> =
        vec![init_pay_id_list.clone(), init_pay_id_list.clone()];
    let mut _pay_id_list_hash_array: Vec<T::Hash> =
        vec![zero_hash.clone(), zero_hash];
    let mut _cond_pay_array: Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber,  T::AccountId, T::Hash, BalanceOf<T>>>> = vec![vec![]];
    let mut pay_id_list_array: Vec<Vec<PayIdList<T::Hash>>> = vec![
        vec![init_pay_id_list.clone(), init_pay_id_list.clone()],
        vec![init_pay_id_list.clone(), init_pay_id_list.clone()],
    ];
    for i in 0..channel_id_len {
        pay_info = get_pay_id_list_info::<T>(pay_amounts_array[i].clone(), conditions);
        _pay_id_lists[i] = pay_info.0[i].clone();
        _cond_pay_array = pay_info.2;

        head_pay_id_lists[i] = pay_info.0[0].clone();
        pay_id_list_hash_array.push(pay_info.1.clone());
        cond_pays[i] = _cond_pay_array;
        total_pending_amounts.push(pay_info.3);
        pay_id_list_array[i] = pay_info.4;
    }

    let init_signed_simplex_state = get_single_signed_simplex_state::<T>(
        channel_ids[0],
        receiver_account.clone(),
    );
    let mut signed_simplex_states: Vec<
        SignedSimplexState<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>>,
    > = vec![init_signed_simplex_state.clone(), init_signed_simplex_state];
    for i in 0..channel_id_len {
        if seq_nums[i] > 0 {
            // co-signed non-null state
            signed_simplex_states[i] = get_co_signed_simplex_state::<T>(
                channel_ids[i],
                peer_froms[i].clone(),
                seq_nums[i],
                transfer_amounts[i],
                head_pay_id_lists[i].clone(),
                last_pay_resolve_deadlines[i],
                total_pending_amounts[i],
        );
        } else if seq_nums[i] == 0 {
            //  single-signed null state
            signed_simplex_states[i] = get_single_signed_simplex_state::<T>(
                channel_ids[i],
                receiver_account.clone(),
            );
        }
    }
    let signed_simplex_state_array: SignedSimplexStateArray<
        T::Hash,
        T::AccountId,
        T::BlockNumber,
        BalanceOf<T>,
    >;
    signed_simplex_state_array = SignedSimplexStateArray::<
        T::Hash,
        T::AccountId,
        T::BlockNumber,
        BalanceOf<T>>
    {
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

fn get_pay_id_list_info<T: Trait>(
    pay_amounts: Vec<Vec<BalanceOf<T>>>,
    pay_conditions: u8,
) -> (
    Vec<PayIdList<T::Hash>>,
    Vec<T::Hash>,
    Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>,
    BalanceOf<T>,
    Vec<PayIdList<T::Hash>>,
) {
    let zero_hash = CelerModule::<T>::get_zero_hash();
    // Initial value of pay id list
    let init_pay_id_list = PayIdList::<T::Hash> {
        pay_ids: vec![zero_hash],
        next_list_hash: None,
    };
    // 1-d array PayIdList
    let mut pay_id_lists: Vec<PayIdList<T::Hash>> =
    vec![init_pay_id_list.clone(), init_pay_id_list.clone()];

    // 1-d array PayIdList, for clearing pays in Celer Ledger
    let mut pay_id_list_array: Vec<PayIdList<T::Hash>> =
    vec![init_pay_id_list.clone(), init_pay_id_list.clone()];

    let mut pay_id_list_hash_array: Vec<T::Hash> =
    vec![zero_hash, zero_hash];

    // Initial value pf cond_pay
    let init_conditions = get_condition::<T>(1);
    let init_transfer_func = get_transfer_func_2::<T>(1.into());
    let init_cond_pay = ConditionalPayOf::<T> {
        pay_timestamp: 0.into(),
        src: account("src", 0, SEED),
        dest: account("dest", 0, SEED),
        conditions: vec![init_conditions],
        transfer_func: init_transfer_func,
        resolve_deadline: 0.into(),
        resolve_timeout: 0.into(),
    };
    // 2-d array list of PayIdList of a simplex channel,
    // for resolving pays with PayRegistry
    // Index is consistent with PayAmounts.
    let mut cond_pay_array: Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber,  T::AccountId, T::Hash, BalanceOf<T>>>> 
    = vec![
        vec![init_cond_pay.clone(), init_cond_pay.clone()],
        vec![init_cond_pay.clone(), init_cond_pay.clone()],
    ];
    // total pending amount in payAmounts/this state
    let mut total_pending_amount: BalanceOf<T> = 0.into();

    let pay_amounts_len = pay_amounts.len();

    let mut i: usize = pay_amounts_len - 1;

    loop {
        let pay_amounts_len_2 = pay_amounts[i].len();
        let mut pay_ids: Vec<T::Hash> = vec![zero_hash, zero_hash];
        for j in 0..pay_amounts_len_2 {
            total_pending_amount += pay_amounts[i][j];
            let conditions: Condition<T::Hash>;
            if pay_conditions == 1 {
                conditions = get_condition::<T>(1);
            } else {
                conditions = get_condition::<T>(2);
            }

            let mut src = T::AccountId::default();
            let mut dest = T::AccountId::default();
            src = account("src", 0, SEED);
            dest = account("dest", 0, SEED);
            let transfer_func = get_transfer_func_2::<T>(pay_amounts[i][j]);
            cond_pay_array[i][j] = ConditionalPayOf::<T> {
                pay_timestamp: 0.into(),
                src: src,
                dest: dest,
                conditions: vec![conditions],
                transfer_func: transfer_func,
                resolve_deadline: 999999.into(),
                resolve_timeout: 5.into(),
            };
            let encoded_cond_pay = encode_conditional_pay::<T>(cond_pay_array[i][j].clone());
            let pay_hash = T::Hashing::hash(&encoded_cond_pay);
            pay_ids[j] = PayRegistry::<T>::calculate_pay_id(pay_hash);
        }

        if i == pay_amounts_len - 1 {
            pay_id_lists[i] = PayIdList::<T::Hash> {
                pay_ids: pay_ids,
                next_list_hash: None,
            };
        } else {
            let k = i + 1;
            pay_id_lists[i] = PayIdList::<T::Hash> {
                pay_ids: pay_ids,
                next_list_hash: Some(pay_id_list_hash_array[k]),
            };
        }
       
        let mut encoded: Vec<u8> = vec![];
        pay_id_lists[i].pay_ids.clone().into_iter().for_each(|pay_id| {
            encoded.extend(pay_id.encode());
        });
        encoded.extend(pay_id_lists[i].next_list_hash.encode());
        pay_id_list_hash_array[i] = T::Hashing::hash(&encoded);

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

fn get_signed_simplex_state_array<T: Trait>(
    channel_ids: Vec<T::Hash>,
    seq_nums: Vec<u128>,
    transfer_amounts: Vec<BalanceOf<T>>,
    last_pay_resolve_deadlines: Vec<T::BlockNumber>,
    pay_id_lists: Vec<PayIdList<T::Hash>>,
    peer_froms: Vec<T::AccountId>,
    total_pending_amounts: Vec<BalanceOf<T>>,
    receiver_account: T::AccountId,
) -> SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>> {
    let mut signed_simplex_states: Vec<
        SignedSimplexState<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>>,
    > = vec![];
    let channel_id_len = channel_ids.len();
    for i in 0..channel_id_len {
        if seq_nums[i] > 0 {
            // co-signed non-null state
            signed_simplex_states.push(get_co_signed_simplex_state::<T>(
                channel_ids[i],
                peer_froms[i].clone(),
                seq_nums[i],
                transfer_amounts[i],
                pay_id_lists[i].clone(),
                last_pay_resolve_deadlines[i],
                total_pending_amounts[i],
            ));
        } else if seq_nums[i] == 0 {
            // single-signed null state
            signed_simplex_states.push(get_single_signed_simplex_state::<T>(
                channel_ids[i],
                receiver_account.clone(),
            ));
        }
    }
    let signed_simplex_state_array: SignedSimplexStateArray<
        T::Hash,
        T::AccountId,
        T::BlockNumber,
        BalanceOf<T>,
    >;
    signed_simplex_state_array = SignedSimplexStateArray::<
        T::Hash,
        T::AccountId,
        T::BlockNumber,
        BalanceOf<T>,
    > {
        signed_simplex_states: signed_simplex_states,
    };

    return signed_simplex_state_array;
}

fn get_single_signed_simplex_state<T: Trait>(
    channel_id: T::Hash,
    signer: T::AccountId,
) -> SignedSimplexState<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>> {
    let simplex_payment_channel = SimplexPaymentChannelOf::<T> {
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

    let signed_simplex_state = SignedSimplexStateOf::<T> {
        simplex_state: simplex_payment_channel,
    };

    return signed_simplex_state;
}

fn get_co_signed_simplex_state<T: Trait>(
    channel_id: T::Hash,
    peer_from: T::AccountId,
    seq_num: u128,
    transfer_amount: BalanceOf<T>,
    pending_pay_ids: PayIdList<T::Hash>,
    last_pay_resolve_deadline: T::BlockNumber,
    total_pending_amount: BalanceOf<T>,
) -> SignedSimplexState<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>> {
    let account_amt_pair = AccountAmtPairOf::<T> {
        account: None,
        amt: transfer_amount,
    };

    let token_info = TokenInfo {
        token_type: TokenType::Celer,
    };

    let transfer_to_peer = TokenTransferOf::<T> {
        token: token_info,
        receiver: account_amt_pair,
    };

    let simplex_payment_channel = SimplexPaymentChannelOf::<T> {
        channel_id: channel_id,
        peer_from: Some(peer_from),
        seq_num: seq_num,
        transfer_to_peer: Some(transfer_to_peer),
        pending_pay_ids: Some(pending_pay_ids),
        last_pay_resolve_deadline: Some(last_pay_resolve_deadline),
        total_pending_amount: Some(total_pending_amount),
    };
    let mut encoded = simplex_payment_channel.channel_id.encode();
    encoded.extend(simplex_payment_channel.peer_from.encode());
    encoded.extend(simplex_payment_channel.seq_num.encode());
    encoded.extend(simplex_payment_channel.clone().transfer_to_peer.unwrap().token.token_type.encode());
    encoded.extend(simplex_payment_channel.clone().transfer_to_peer.unwrap().receiver.account.encode());
    encoded.extend(simplex_payment_channel.clone().transfer_to_peer.unwrap().receiver.amt.encode());
    simplex_payment_channel.clone().pending_pay_ids.unwrap().pay_ids.into_iter().for_each(|pay_id| {
        encoded.extend(pay_id.encode());
    });
    encoded.extend(simplex_payment_channel.clone().pending_pay_ids.unwrap().next_list_hash.encode());
    encoded.extend(simplex_payment_channel.last_pay_resolve_deadline.encode());
    encoded.extend(simplex_payment_channel.total_pending_amount.encode());
    
    let signed_simplex_state = SignedSimplexStateOf::<T> {
        simplex_state: simplex_payment_channel,
    };

    return signed_simplex_state;
}

fn get_cooperative_settle_request<T: Trait>(
    channel_id: T::Hash,
    seq_num: u128,
    channel_peers: Vec<T::AccountId>,
    settle_amounts: Vec<BalanceOf<T>>,
    settle_deadline: T::BlockNumber,
) -> CooperativeSettleRequest<T::Hash, T::BlockNumber, T::AccountId, BalanceOf<T>> {
    let account_amt_pair_1 = AccountAmtPairOf::<T> {
        account: Some(channel_peers[0].clone()),
        amt: settle_amounts[0],
    };
    let account_amt_pair_2 = AccountAmtPairOf::<T> {
        account: Some(channel_peers[1].clone()),
        amt: settle_amounts[1],
    };
    let settle_info = CooperativeSettleInfoOf::<T> {
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

    let cooperative_settle_request = CooperativeSettleRequestOf::<T> {
        settle_info: settle_info,
    };

    return cooperative_settle_request;
}

fn get_token_transfer<T: Trait>(
    account: T::AccountId,
    amount: BalanceOf<T>,
) -> TokenTransfer<T::AccountId, BalanceOf<T>> {
    let account_amt_pair = AccountAmtPairOf::<T> {
        account: Some(account),
        amt: amount,
    };

    let token_info = TokenInfo {
        token_type: TokenType::Celer,
    };

    let token_transfer = TokenTransferOf::<T> {
        token: token_info,
        receiver: account_amt_pair,
    };

    return token_transfer;
}

fn get_transfer_func_2<T: Trait>(amount: BalanceOf<T>) -> TransferFunction<T::AccountId, BalanceOf<T>> {
    let account_amt_pair = AccountAmtPairOf::<T> {
        account: None,
        amt: amount,
    };

    let token_info = TokenInfo {
        token_type: TokenType::Celer,
    };

    let token_transfer = TokenTransferOf::<T> {
        token: token_info,
        receiver: account_amt_pair,
    };

    let transfer_func = TransferFunctionOf::<T> {
        logic_type: TransferFunctionType::BooleanAnd,
        max_transfer: token_transfer,
    };

    return transfer_func;
}

pub fn calculate_channel_id<T: Trait>(
    open_request: OpenChannelRequest<T::AccountId, T::BlockNumber, BalanceOf<T>>,
    channel_peers: Vec<T::AccountId>
) -> T::Hash {
    let channel_initializer = open_request.channel_initializer;
    let encoded_1 = encode_channel_initializer::<T>(channel_initializer);
    let nonce = T::Hashing::hash(&encoded_1);
    let mut encoded_2 = channel_peers[0].clone().encode();
    encoded_2.extend(channel_peers[1].encode());
    encoded_2.extend(nonce.encode());
    let channel_id = T::Hashing::hash(&encoded_2);
    return channel_id;
}

fn encode_conditional_pay<T: Trait>(pay: ConditionalPayOf<T>) -> Vec<u8> {
    let mut encoded = pay.pay_timestamp.encode();
    encoded.extend(pay.src.encode());
    encoded.extend(pay.dest.encode());
    pay.conditions.into_iter().for_each(|condition| {
        encoded.extend(condition.condition_type.encode());
        if condition.condition_type == ConditionType::HashLock {
            encoded.extend(condition.hash_lock.encode());
            encoded.extend(condition.runtime_module_call_data.encode());
            encoded.extend(condition.smart_contract_call_data.encode());
        } else if condition.condition_type == ConditionType::RuntimeModule { 
            encoded.extend(condition.hash_lock.encode());
            encoded.extend(condition.runtime_module_call_data.clone().unwrap().registration_num.encode());
            encoded.extend(condition.runtime_module_call_data.clone().unwrap().args_query_finalization);
            encoded.extend(condition.runtime_module_call_data.clone().unwrap().args_query_outcome);
            encoded.extend(condition.smart_contract_call_data.encode());
        } else { // ConditionType::SmartContract
            encoded.extend(condition.hash_lock.encode());
            encoded.extend(condition.runtime_module_call_data.encode());
            encoded.extend(condition.smart_contract_call_data.as_ref().unwrap().virt_addr.encode());
            encoded.extend(condition.smart_contract_call_data.as_ref().unwrap().is_finalized_call_gas_limit.encode());
            encoded.extend(condition.smart_contract_call_data.clone().unwrap().is_finalized_call_input_data);
            encoded.extend(condition.smart_contract_call_data.as_ref().unwrap().get_outcome_call_gas_limit.encode());
            encoded.extend(condition.smart_contract_call_data.unwrap().get_outcome_call_input_data);
        }
    });
    encoded.extend(pay.transfer_func.logic_type.encode());
    encoded.extend(pay.transfer_func.max_transfer.token.token_type.encode());
    encoded.extend(pay.transfer_func.max_transfer.receiver.account.encode());
    encoded.extend(pay.transfer_func.max_transfer.receiver.amt.encode());
    encoded.extend(pay.resolve_deadline.encode());
    encoded.extend(pay.resolve_timeout.encode());

    encoded
}

pub fn get_condition<T: Trait>(r#type: u8) -> Condition<T::Hash> {
    let one_hash = get_one_hash::<T>();
    if r#type == 0 {
        let condition_hash_lock = Condition {
            condition_type: ConditionType::HashLock,
            hash_lock: Some(one_hash),                
            runtime_module_call_data: None,
            smart_contract_call_data: None,
        };
        return condition_hash_lock;
    } else if r#type == 1 {
        let boolean_args_query_finalization = BooleanArgsQueryFinalization {
            session_id: one_hash,
            query_data: 1,
        };
        let boolean_args_query_outcome = BooleanArgsQueryOutcome {
            session_id: one_hash,
            query_data: 1,
        };
        let boolean_runtime_module_call_data = RuntimeModuleCallData {
            registration_num: 1,
            args_query_finalization: boolean_args_query_finalization.encode(),
            args_query_outcome: boolean_args_query_outcome.encode(),
        };
        let boolean_condition_true = Condition {
            condition_type: ConditionType::RuntimeModule,
            hash_lock: None,
            runtime_module_call_data: Some(boolean_runtime_module_call_data),
            smart_contract_call_data: None,
        };
        return boolean_condition_true;
    } else if r#type == 2 {
        let boolean_args_query_finalization = BooleanArgsQueryFinalization {
            session_id: one_hash,
            query_data: 1,
        };
        let boolean_args_query_outcome = BooleanArgsQueryOutcome {
            session_id: one_hash,
            query_data: 0,
        };
        let boolean_runtime_module_call_data = RuntimeModuleCallData {
            registration_num: 1,
            args_query_finalization: boolean_args_query_finalization.encode(),
            args_query_outcome: boolean_args_query_outcome.encode(),
        };
        let boolean_condition_false = Condition {
            condition_type: ConditionType::RuntimeModule,
            hash_lock: None,
            runtime_module_call_data: Some(boolean_runtime_module_call_data),
            smart_contract_call_data: None,
        };
        return boolean_condition_false;
    } else if r#type == 3 {
        let numeric_args_query_finalization = NumericArgsQueryFinalization {
            session_id: one_hash,
            query_data: 1,
        };
        let numeric_args_query_outcome = NumericArgsQueryOutcome {
            session_id: one_hash,
            query_data: 10,
        };
        let numeric_runtime_module_call_data = RuntimeModuleCallData {
            registration_num: 0,
            args_query_finalization: numeric_args_query_finalization.encode(),
            args_query_outcome: numeric_args_query_outcome.encode(),
        };
        let numeric_condition_10 = Condition {
            condition_type: ConditionType::RuntimeModule,
            hash_lock: None,
            runtime_module_call_data: Some(numeric_runtime_module_call_data),
            smart_contract_call_data: None,
        };
        return numeric_condition_10;
    } else {
        let numeric_args_query_finalization = NumericArgsQueryFinalization {
            session_id: one_hash,
            query_data: 1,
        };
        let numeric_args_query_outcome = NumericArgsQueryOutcome {
            session_id: one_hash,
            query_data: 25,
        };
        let numeric_runtime_module_call_data = RuntimeModuleCallData {
            registration_num: 0,
            args_query_finalization: numeric_args_query_finalization.encode(),
            args_query_outcome: numeric_args_query_outcome.encode(),
        };
        let numeric_condition_25 = Condition {
            condition_type: ConditionType::RuntimeModule,
            hash_lock: None,
            runtime_module_call_data: Some(numeric_runtime_module_call_data),
            smart_contract_call_data: None,
        };
        return numeric_condition_25;
        }
    }

fn get_transfer_func<T: Trait>(
    account: T::AccountId,
    amount: BalanceOf<T>,
    r#type: u8,
) -> TransferFunction<T::AccountId, BalanceOf<T>> {   
    if r#type == 0 {
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };
        let account_amt_pair = AccountAmtPair {
            account: Some(r#account),
            amt: r#amount,
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
    } else if r#type == 1 {
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };
        let account_amt_pair = AccountAmtPair {
            account: Some(r#account),
            amt: r#amount,
        };
        let token_transfer = TokenTransfer {
            token: token_info,
            receiver: account_amt_pair,
        };
        let transfer_func = TransferFunction {
            logic_type: TransferFunctionType::BooleanOr,
            max_transfer: token_transfer,
        };
        return transfer_func;
    } else if r#type == 2 {
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };
        let account_amt_pair = AccountAmtPairOf::<T> {
            account: Some(account),
            amt: amount,
        };
        let token_transfer = TokenTransferOf::<T> {
            token: token_info,
            receiver: account_amt_pair,
        };
        let transfer_func = TransferFunctionOf::<T> {
            logic_type: TransferFunctionType::BooleanCircut,
            max_transfer: token_transfer,
        };
        return transfer_func;
    } else if r#type == 3 {
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };
        let account_amt_pair = AccountAmtPairOf::<T> {
            account: Some(account),
            amt: amount,
        };
        let token_transfer = TokenTransferOf::<T> {
            token: token_info,
            receiver: account_amt_pair,
        };
        let transfer_func = TransferFunctionOf::<T> {
            logic_type: TransferFunctionType::NumericAdd,
            max_transfer: token_transfer,
        };
        return transfer_func;
    } else if r#type == 4 {
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };
        let account_amt_pair = AccountAmtPairOf::<T> {
            account: Some(account),
            amt: amount,
        };
        let token_transfer = TokenTransferOf::<T> {
            token: token_info,
            receiver: account_amt_pair,
        };
        let transfer_func = TransferFunctionOf::<T> {
            logic_type: TransferFunctionType::NumericMax,
            max_transfer: token_transfer,
        };
        return transfer_func;
    } else {
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };
        let account_amt_pair = AccountAmtPairOf::<T> {
            account: Some(account),
            amt: amount,
        };
        let token_transfer = TokenTransferOf::<T> {
            token: token_info,
            receiver: account_amt_pair,
        };
        let transfer_func = TransferFunctionOf::<T> {
            logic_type: TransferFunctionType::NumericMin,
            max_transfer: token_transfer,
        };
        return transfer_func;
    }
}


benchmarks! {
    _{}

    open_channel {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let dispute_timeout = 11+i;
        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10001.into()).saturating_add(i.into()),
            50000.into(),
            dispute_timeout.into(),
            false,
            channel_peers.clone(),
            1
        );
    }: _(RawOrigin::Signed(channel_peers[0].clone()), open_channel_request, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))

    set_balance_limits {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer11", i, SEED);
        peer2 = account("peer22", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let dispute_timeout = 11+i;
        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10001.into()),
            50000.into(),
            dispute_timeout.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[1].clone()), channel_id, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))

    disable_balance_limits {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id)

    enable_balance_limits {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id)

    deposit {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id, channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), 0.into())

    snapshot_states {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());

        let pay_id_list_info = get_pay_id_list_info::<T>(vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(2.into())]], 3);
        let pay_id_list = pay_id_list_info.0[0].clone();
        let total_pending_amount = pay_id_list_info.3;
        let signed_simplex_state_array = get_signed_simplex_state_array::<T>(
            vec![channel_id],
            vec![5],
            vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into())],
            vec![99999.into()],
            vec![pay_id_list],
            vec![channel_peers[1].clone()],
            vec![total_pending_amount],
            channel_peers[1].clone(),
        );    
    }: _(RawOrigin::Signed(channel_peers[0].clone()), signed_simplex_state_array)

    intend_withdraw {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        activate_celer_pay_module::<T>();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
        let zero_channel_id = CelerModule::<T>::get_zero_hash();
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), zero_channel_id)

    confirm_withdraw {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        activate_celer_pay_module::<T>();
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
        let zero_channel_id = CelerModule::<T>::get_zero_hash();
        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_id, channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(300.into()), 0.into())?;
        CelerModule::<T>::intend_withdraw(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_id, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), zero_channel_id)?;
        System::<T>::set_block_number(System::<T>::block_number() + 11.into());
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id)

    veto_withdraw {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        activate_celer_pay_module::<T>();
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
        let zero_channel_id = CelerModule::<T>::get_zero_hash();
        CelerModule::<T>::intend_withdraw(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_id, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), zero_channel_id)?;
    }: _(RawOrigin::Signed(channel_peers[1].clone()), channel_id)

    cooperative_withdraw {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        activate_celer_pay_module::<T>();
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
        let zero_channel_id = CelerModule::<T>::get_zero_hash();
        let cooperative_withdraw_request = get_cooperative_withdraw_request::<T>(
            channel_id,
            1,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()),
            channel_peers[0].clone(),
            999999.into(),
            zero_channel_id
        );
    }: _(RawOrigin::Signed(channel_peers[0].clone()), cooperative_withdraw_request)

    intend_settle {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            false,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());

        // the meaning of the index: [peer index][pay hash list index][pay index]
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<BalanceOf<T>>>> =
            vec![vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(2.into()),], vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(3.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(4.into()),]], vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(5.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(6.into()),], vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(7.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(8.into())]]];
        
        let global_result: (
            SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>>,
            Vec<T::BlockNumber>,
            Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
            Vec<Vec<T::Hash>>,
            Vec<Vec<PayIdList<T::Hash>>>,
        ) = get_cosigned_intend_settle::<T>(
            vec![channel_id, channel_id],
            peers_pay_hash_lists_amts,
            vec![1, 1],   // seq_nums
            vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(10.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(20.into())], // transfer amounts
            vec![2.into(), 2.into()],   // last_pay_resolve_deadlines
            vec![channel_peers[0].clone(), channel_peers[1].clone()],
            channel_peers[0].clone(),
            1,
        );

        let signed_simplex_state_array = global_result.0;

        System::<T>::set_block_number(System::<T>::block_number() + 3.into());
    }: _(RawOrigin::Signed(channel_peers[0].clone()), signed_simplex_state_array)

    clear_pays {
        let i in 0 .. 1000;
        System::<T>::set_block_number(1.into());
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        
        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            true,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), 0.into())?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());

        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_id, channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), 0.into())?;
        
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<BalanceOf<T>>>> =
            vec![vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(2.into()),], vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(3.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(4.into()),]], vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(5.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(6.into()),], vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(7.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(8.into())]]];
        
        let global_result: (
            SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>>,
            Vec<T::BlockNumber>,
            Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
            Vec<Vec<T::Hash>>,
            Vec<Vec<PayIdList<T::Hash>>>,
        ) = get_cosigned_intend_settle::<T>(
            vec![channel_id, channel_id],
            peers_pay_hash_lists_amts,
            vec![1, 1],   // seq_nums
            vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(10.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(20.into())], // transfer amounts
            vec![99999.into(), 99999.into()],   // last_pay_resolve_deadlines
            vec![channel_peers[0].clone(), channel_peers[1].clone()],
            channel_peers[0].clone(),
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
                    CelerModule::<T>::resolve_payment_by_conditions(RawOrigin::Signed(channel_peers[0].clone()).into(), pay_request)?;
                }
            }
        }

        System::<T>::set_block_number(System::<T>::block_number() + 6.into());

        CelerModule::<T>::intend_settle(RawOrigin::Signed(channel_peers[0].clone()).into(), signed_simplex_state_array.clone())?;

        let settle_finalized_time = CelerModule::<T>::get_settle_finalized_time(channel_id.clone());
        System::<T>::set_block_number(settle_finalized_time);
    
        let pay_id_list_array = global_result.4;
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id, channel_peers[0].clone(), pay_id_list_array[0][1].clone())

    confirm_settle {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            true,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), 0.into())?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());

        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_id, channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()), 0.into())?;
        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[1].clone()).into(), channel_id, channel_peers[1].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), 0.into())?;

        // the meaning of the index: [peer index][pay hash list index][pay index]
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<BalanceOf<T>>>> =
            vec![vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(2.into()),], vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(3.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(4.into()),]], vec![vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(5.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(6.into()),], vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(7.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(8.into())]]];
        
        let global_result: (
            SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>>,
            Vec<T::BlockNumber>,
            Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
            Vec<Vec<T::Hash>>,
            Vec<Vec<PayIdList<T::Hash>>>,
        ) = get_cosigned_intend_settle::<T>(
            vec![channel_id, channel_id],
            peers_pay_hash_lists_amts,
            vec![1, 1],   // seq_nums
            vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(10.into()),<T as traits::Trait>::Currency::minimum_balance().saturating_mul(20.into())], // transfer amounts
            vec![2.into(), 2.into()],   // last_pay_resolve_deadlines
            vec![channel_peers[0].clone(), channel_peers[1].clone()],
            channel_peers[0].clone(),
            1,
        );

        let signed_simplex_state_array = global_result.0;

        System::<T>::set_block_number(System::<T>::block_number() + 3.into());

        // intend settle
        CelerModule::<T>::intend_settle(
            RawOrigin::Signed(channel_peers[0].clone()).into(),
            signed_simplex_state_array,
        )?;

        let settle_finalized_time = CelerModule::<T>::get_settle_finalized_time(channel_id.clone());
        System::<T>::set_block_number(System::<T>::block_number() + settle_finalized_time);
    }: _(RawOrigin::Signed(channel_peers[0].clone()), channel_id.clone())


    cooperative_settle {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        let channel_peers = get_sorted_peer::<T>(vec![peer1, peer2]);
        activate_celer_pay_module::<T>();
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(channel_peers[0].clone()).into(), celer_ledger_account, <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into()))?;

        let open_channel_request = get_open_channel_request::<T>(
            true,
            <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10000.into()),
            50000.into(),
            10.into(),
            true,
            channel_peers.clone(),
            1
        );
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0].clone()).into(), open_channel_request.clone(), 0.into())?; 
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());

        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0].clone()).into(), channel_id, channel_peers[0].clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()), 0.into())?;

        let cooperative_settle_request = get_cooperative_settle_request::<T>(
            channel_id,
            2,
            channel_peers.clone(),
            vec![<T as traits::Trait>::Currency::minimum_balance().saturating_mul(150.into()), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(50.into())],
            50000.into()
        );
    }: _(RawOrigin::Signed(channel_peers[0].clone()), cooperative_settle_request.clone())

    deposit_pool {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        activate_celer_pay_module::<T>();
        let deposit_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(1_000.into());
    }: _(RawOrigin::Signed(peer1.clone()), peer1.clone(), deposit_amount)
    
    withdraw_from_pool {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        activate_celer_pay_module::<T>();
        let deposit_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(1_000.into());
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(peer1.clone()).into(), peer1.clone(), deposit_amount)?;
        let withdraw_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into());
    }: _(RawOrigin::Signed(peer1.clone()), withdraw_amount)

    transfer_from {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut peer2 = T::AccountId::default();
        let mut peer3 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        peer2 = account("peer2", i, SEED);
        peer3 = account("peer3", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value().saturating_sub(<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1000.into())));
        <T as traits::Trait>::Currency::make_free_balance_be(&peer2, BalanceOf::<T>::max_value().saturating_sub(<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1000.into())));
        <T as traits::Trait>::Currency::make_free_balance_be(&peer3, BalanceOf::<T>::max_value().saturating_sub(<T as traits::Trait>::Currency::minimum_balance().saturating_mul(1000.into())));
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(peer2.clone()).into(), peer2.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into()))?;
        CelerModule::<T>::approve(RawOrigin::Signed(peer2.clone()).into(), peer3.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(150.into()))?;
    }: _(RawOrigin::Signed(peer3.clone()), peer2.clone(), peer1.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(150.into()))

    approve {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        let celer_ledger_account = CelerModule::<T>::get_celer_ledger_id();
        let approve_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(100.into());
    }: _(RawOrigin::Signed(peer1.clone()), celer_ledger_account.clone(), approve_amount)

    increase_allowance {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut spender = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        spender = account("spender", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&spender, BalanceOf::<T>::max_value());
        let approve_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into());
        CelerModule::<T>::approve(RawOrigin::Signed(peer1.clone()).into(), spender.clone(), approve_amount)?;
        let increase_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into());
    }: _(RawOrigin::Signed(peer1.clone()), spender.clone(), increase_amount)

    decrease_allowance {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        let mut spender = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        spender = account("spender", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        <T as traits::Trait>::Currency::make_free_balance_be(&spender, BalanceOf::<T>::max_value());
        let approve_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(200.into());
        CelerModule::<T>::approve(RawOrigin::Signed(peer1.clone()).into(), spender.clone(), approve_amount)?;
        let decrease_amount = <T as traits::Trait>::Currency::minimum_balance().saturating_mul(50.into());
    }: _(RawOrigin::Signed(peer1.clone()), spender.clone(), decrease_amount)

    resolve_payment_by_conditions {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        
        let transfer_func = get_transfer_func::<T>(peer1.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10.into()), 0);
        let cond_pay = ConditionalPayOf::<T> {
            pay_timestamp: 0.into(),
            src: account("src", i, SEED),
            dest: account("dest", i , SEED),
            conditions: vec![get_condition::<T>(0), get_condition::<T>(1), get_condition::<T>(1)],
            transfer_func: transfer_func,
            resolve_deadline: 99999.into(),
            resolve_timeout: 10.into()
        };
        let one_hash = get_one_hash::<T>();
        let pay_request = ResolvePaymentConditionsRequestOf::<T> {
            cond_pay: cond_pay.clone(),
            hash_preimages: vec![one_hash]
        };
    }: _(RawOrigin::Signed(peer1.clone()), pay_request.clone())

    resolve_payment_by_vouched_result {
        let i in 0 .. 1000;
        let mut peer1 = T::AccountId::default();
        peer1 = account("peer1", i, SEED);
        <T as traits::Trait>::Currency::make_free_balance_be(&peer1, BalanceOf::<T>::max_value());
        
        let transfer_func = get_transfer_func::<T>(peer1.clone(), <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10.into()), 3);
        let shared_pay = ConditionalPayOf::<T> {
            pay_timestamp: 0.into(),
            src: account("src", i, SEED),
            dest: account("dest", i , SEED),
            conditions: vec![get_condition::<T>(0), get_condition::<T>(3), get_condition::<T>(4)],
            transfer_func: transfer_func,
            resolve_deadline: 99999.into(),
            resolve_timeout: 10.into()
        };
        let encoded_cond_pay = encode_conditional_pay::<T>(shared_pay.clone());
        let cond_pay_result = CondPayResultOf::<T> {
            cond_pay: shared_pay,
            amount: <T as traits::Trait>::Currency::minimum_balance().saturating_mul(10.into()),
        };
        let vouched_cond_pay_result = VouchedCondPayResultOf::<T> {
            cond_pay_result: cond_pay_result,
        };
    }: _(RawOrigin::Signed(peer1.clone()), vouched_cond_pay_result.clone())
}
