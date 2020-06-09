// ! Celer Pay palllet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_system::RawOrigin;
use sp_io::hashing::blake2_256;
use frame_benchmarking::benchmarks;
use sp_runtime::traits::Bounded;
use crate::ledger_operation::tests::*;
use crate::ledger_operation::{LedgerOperation, SignedSimplexStateArray};
use crate::mock::*;
use crate::pay_resolver::tests::*;
use crate::pay_resolver::{
    CondPayResult, ConditionalPay, PayResolver,
    ResolvePaymentConditionsRequest, VouchedCondPayResult,
};
use crate::pool::Pool;
use sp_core::{hashing, Pair, H256};

use crate::Module as CelerModule;

fn account<T: Trait>(name: &'static str, index: u32) -> T::AccountId {
	let entropy = (name, index).using_encoded(blake2_256);
	T::AccountId::decode(&mut &entropy[..]).unwrap_or_default()
}

fn set_approve<T: Trait>(r: u32) -> (
    Vec<T::AccountId>, Vec<sr25519::Pair>
) {
    let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", r))?;
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", 2*r+1))?;
    let (channel_peers, peers_pair) = get_sorted_peer(account::<T>("channel_peer", r), account::<T>("channel_peer", 2*r));
    Pool::<T>::deposit_pool(
        RawOrigin::signed(channel_peers[0]),
        channel_peers[0],
        500,
    );
    approve(channel_peers[0], ledger_addr, 500);

    return (channel_peers, peers_pair);
}

fn set_open_channel<T: Trait>(r: u32) -> (
    Vec<T::AccountId>, Vec<sr25519::Pair>, T::Hash
) {
    let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", r))?;
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", 2*r+1))?;
    let (channel_peers, peers_pair) = get_sorted_peer(account::<T>("channel_peer", r), account::<T>("channel_peer", 2*r));
    Pool::<T>::deposit_pool(
        Origin::signed(channel_peers[0]),
        channel_peers[0],
        100,
    );
    approve(channel_peers[0], ledger_addr, 100);

    let open_channel_request = get_open_channel_request(true, 1000, 50000, 10, false, channel_peers.clone(), 1, peers_pair.clone());
    CelerModule::open_channel(RawOrigin::signed(channel_peers[0]), open_channel_request, 200)?;
    let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
    return (channel_peers, peers_pair, channel_id);
}

benchmarks! {
    _ { }

    open_channel {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
    }: _(RawOrigin::Signed(channel_peers[0]), open_channel_request.clone(), 200)

    set_balance_limits {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerModule::open_channel(RawOrigin::signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::signed(channel_peers[0]), channel_id, 200)

    disable_balance_limits {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerModule::open_channel(RawOrigin::signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::signed(channel_peers[0]), channel_id)

    enable_balance_limits {
        let r in 0  .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request(false, 0, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerModule::open_channel(RawOrigin::signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::signed(channel_peers[0]), channel_id)

    deposit {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
    }: _(RawOrigin::signed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)

    snapshot_states {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);

        let pay_id_list_info = get_pay_id_list_info(vec![vec![1, 2]], 1);
        let pay_id_list = pay_id_list_info.0[0].clone();
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
    }: _(signed_simplex_state_array)

    intend_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
    }: _(RawOrigin::signed(channel_peers[0]), channel_id, 200, zero_channel_id)

    confirm_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)?;
        let zero_channel_id = CelerModule::<T>zero_hash();
        CelerModule::<T>::intend_withdraw(RawOrigin::signed(channel_peers[0]), channel_id, 200, zero_channel_id)?;
        System::<T>::set_block_number(System::block_number() + 11);
    }: _(RawOrigin::signed(channel_peers[0]), channel_id)

    veto_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
        CelerModule::<T>::intend_withdraw(RawOrigin::signed(channel_peers[0]), channel_id, 200, zero_channel_id)?;
    }: _(RawOrigin::signed(channel_peers[1]), channel_id)

    cooperative_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
        let cooperative_withdraw_request = get_cooperative_withdraw_request(
            channel_id,
            1,
            200,
            channel_peers[0],
            999999,
            zero_channel_id,
            peers_pair,
        );
    }: _(RawOrigin::signed(channel_peers[0]), cooperative_withdraw_request)

    intend_settle {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 200, 0)?;

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
            CelerModule::<T>::resolve_payment_by_conditions(pay_request)?;
        }

        // the head list of peer_from 1
        for i in 0..cond_pays[1][0].len() {
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pays[1][0][i].clone(),
                hash_preimages: vec![],
            };
            CelerModule::<T>::resolve_payment_by_conditions(pay_request)?;
        }

        // pass onchain  resolve deadline of all onchain resolved pays
        // but not pass the last pay resolved deadline
        System::<T>::set_block_number(System::<T>::block_number() + 6);
    }: _(RawOrigin::signed(channel_peers[0]), signed_simplex_state_array)

    clear_pays {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 200, 0)?;

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
                    CelerModule::<T>::resolve_payment_by_conditions(pay_request)?;
                }
            }
        }

        // pass onchain  resolve deadline of all onchain resolved pays
        System::<T>::set_block_number(System::<T>::block_number() + 6);

        // intend settle
        CelerModule::<T>::intend_settle(RawOrigin::signed(channel_peers[0]), signed_simplex_state_array)?;

        let pay_id_list_array = global_result.4;
    }: _(RawOrigin::signed(channel_peers[0]), channel_id, channel_peers[0], pay_id_list_array[0][1].clone())

    confirm_settle {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)?;
        CelerModule::<T>::deposit(RawOrigin::signed(channel_peers[1]), channel_id, channel_peers[1], 300, 0)?;

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
                    CelerModule::<T>::resolve_payment_by_conditions(pay_request).unwrap()?;
                }
            }
        }

        // pass onchain resolve deadline of all onchan resolve pays
        System::set_block_number(System::block_number() + 6);

        // intend settle
        CelerModule::<T>::intend_settle(RawOrigin::signed(channel_peers[0]), signed_simplex_state_array)?;
    
        let pay_id_list_array = global_result.4;
        for peer_index in 0..2 {
            CelerModule::<T>::clear_pays(
                channel_id,
                channel_peers[peer_index as usize],
                pay_id_list_array[peer_index as usize][1].clone()
            );
        }
        let settle_finalized_time = CelerModule::<T>::get_settle_finalized_time(channel_id).unwrap();
        System::<T>::set_block_number(settle_finalized_time);
    }: _(RawOrigin::signed(channel_peers[0]), channel_id)

    cooperative_settle {
        for r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::signed(channel_peers[0]), channel_id, channel_peers[0], 200, 0)?;
        let cooperative_settle_request = get_cooperative_settle_request(
            channel_id,
            2,
            vec![150, 50],
            50000,
            peers_pair
        );
    }: _(RawOrigin::signed(channel_peers[0]), cooperative_settle_request)

    deposit_native_token {
        for r in 0 .. 1000;
        let (channel_peers, peers_pair, wallet_id) = set_open_channel::<T>(r);
    }: _(RawOrigin::signed(channel_peers[0]), wallet_id, 100)

    deposit_pool {
        for r in 0 .. 1000;
        let alice = account::<T>(r);
    }: _(RawOrigin::signed(alice), alice, 100)

    withdraw_from_pool {
        for r in 0 .. 1000;
        let alice = account::<T>(r);
        CelerModule::<T>::deposit_pool(RawOrigin::signed(alice), alice, 100);
    }: _(RawOrigin::signed(alice), 100)

    approve {
        for r in 0 .. 1000;
        let alice = account::<T>(r);
        let bob = account::<T>(2*r+1);
    }: _(RawOrigin::signed(alice), bob, 100)

    transfer_from {
        for r in 0 .. 1000;
        let risa = account::<T>(3*r+1);
        let (channel_peers, peers_pair, wallet_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit_pool(
            RawOrigin::signed(channel_peers[1]),
            channel_peers[0],
            200
        );
        CelerModule::<T>::approve(
            RawOrigin::signed(channel_peers[0].clone()),
            risa,
            200
        );
    }: _(RawOrigin::signed(risa), channel_peers[0].clone(), wallet_id, 200)

    increase_allowance {
        for r in 0 .. 1000;
        let (peers, _) = set_approve::<T>(r);
    }: _(RawOrigin::signed(peers[0]), peers[1], 50)

    decrease_allowacen {
        for r in 0 .. 1000;
        let (peers, _) = set_approve::<T>(r);
    }: _(RawOrigin::singed(peers[0]), peers[1], 50)

    resolve_payment_by_conditions {
        for r in 0 .. 1000;
        let transfer_func = get_transfer_func(account::<T>(r), 10, 0);
        let cond_pay = ConditionalPay {
            pay_timestamp: Timestamp::get(),
            src: account_key("src"),
            dest: account_key("dest"),
            conditions: vec![get_condition(0), get_condition(1), get_condition(1)],
            transfer_func: transfer_func,
            resolve_deadline: 99999,
            resolve_timeout: 10,
        };
        let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
        let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
        let pay_request = ResolvePaymentConditionsRequest {
            cond_pay: cond_pay,
            hash_preimages: vec![H256::from_low_u64_be(1)],
        };
    }: _(RawOrigin::signed(account::<T>(r)), pay_request)

    resolve_payment_by_vouched_result {
        for r in 0 .. 1000;
        let transfer_func = get_transfer_func(account_key("Alice"), 100, 3);
        let shared_pay = ConditionalPay {
            pay_timestamp: 0,
            src: account_key("src"),
            dest: account_key("dest"),
            conditions: vec![get_condition(0), get_condition(3), get_condition(4)],
            transfer_func: transfer_func,
            resolve_deadline: 99999,
            resolve_timeout: 10,
        };

        let encoded_cond_pay = encode_conditional_pay(shared_pay.clone());
        let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
        let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
        let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
        let cond_pay_result = CondPayResult {
            cond_pay: shared_pay,
            amount: 10,
        };
        let vouched_cond_pay_result = VouchedCondPayResult {
            cond_pay_result: cond_pay_result,
            sig_of_src: sig_of_src,
            sig_of_dest: sig_of_dest,
        };             
    }: _(RawOrigin::signed(account::<T>(r)), vouched_cond_pay_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::*;
    use frame_support::assert_ok;

    #[test]
    fn test_benchmarks() {
        ExtBuilder::build().execute_with(|| {
           assert_ok!(test_benchmark_open_channel::<TestRuntime>());
           assert_ok!(test_benchmark_set_balance_limits::<TestRuntime>());
           assert_ok!(test_benchmark_disable_balance_limits::<TestRuntime>());
           assert_ok!(test_benchmark_enable_balance_limits::<TestRuntime>());
           assert_ok!(test_benchmark_deposit::<TestRuntime>());
           assert_ok!(test_benchmark_snapshot_states::<TestRuntime>());
           assert_ok!(test_benchmark_intend_withdraw::<TestRuntime>());
           assert_ok!(test_benchmark_confirm_withdraw::<TestRuntime>());
           assert_ok!(test_benchmark_veto_withdraw::<TestRuntime>());
           assert_ok!(test_benchmark_cooperative_withdraw::<TestRuntime>());
           assert_ok!(test_benchmark_intend_settle::<TestRuntime>());
           assert_ok!(test_benchmark_clear_pays::<TestRuntime>());
           assert_ok!(test_benchmark_confrim_settle::<TestRuntime>());
           assert_ok!(test_benchmark_cooperative_settle::<TestRuntime>());
           assert_ok!(test_benchmark_deposit_native_token::<TestRuntime>());
           assert_ok!(test_benchmark_deposit_pool::<TestRuntime>());
           assert_ok!(test_benchmark_withdraw_from_pool::<TestRuntime>());
           assert_ok!(test_benchmark_approve::<TestRuntime>());
           assert_ok!(test_benchmark_transfer_from::<TestRuntime>());
           assert_ok!(test_benchmark_transfer_to_celer_wallet::<TestRuntime>());
           assert_ok!(test_benchmark_increase_allowance::<TestRuntime>());
           assert_ok!(test_benchmark_decrease_allowance::<TestRuntime>());
           assert_ok!(test_benchmark_resolve_payment_by_conditions::<TestRuntime>());
           assert_ok!(test_benchmark_resolve_payment_by_vouched_result::<TestRuntime>());
        })
    }
}