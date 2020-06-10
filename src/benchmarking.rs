// ! Celer Pay palllet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_system::RawOrigin;
use sp_io::hashing::blake2_256;
use frame_benchmarking::benchmarks;
use sp_runtime::traits::Bounded;
use crate::ledger_operation::{LedgerOperation, SignedSimplexStateArray};
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

fn account_pair<T: Trait>(index: u32) -> sr25519::Pair {
    sr25519::Pair::from_string(&format!("//{}", s), None).expect("static values are valid: qed")
}


fn set_approve<T: Trait>(r: u32) -> (
    Vec<T::AccountId>, Vec<sr25519::Pair>
) {
    let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", r))?;
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", 2*r+1))?;
    let (channel_peers, peers_pair) = get_sorted_peer::<T>(account::<T>("channel_peer", r), account::<T>("channel_peer", 2*r));
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
    let (channel_peers, peers_pair) = get_sorted_peer::<T>(account::<T>("channel_peer", r), account::<T>("channel_peer", 2*r));
    Pool::<T>::deposit_pool(
        Origin::signed(channel_peers[0]),
        channel_peers[0],
        100,
    );
    approve(channel_peers[0], ledger_addr, 100);

    let open_channel_request = get_open_channel_request(true, 1000, 50000, 10, false, channel_peers.clone(), 1, peers_pair.clone());
    CelerModule::<T>::open_channel(RawOrigin::signed(channel_peers[0]), open_channel_request, 200)?;
    let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    return (channel_peers, peers_pair, channel_id);
}

fn get_sorted_peer<T: Trait>(
    peer_1: sr25519::Pair, 
) {

}

fn calculate_channel_id<T: Trait>() -> T::Hash {

}

fn get_open_channel_request<T: Trait> {

}

fn get_pay_id_list_info<T: Trait> {

}

fn get_signed_simplex_state_array<T: Trait> {

}

fn get_cooperative_withdraw_request<T: Trait> {

}

fn get_cosigned_intend_settle<T: Trait> {

}

fn get_cooperative_settle_request<T: Trait> {

}

fn get_transfer_func<T: Trait> {

}

fn get_condition<T: Trait> {

}




benchmarks! {
    _ { }

    open_channel {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request::<T>(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
    }: _(RawOrigin::Signed(channel_peers[0]), open_channel_request.clone(), 200)

    set_balance_limits {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request::<T>(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerModule::<T>::open_channel(RawOrigin::signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id, 200)

    disable_balance_limits {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request::<T>(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id)

    enable_balance_limits {
        let r in 0  .. 1000;
        let (channel_peers, peers_pair) = set_approve::<T>(r);
        let open_channel_request = get_open_channel_request::<T>(false, 0, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerModule::<T>::open_channel(RawOrigin::Signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id::<T>(open_channel_request, channel_peers.clone());
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id)

    deposit {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
    }: _(RawOrigin::signed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)

    snapshot_states {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);

        let pay_id_list_info = get_pay_id_list_info::<T>(vec![vec![1, 2]], 1);
        let pay_id_list = pay_id_list_info.0[0].clone();
        let signed_simplex_state_array = get_signed_simplex_state_array::<T>(
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
        CelerModule::<T>::deposit(RawOrigin::Singed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id, 200, zero_channel_id)

    confirm_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
        CelerModule::<T>::intend_withdraw(RawOrigin::Signed(channel_peers[0]), channel_id, 200, zero_channel_id)?;
        System::<T>::set_block_number(System::block_number() + 11);
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id)

    veto_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
        CelerModule::<T>::intend_withdraw(RawOrigin::Signed(channel_peers[0]), channel_id, 200, zero_channel_id)?;
    }: _(RawOrigin::Signed(channel_peers[1]), channel_id)

    cooperative_withdraw {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::Singed(channel_peers[0]), channel_id, channel_peers[0], 100, 0)?;
        let zero_channel_id = CelerModule::<T>::zero_hash();
        let cooperative_withdraw_request = get_cooperative_withdraw_request::<T>(
            channel_id,
            1,
            200,
            channel_peers[0],
            999999,
            zero_channel_id,
            peers_pair,
        );
    }: _(RawOrigin::Signed(channel_peers[0]), cooperative_withdraw_request)

    intend_settle {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::singed(channel_peers[0]), channel_id, channel_peers[0], 200, 0)?;

        // the meaning of the index: [peer index][pay hash list index][pay index]
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<BalanceOf<T>>>> =
            vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

        let global_result: (
            SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>, sr25519::Signature>,
            Vec<T::BlockNumber>,
            Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
            Vec<Vec<T::Hash>>,
            Vec<Vec<PayIdList<T::Hash>>>,
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
    }: _(RawOrigin::Signed(channel_peers[0]), signed_simplex_state_array)

    clear_pays {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::Singed(channel_peers[0]), channel_id, channel_peers[0], 200, 0)?;

        // the meaning of the index: [peer index][pay hash list index][pay index]
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> =
            vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

        let global_result: (
            SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>, sr25519::Signature>,
            Vec<BlockNumber>,
            Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
            Vec<Vec<T::Hash>>,
            Vec<Vec<PayIdList<T::Hash>>>,
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
        CelerModule::<T>::intend_settle(RawOrigin::Signed(channel_peers[0]), signed_simplex_state_array)?;

        let pay_id_list_array = global_result.4;
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id, channel_peers[0], pay_id_list_array[0][1].clone())

    confirm_settle {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0]), channel_id, channel_peers[0], 300, 0)?;
        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[1]), channel_id, channel_peers[1], 300, 0)?;

        // the meaning of the index: [peer index][pay hash list index][pay index]
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<BalanceOf<T>>>> =
            vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];

        let global_result: (
            SignedSimplexStateArray<T::Hash, T::AccountId, T::BlockNumber, BalanceOf<T>, sr25519::Signature>,
            Vec<T::BlockNumber>,
            Vec<Vec<Vec<ConditionalPay<T::Moment, T::BlockNumber, T::AccountId, T::Hash, BalanceOf<T>>>>>,
            Vec<Vec<T::Hash>>,
            Vec<Vec<PayIdList<T::Hash>>>,
        ) = get_cosigned_intend_settle::<T>(
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

        // pass onchain resolve deadline of all onchan resolve pays
        System::set_block_number(System::block_number() + 6);

        // intend settle
        CelerModule::<T>::intend_settle(RawOrigin::Signed(channel_peers[0]), signed_simplex_state_array)?;
    
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
    }: _(RawOrigin::Signed(channel_peers[0]), channel_id)

    cooperative_settle {
        for r in 0 .. 1000;
        let (channel_peers, peers_pair, channel_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit(RawOrigin::Signed(channel_peers[0]), channel_id, channel_peers[0], 200, 0)?;
        let cooperative_settle_request = get_cooperative_settle_request::<T>(
            channel_id,
            2,
            vec![150, 50],
            50000,
            peers_pair
        );
    }: _(RawOrigin::Signed(channel_peers[0]), cooperative_settle_request)

    deposit_native_token {
        for r in 0 .. 1000;
        let (channel_peers, peers_pair, wallet_id) = set_open_channel::<T>(r);
    }: _(RawOrigin::Signed(channel_peers[0]), wallet_id, 100)

    deposit_pool {
        for r in 0 .. 1000;
        let alice = account::<T>(r);
    }: _(RawOrigin::Signed(alice), alice, 100)

    withdraw_from_pool {
        for r in 0 .. 1000;
        let alice = account::<T>(r);
        CelerModule::<T>::deposit_pool(RawOrigin::Signed(alice), alice, 100);
    }: _(RawOrigin::Signed(alice), 100)

    approve {
        for r in 0 .. 1000;
        let alice = account::<T>(r);
        let bob = account::<T>(2*r+1);
    }: _(RawOrigin::Signed(alice), bob, 100)

    transfer_from {
        for r in 0 .. 1000;
        let risa = account::<T>(3*r+1);
        let (channel_peers, peers_pair, wallet_id) = set_open_channel::<T>(r);
        CelerModule::<T>::deposit_pool(
            RawOrigin::Signed(channel_peers[1]),
            channel_peers[0],
            200
        );
        CelerModule::<T>::approve(
            RawOrigin::Signed(channel_peers[0].clone()),
            risa,
            200
        );
    }: _(RawOrigin::Signed(risa), channel_peers[0].clone(), wallet_id, 200)

    increase_allowance {
        for r in 0 .. 1000;
        let (peers, _) = set_approve::<T>(r);
    }: _(RawOrigin::Signed(peers[0]), peers[1], 50)

    decrease_allowacen {
        for r in 0 .. 1000;
        let (peers, _) = set_approve::<T>(r);
    }: _(RawOrigin::Singed(peers[0]), peers[1], 50)

    resolve_payment_by_conditions {
        for r in 0 .. 1000;
        let transfer_func = get_transfer_func::<T>(account::<T>("channel_peers",r), 10, 0);
        let cond_pay = ConditionalPay {
            pay_timestamp: T::Timestamp::get(),
            src: account_pair::<T>("src"),
            dest: account_pair::<T>("dest"),
            conditions: vec![get_condition::<T>(0), get_condition::<T>(1), get_condition::<T>(1)],
            transfer_func: transfer_func,
            resolve_deadline: 99999,
            resolve_timeout: 10,
        };
        let encoded_cond_pay = PayResolver::<T>encode_conditional_pay(cond_pay.clone());
        let pay_hash: T::Hash = T::Hashing::hash(&encoded_cond_pay);
        let pay_request = ResolvePaymentConditionsRequest {
            cond_pay: cond_pay,
            hash_preimages: vec![H256::from_low_u64_be(1)],
        };
    }: _(RawOrigin::Signed(account::<T>(r)), pay_request)

    resolve_payment_by_vouched_result {
        for r in 0 .. 1000;
        let transfer_func = get_transfer_func::<T>(account_key::<T>("channel_peer", r), 100, 3);
        let shared_pay = ConditionalPay {
            pay_timestamp: 0,
            src: account_pair::<T>("src"),
            dest: account_pair::<T>("dest"),
            conditions: vec![get_condition::<T>(0), get_condition::<T>(3), get_condition::<T>(4)],
            transfer_func: transfer_func,
            resolve_deadline: 99999,
            resolve_timeout: 10,
        };

        let encoded_cond_pay = PayResolver::<T>::encode_conditional_pay(shared_pay.clone());
        let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
        let sig_of_src = account_pair::<T>("src").sign(&encoded_cond_pay);
        let sig_of_dest = account_pair::<T>("dest").sign(&encoded_cond_pay);
        let cond_pay_result = CondPayResult {
            cond_pay: shared_pay,
            amount: 10,
        };
        let vouched_cond_pay_result = VouchedCondPayResult {
            cond_pay_result: cond_pay_result,
            sig_of_src: sig_of_src,
            sig_of_dest: sig_of_dest,
        };             
    }: _(RawOrigin::Signed(account::<T>(r)), vouched_cond_pay_result)
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