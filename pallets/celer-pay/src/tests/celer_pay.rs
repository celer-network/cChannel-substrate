#[cfg(test)]
pub mod tests_celer {
    use crate::tests::ledger_operation::test_ledger_operation::*;
    use crate::ledger_operation::{LedgerOperation, SignedSimplexStateArray, PayIdList};
    use crate::mock::*;
    use crate::tests::pay_resolver::test_pay_resolver::*;
    use crate::pay_resolver::{
        CondPayResult, ConditionalPay, PayResolver, 
        ResolvePaymentConditionsRequest,VouchedCondPayResult,
    };
    use crate::pool::Pool;
    use crate::pool::tests::{deposit_pool};
    use frame_support::assert_ok;
    use sp_core::{Pair, H256};

    #[test]
    fn test_pass_open_channel() {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);

            let open_channel_request = get_open_channel_request(
                true,
                10000,
                50000,
                10,
                false,
                channel_peers.clone(),
                1,
                peers_pair,
            );
            assert_ok!(CelerPayModule::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request.clone(),
                200
            ));
        })
    }

    #[test]
    fn test_pass_set_balnce_limits() {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);

            let open_channel_request = get_open_channel_request(
                true,
                10000,
                50000,
                10,
                false,
                channel_peers.clone(),
                1,
                peers_pair,
            );
            assert_ok!(CelerPayModule::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request.clone(),
                200
            ));

            let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
            assert_ok!(CelerPayModule::set_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id,
                200
            ));
        })
    }

    #[test]
    fn test_pass_disable_balance_limits() {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);

            let open_channel_request = get_open_channel_request(
                true,
                10000,
                50000,
                10,
                false,
                channel_peers.clone(),
                1,
                peers_pair,
            );
            assert_ok!(CelerPayModule::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request.clone(),
                200
            ));

            let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
            assert_ok!(CelerPayModule::disable_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_pass_enable_balance_limits() {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);

            let open_channel_request = get_open_channel_request(
                false,
                0,
                50000,
                10,
                false,
                channel_peers.clone(),
                1,
                peers_pair,
            );
            assert_ok!(CelerPayModule::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request.clone(),
                200
            ));

            let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
            assert_ok!(CelerPayModule::enable_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_pass_deposit() {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);

            let open_channel_request = get_open_channel_request(
                true,
                1000,
                50000,
                10,
                false,
                channel_peers.clone(),
                1,
                peers_pair,
            );
            assert_ok!(CelerPayModule::open_channel(
                Origin::signed(channel_peers[0]),
                open_channel_request.clone(),
                200
            ));

            let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
            assert_ok!(CelerPayModule::deposit(
                Origin::signed(channel_peers[0]),
                channel_id,
                channel_peers[0],
                300,
                0
            ));
        })
    }

    #[test]
    fn test_pass_snapshot_states() {
        ExtBuilder::build().execute_with(|| {   
                        let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);

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
                vec![total_pending_amount],
                channel_peers[1].clone(),
                peers_pair.clone(),
            );

            assert_ok!(CelerPayModule::snapshot_states(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array
            ));

        })
    }

    #[test]
    fn test_pass_intend_withdraw() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(
                true,
                300,
                500001,
                10,
                true,
                channel_peers.clone(),
                1,
                peers_pair,
            );
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
            assert_ok!(CelerPayModule::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id
            ));
        })
    }

    #[test]
    fn test_pass_confirm_withdraw() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(
                true,
                800,
                500001,
                10,
                true,
                channel_peers.clone(),
                1,
                peers_pair,
            );
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();

            System::set_block_number(System::block_number() + 11);

            assert_ok!(CelerPayModule::confirm_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_pass_veto_withdraw() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(
                true,
                300,
                500001,
                10,
                true,
                channel_peers.clone(),
                1,
                peers_pair,
            );
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
            let _ = LedgerOperation::<TestRuntime>::intend_withdraw(
                Origin::signed(channel_peers[0]),
                channel_id,
                200,
                zero_channel_id,
            ).unwrap();

            assert_ok!(CelerPayModule::veto_withdraw(
                Origin::signed(channel_peers[1]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(
                true,
                800,
                500001,
                10,
                true,
                channel_peers.clone(),
                1,
                peers_pair.clone(),
            );
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                200,
                channel_peers[0],
                9999999,
                zero_channel_id,
                peers_pair,
            );
            assert_ok!(CelerPayModule::cooperative_withdraw(
                Origin::signed(channel_peers[0]),
                cooperative_withdraw_request
            ));
        })
    }

    #[test]
    fn test_pass_intend_settle() {
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
                channel_peers[0],
                vec![peers_pair[0].clone(), peers_pair[1].clone()],
                1,
            );

            let signed_simplex_state_array = global_result.0;
           
            // ensure it passes the lat pay resolve deadline
            System::set_block_number(System::block_number() + 3);
            assert_eq!(System::block_number(), 3);

            // intend settle
            assert_ok!(CelerPayModule::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ));

        })
    }

    #[test]
    fn test_pass_confirm_settle() {
        ExtBuilder::build().execute_with(|| {   
            System::set_block_number(1);
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(
                true,
                20000,
                500000,
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
                        assert_ok!(PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request));
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

            for peer_index in 0..2 {
                assert_ok!(LedgerOperation::<TestRuntime>::clear_pays(
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));
            }

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(settle_finalized_time);

            assert_ok!(CelerPayModule::confirm_settle(
                Origin::signed(channel_peers[0]),
                channel_id
            ));
        })
    }

    #[test]
    fn test_pass_cooperative_settle() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let open_channel_request = get_open_channel_request(
                true,
                800,
                500000,
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
                channel_peers.clone(),
                vec![150, 50],
                500000,
                peers_pair,
            );
            assert_ok!(CelerPayModule::cooperative_settle(
                Origin::signed(channel_peers[0]),
                cooperative_settle_request
            ));
        })
    }

    #[test]
    fn test_pass_deposit_pool() {
        ExtBuilder::build().execute_with(|| {   
            let alice = account_key("Alice");
            assert_ok!(CelerPayModule::deposit_pool(Origin::signed(alice), alice, 100));
        })
    }

    #[test]
    fn test_pass_withdraw_from_pool() {
        ExtBuilder::build().execute_with(|| {   
            let alice = account_key("Alice");
            assert_ok!(CelerPayModule::deposit_pool(Origin::signed(alice), alice, 100));
            assert_ok!(CelerPayModule::withdraw_from_pool(Origin::signed(alice), 100));
        })
    }

    #[test]
    fn test_pass_transfer_from() {
        ExtBuilder::build().execute_with(|| {   
            let alice = account_key("Alice"); // to address
            let bob = account_key("Bob"); // from address
            let risa = account_key("Risa"); // spender address

            deposit_pool(bob, 200);
            approve(bob, risa, 150);
            assert_ok!(CelerPayModule::transfer_from(
                Origin::signed(risa),
                bob,
                alice, 150
            ));
        })
    }

    #[test]
    fn test_pass_approve() {
        ExtBuilder::build().execute_with(|| {   
            let bob = account_key("Bob"); // owner address
            let risa = account_key("Risa"); // spender address
            assert_ok!(CelerPayModule::approve(
                Origin::signed(bob.clone()),
                risa.clone(),
                100
            ));
        })
    }

    #[test]
    fn test_pass_increase_allowance() {
        ExtBuilder::build().execute_with(|| {   
            let bob = account_key("Bob"); // owner address
            let risa = account_key("Risa"); // spender address
            approve(bob, risa, 100);

            assert_ok!(CelerPayModule::increase_allowance(
                Origin::signed(bob),
                risa,
                50
            ));
        })
    }

    #[test]
    fn test_pass_decrease_allowacne() {
        ExtBuilder::build().execute_with(|| {   
            let bob = account_key("Bob"); // owner address
            let risa = account_key("Risa"); // spender address
            approve(bob, risa, 100);

            assert_ok!(CelerPayModule::decrease_allowance(
                Origin::signed(bob),
                risa,
                50
            ));
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 10, 0);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(1), get_condition(1)],
                transfer_func: transfer_func,
                resolve_deadline: 99999,
                resolve_timeout: 10,
            };
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)],
            };

            assert_ok!(CelerPayModule::resolve_payment_by_conditions(
                Origin::signed(account_key("Alice")),
                pay_request
            ));
        })
    }

    #[test]
    fn test_pass_payment_by_vouched_result() {
        ExtBuilder::build().execute_with(|| {   
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
            assert_ok!(CelerPayModule::resolve_payment_by_vouched_result(
                Origin::signed(account_key("Alice")),
                vouched_cond_pay_result
            ));
        })
    }
}
