#[cfg(test)]
pub mod test_ledger_operation {
    use crate::Error;
    use crate::mock::*;
    use crate::pay_resolver::{
        Condition, ConditionalPay, PayResolver, ResolvePaymentConditionsRequest, TokenTransfer,
        TransferFunction, TransferFunctionType, TokenType, AccountAmtPair, TokenInfo,
    };
    use crate::pool::Pool;
    use crate::pay_registry::PayRegistry;
    use crate::tests::pay_resolver::test_pay_resolver::*;
    use crate::ledger_operation::*;
    use crate::RawEvent;
    use frame_support::{assert_noop, assert_ok};
    use sp_core::{hashing, sr25519, Pair, H256};
    use sp_runtime::DispatchError;
    use codec::{Encode};

    #[test]
    fn test_pass_return_uninitialized_status_for_an_inexistent_channel() {
        ExtBuilder::build().execute_with(|| {   
            let random_channel_id: H256 = H256::from_low_u64_be(3);
            let status = CelerPayModule::get_channel_status(random_channel_id);
            assert_eq!(status, 0);
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
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            approve(channel_peers[1], celer_ledger_account, 200);

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
            let cal_channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            assert_ok!(CelerPayModule::enable_balance_limits(
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
            let err = CelerPayModule::set_balance_limits(Origin::signed(risa), channel_id, 200).unwrap_err();
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

            assert_ok!(CelerPayModule::set_balance_limits(
                Origin::signed(channel_peers[0]),
                channel_id,
                300
            ));
            let amount = CelerPayModule::get_balance_limits(channel_id);
            assert_eq!(amount.amount, 300);
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
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            approve(channel_peers[1], celer_ledger_account, 200);
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
                CelerPayModule::disable_balance_limits(Origin::signed(risa), channel_id).unwrap_err();
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

            assert_ok!(CelerPayModule::disable_balance_limits(
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
            let _ = CelerPayModule::disable_balance_limits(Origin::signed(channel_peers[0]), channel_id).unwrap();

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
            let err = CelerPayModule::enable_balance_limits(Origin::signed(risa), channel_id).unwrap_err();
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
            let _ = CelerPayModule::enable_balance_limits(Origin::signed(channel_peers[0]), channel_id).unwrap();
            let _ = CelerPayModule::set_balance_limits(Origin::signed(channel_peers[0]), channel_id, 10).unwrap();

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
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            approve(channel_peers[0], celer_ledger_account, 200);

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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            let (_channel_id, _amount, _receiver, _, _withdraw_info_seq_num) =
                LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();
            assert_eq!(_channel_id, channel_id);
            assert_eq!(_amount, 200);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_withdraw_info_seq_num, 1);
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_using_an_expected_seq_num() {
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
            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            assert_eq!(err, DispatchError::Other("seqNum error"));

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
            assert_eq!(err, DispatchError::Other("seqNum error"));

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
    fn test_pass_cooperative_withdraw_when_receiver_is_channel_peer_1() {
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
            let cooperative_withdraw_request = get_cooperative_withdraw_request(
                channel_id,
                1,
                200,
                channel_peers[1],
                9999999,
                zero_channel_id,
                peers_pair.clone(),
            );
            let (_channel_id, _amount, _receiver, _, _withdraw_info_seq_num) =
                LedgerOperation::<TestRuntime>::cooperative_withdraw(cooperative_withdraw_request).unwrap();
            assert_eq!(_channel_id, channel_id);
            assert_eq!(_amount, 200);
            assert_eq!(_receiver, channel_peers[1]);
            assert_eq!(_withdraw_info_seq_num, 1);

            let (_, _deposits, _withdrawals)
                = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![_deposits[0].amount, _deposits[1].amount], vec![300, 0]);
            assert_eq!(vec![_withdrawals[0].amount, _withdrawals[1].amount], vec![0, 200]);
        })
    }

    #[test]
    fn test_pass_cooperative_withdraw_when_receiver_does_not_have_enough_deposit_but_the_whole_channel_does(
    ) {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let balance_amt = CelerPayModule::get_total_balance(channel_id);
            let (_channel_peer, _deposits, _withdrawals)
                = CelerPayModule::get_balance_map(channel_id);

            assert_eq!(_channel_id, channel_id);
            assert_eq!(_withdrawn_amount, 200);
            assert_eq!(_receiver, channel_peers[0]);
            assert_eq!(_recipient_channel_id, zero_channel_id);
            assert_eq!(_withdraw_info_seq_num, 1);
            assert_eq!(balance_amt.amount, 0);
            assert_eq!(_channel_peer, channel_peers);
            assert_eq!(vec![_deposits[0].amount, _deposits[1].amount], [160, 40]);
            assert_eq!(vec![_withdrawals[0].amount, _withdrawals[1].amount], [200, 0]);
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

            let _balance_amt_1 = CelerPayModule::get_total_balance(channel_id_1);
            let (_channel_peer_1, _deposits_1, _withdrawals_1)
                = CelerPayModule::get_balance_map(channel_id_1);
            let _balance_amt_2 = CelerPayModule::get_total_balance(channel_id_2);
            let (_channel_peer_2, _deposits_2, _withdrawals_2)
                = CelerPayModule::get_balance_map(channel_id_2);

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
            assert_eq!(_balance_amt_1.amount, 0);
            assert_eq!(_channel_peer_1, channel_peers_1);
            assert_eq!(vec![_deposits_1[0].amount, _deposits_1[1].amount], expected_deposits);
            assert_eq!(vec![_withdrawals_1[0].amount, _withdrawals_1[1].amount], [200, 0]);
            assert_eq!(_balance_amt_2.amount, 200);
            assert_eq!(_channel_peer_2, channel_peers_2);
            assert_eq!(vec![_deposits_2[0].amount, _deposits_2[1].amount], expected_deposits);
            assert_eq!(vec![_withdrawals_2[0].amount, _withdrawals_2[1].amount], [0, 0]);
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
                    error: 9,
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();

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
            System::set_block_number(1);
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
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>>>,
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

            // resolve the payments in head PayIdList
            // the head list of peer_from 0
            for i in 0..cond_pays[0][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // the head list of peer_from 1
            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            assert_eq!(settle_finalized_time, System::block_number() + 10);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 2);

            let (_, _, _, _, transfer_out, pending_pay_out) = CelerPayModule::get_peers_migration_info(channel_id);
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], vec![13, 31]);
            assert_eq!(vec![pending_pay_out[0].amount, pending_pay_out[1].amount], vec![7, 15]);

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
            System::set_block_number(1);
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
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>>>,
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

            // resolve the payments in head PayIdList
            // the head list of peer_from 0
            for i in 0..cond_pays[0][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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
            System::set_block_number(1);
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
                Vec<Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>>>,
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
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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
                assert_ok!(CelerPayModule::clear_pays(
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
            System::set_block_number(1);
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
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            assert!(System::block_number() <= settle_finalized_time);
        })
    }

    #[test]
    fn test_confirm_settle_fail_due_to_lack_of_deposit() {
        ExtBuilder::build().execute_with(|| {  
            System::set_block_number(1); 
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
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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

            let (_, deposits, withdrawals) = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![deposits[0].amount, deposits[1].amount], [5, 0]);
            assert_eq!(vec![withdrawals[0].amount, withdrawals[1].amount], [0, 0]);

            let (_, transfer_out) = CelerPayModule::get_transfer_out_map(channel_id);
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], [20, 46]);

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(settle_finalized_time);

            let err = LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Module {
                    index: 0,
                    error: 10,
                    message: Some("ConfirmSettleFail")
                }
            );
        })
    }

    #[test]
    fn test_pass_clear_pays_after_settle_finalized_time() {
        ExtBuilder::build().execute_with(|| {   
            System::set_block_number(1);
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
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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
            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(settle_finalized_time);

            let pay_id_list_array = global_result.4;
            let amounts = vec![vec![3, 4], vec![7, 8]];

            for peer_index in 0..2 {
                assert_ok!(CelerPayModule::clear_pays(
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
            System::set_block_number(1);  
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
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
                    }
                }
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
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
            System::set_block_number(1);  
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
                        let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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
            let mut encoded = pay_id_list_array[0][1].pay_ids[0].encode();
            encoded.extend(pay_id_list_array[0][1].pay_ids[1].encode());
            encoded.extend(pay_id_list_array[0][1].next_list_hash.encode());

            let hash = hashing::blake2_256(&encoded).into();
            assert_eq!(next_list_hash.unwrap(), hash);

            for peer_index in 0..2 {
                assert_ok!(LedgerOperation::<TestRuntime>::clear_pays(
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                ));
            }

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(settle_finalized_time);

            let (_, deposits, withdrawals) = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![deposits[0].amount, deposits[1].amount], [500, 500]);
            assert_eq!(vec![withdrawals[0].amount, withdrawals[1].amount], [0, 0]);

            let (_, transfer_out) = CelerPayModule::get_transfer_out_map(channel_id);
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], [20, 46]);

            let (_, settle_balance) =
                LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [526, 474]);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 3);
        })
    }

    #[test]
    fn test_pass_open_channel_when_total_deposit_is_larger_than_zero() {
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

            let open_channel_request = get_open_channel_request(false, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request,
                200,
            ).unwrap();

            let (_, deposits, _) = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![deposits[0].amount, deposits[1].amount], [100, 200]);
        })
    }

    #[test]
    fn test_pass_open_channel_when_total_deposit_is_larger_than_zero_and_msg_value_receiver_is_1_and_caller_is_not_peers(
    ) {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let risa = account_key("Risa");

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 100);
            let open_channel_request = get_open_channel_request(true, 1000, 500001, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(risa),
                open_channel_request,
                200,
            ).unwrap();

            let (_, deposits, _) = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![deposits[0].amount, deposits[1].amount], [100, 200]);
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

            let total_balance = CelerPayModule::get_total_balance(channel_id);
            assert_eq!(total_balance.amount, 200);

            let (channel_id, settle_balance): (H256, Vec<Balance>) =
                LedgerOperation::<TestRuntime>::cooperative_settle(cooperative_settle_request).unwrap();
            assert_eq!(settle_balance, [150, 50]);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 3);
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
            let _ = CelerPayModule::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            //System::set_block_number(System::block_number() + settle_finalized_time);
            let expected_settle_finalized_time = System::block_number() + 10;
            assert_eq!(settle_finalized_time, expected_settle_finalized_time);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 2);

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

            let (_, _, _, _, transfer_out, pending_pay_out) = CelerPayModule::get_peers_migration_info(channel_id);
            // updated transfer_out map with cleared pays in the head PayIdList
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], [10, 20]);
            assert_eq!(vec![pending_pay_out[0].amount, pending_pay_out[1].amount], [10, 26]);
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

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(System::block_number() + settle_finalized_time);

            let (_, settle_balance) =
                LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [110, 190]);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 3);
        })
    }

    #[test]
    fn test_pass_intend_settle_with_0_payment() {
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

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            let expected_single_settle_finalized_time = 10 as BlockNumber + System::block_number();
            assert!(settle_finalized_time == expected_single_settle_finalized_time);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 2);

            let (_, _, _, _, transfer_out, pending_pay_out) = CelerPayModule::get_peers_migration_info(channel_id);
            // updated transfer_out map with cleared pays in the head PayIdList
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], [0, 0]);
            // updated pending_pay_out map without cleared pays in the head PayIdList
            assert_eq!(vec![pending_pay_out[0].amount, pending_pay_out[1].amount], [0, 0]);
        })
    }

    #[test]
    fn test_fail_intend_settle_with_0_payment_again() {
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

            let single_singed_null_state = get_single_signed_simplex_state(channel_id, channel_peers[0], peers_pair);
            let signed_simplex_state_array = SignedSimplexStateArray {
                signed_simplex_states: vec![single_singed_null_state],
            };

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array.clone(),
            ).unwrap();

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(settle_finalized_time);

            let (_, settle_balance) = LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [100, 200]);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 3);
        })
    }

    #[test]
    fn test_pass_intend_settle_with_one_non_null_simplex_state() {
        ExtBuilder::build().execute_with(|| {  
            System::set_block_number(1); 
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            let expected_single_settle_finalized_time = 10 + System::block_number();
            assert_eq!(settle_finalized_time, expected_single_settle_finalized_time);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 2);

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

            let (_, _, _, _, transfer_out, pending_pay_out) = CelerPayModule::get_peers_migration_info(channel_id);
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], [13, 0]);
            assert_eq!(vec![pending_pay_out[0].amount, pending_pay_out[1].amount], [0, 0]);
        })
    }

    #[test]
    fn test_pass_confirm_settle_with_one_non_null_simplex_state() {
        ExtBuilder::build().execute_with(|| {   
            System::set_block_number(1);
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            System::set_block_number(settle_finalized_time);

            let (_, settle_balance) =
                LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
            assert_eq!(settle_balance, [87, 213]);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 3);
        })
    }

    #[test]
    fn test_pass_intend_settle_with_multiple_cross_channel_simplex_states() {
        ExtBuilder::build().execute_with(|| {  
            System::set_block_number(1); 
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // 1 pair of simplex states + 1 non-null simplex state + 1 null simplex state
            approve(channel_peers[1], celer_ledger_account, 600);

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
                Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>>,
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }
            for i in 0..2 {
                let cond_pays = pay_id_infos[1].2.clone();
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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
                let settle_finalized_time = CelerPayModule::get_settle_finalized_time(unique_channel_ids[i]);
                assert_eq!(expected_settle_finalized_time, settle_finalized_time);
                let status = CelerPayModule::get_channel_status(unique_channel_ids[i]);
                assert_eq!(status, 2);
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
            System::set_block_number(1);
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            // 1 pair of simplex states + 1 non-null simplex state + 1 null simplex state
            approve(channel_peers[1], celer_ledger_account, 600);

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
                Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>>,
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }
            for i in 0..2 {
                let cond_pays = pay_id_infos[1].2.clone();
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
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
                let tmp = CelerPayModule::get_settle_finalized_time(unique_channel_ids[i]);
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
                let status = CelerPayModule::get_channel_status(unique_channel_ids[i]);
                assert_eq!(status, 3);
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            assert_ok!(LedgerOperation::<TestRuntime>::snapshot_states(
                signed_simplex_state_array
            ));

            // intend withdraw
            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            let balance_amt = CelerPayModule::get_total_balance(channel_id);
            assert_eq!(balance_amt.amount, 200);

            // get balance map
            let (_channel_peers, _deposits, _withdrawals) =
                CelerPayModule::get_balance_map(channel_id);
            assert_eq!(_channel_peers, channel_peers);
            assert_eq!(vec![_deposits[0].amount, _deposits[1].amount], [100, 200]);
            assert_eq!(vec![_withdrawals[0].amount, _withdrawals[1].amount], [100, 0]);
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let (_, _deposits, _withdrawals) = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![_deposits[0].amount, _deposits[1].amount], [50, 150]);
            assert_eq!(vec![_withdrawals[0].amount, _withdrawals[1].amount], [50, 0]);
        })
    }

    #[test]
    fn test_fail_intend_settle_with_smaller_seq_num_than_snapshot() {
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain resolve deadline of all onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            assert_ok!(LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                local_signed_simplex_state_array
            ));

            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
            let expected_settle_finalized_time = 10 + System::block_number();
            assert_eq!(settle_finalized_time, expected_settle_finalized_time);

            let status = CelerPayModule::get_channel_status(channel_id);
            assert_eq!(status, 2);

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

            let (_, _, _, _, transfer_out, pending_pay_out) = CelerPayModule::get_peers_migration_info(channel_id);
            // updated transferOut map with clreared pays in the head PayIdList
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], vec![0, 13]);
            assert_eq!(vec![pending_pay_out[0].amount, pending_pay_out[1].amount], vec![0, 0]);
        })
    }

    #[test]
    fn test_fail_intend_withdraw_after_intend_settle() {
        ExtBuilder::build().execute_with(|| {  
            System::set_block_number(1); 
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // the head list of peer_from 1
            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            System::set_block_number(1);  
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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // the head list of peer_from 1
            for i in 0..cond_pays[1][0].len() {
                let pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pays[1][0][i].clone(),
                    hash_preimages: vec![],
                };
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain  resolve deadline of all onchain resolved pays
            // but not pass the last pay resolved deadline
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let deposit_account = account_key("Carl");

            approve(deposit_account, celer_ledger_account, 10000);

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
            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(deposit_account),
                deposit_account,
                10000,
            ));
            approve(deposit_account, celer_ledger_account, 10000);
            let receivers = vec![channel_peers[0].clone(), channel_peers[1].clone()];
            let amounts = vec![100, 200];

            assert_ok!(CelerPayModule::deposit_in_batch(
                Origin::signed(deposit_account),
                channel_ids.clone(),
                receivers.clone(),
                vec![0, 0],
                amounts.clone()
            ));

            let (_, deposits_1, _) = CelerPayModule::get_balance_map(channel_ids[0].clone());
            let (_, deposits_2, _) = CelerPayModule::get_balance_map(channel_ids[1].clone());
            assert_eq!(vec![deposits_1[0].amount, deposits_1[1].amount], [100, 0]);
            assert_eq!(vec![deposits_2[0].amount, deposits_2[1].amount], [0, 200]);
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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

            let (_, _deposits, _withdrawals) = CelerPayModule::get_balance_map(channel_id);
            assert_eq!(vec![_deposits[0].amount, _deposits[1].amount], [50, 150]);
            assert_eq!(vec![_withdrawals[0].amount, _withdrawals[1].amount], [60, 0]);
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

            let zero_channel_id = CelerPayModule::get_zero_hash();
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
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 200);

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
                let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(channel_peers[0], pay_request).unwrap();
            }

            // pass onchain resolve deadline ofall onchain resolved pays
            System::set_block_number(System::block_number() + 6);

            // intend settle
            let _ = LedgerOperation::<TestRuntime>::intend_settle(
                Origin::signed(channel_peers[0]),
                signed_simplex_state_array,
            ).unwrap();

            let expected_single_settle_finalized_time = 10 + System::block_number();
            let settle_finalized_time = CelerPayModule::get_settle_finalized_time(channel_id);
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

            let (_, _, _, _, transfer_out, pending_pay_out) = CelerPayModule::get_peers_migration_info(channel_id);
            // updated  transferOut  map  which  cleared pays in the head PayIdList
            assert_eq!(vec![transfer_out[0].amount, transfer_out[1].amount], [10, 0]);
            // updated pendingPayOut map without cleared  pays  in the head PayIdList
            assert_eq!(vec![pending_pay_out[0].amount, pending_pay_out[1].amount], [0, 0]);
        })
    }

    #[test]
    fn test_fail_intend_settle_operable_channel_for_a_non_peer() {
        ExtBuilder::build().execute_with(|| {   
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let risa = account_key("Risa");

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 200);

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
            let celer_ledger_account = CelerPayModule::get_celer_ledger_id();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            let risa = account_key("Risa");

            assert_ok!(Pool::<TestRuntime>::deposit_pool(
                Origin::signed(channel_peers[0]),
                channel_peers[0],
                100,
            ));
            approve(channel_peers[0], celer_ledger_account, 200);

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
        let account_amt_pair_0: AccountAmtPair<AccountId, Balance>;
        let account_amt_pair_1: AccountAmtPair<AccountId, Balance>;
        let token_distribution: TokenDistribution<AccountId, Balance>;
        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };

        if zero_total_deposit == true {
            account_amt_pair_0 = AccountAmtPair {
                account: Some(channel_peers[0]),
                amt: 0,
            };
            account_amt_pair_1 = AccountAmtPair {
                account: Some(channel_peers[1]),
                amt: 0,
            };

            token_distribution = TokenDistribution {
                token: token_info,
                distribution: vec![account_amt_pair_0, account_amt_pair_1],
            };
        } else {
            account_amt_pair_0 = AccountAmtPair {
                account: Some(channel_peers[0]),
                amt: 100,
            };
            account_amt_pair_1 = AccountAmtPair {
                account: Some(channel_peers[1]),
                amt: 200,
            };

            token_distribution = TokenDistribution {
                token: token_info,
                distribution: vec![account_amt_pair_0, account_amt_pair_1],
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
            Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>>,
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
        let mut _cond_pay_array: Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>> = vec![vec![]];
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
        let mut cond_pay_array: Vec<Vec<ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>>> 
        = vec![
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
                let conditions: Condition<H256>;
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
           
            let mut encoded: Vec<u8> = vec![];
            pay_id_lists[i].pay_ids.clone().into_iter().for_each(|pay_id| {
                encoded.extend(pay_id.encode());
            });
            encoded.extend(pay_id_lists[i].next_list_hash.encode());
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
        peers_pair: Vec<sr25519::Pair>,
    ) -> SignedSimplexState<H256, AccountId, BlockNumber, Balance, Signature> {
        let account_amt_pair = AccountAmtPair {
            account: None,
            amt: transfer_amount,
        };

        let token_info = TokenInfo {
            token_type: TokenType::Celer,
        };

        let transfer_to_peer = TokenTransfer {
            token: token_info,
            receiver: account_amt_pair,
        };

        let simplex_payment_channel = SimplexPaymentChannel {
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
        let account_amt_pair_0 = AccountAmtPair {
            account: Some(channel_peers[0]),
            amt: settle_amounts[0],
        };
        let account_amt_pair_1 = AccountAmtPair {
            account: Some(channel_peers[1]),
            amt: settle_amounts[1],
        };
        let settle_info = CooperativeSettleInfo {
            channel_id: channel_id,
            seq_num: seq_num,
            settle_balance: vec![account_amt_pair_0, account_amt_pair_1],
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
   
    pub fn get_transfer_func_2(amount: Balance) -> TransferFunction<AccountId, Balance> {
        let account_amt_pair = AccountAmtPair {
            account: None,
            amt: amount,
        };

        let token_info = TokenInfo {
            token_type: TokenType::Celer,
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