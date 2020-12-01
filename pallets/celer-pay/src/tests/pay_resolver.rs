#[cfg(test)]
pub mod test_pay_resolver {
    use crate::mock::*;
    use sp_core::{hashing, Pair, H256};
    use sp_runtime::DispatchError;
    use crate::pay_resolver::*;
    use codec::{Encode};
    use mock_boolean_condition::{BooleanArgsQueryFinalization, BooleanArgsQueryOutcome};
    use mock_numeric_condition::{NumericArgsQueryFinalization, NumericArgsQueryOutcome};

    #[test]
    fn test_pass_resolve_payment_by_conditions_boolean_and_and_all_condition_true() {
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
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)],
            };

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 10);
            assert_eq!(resolve_deadline, System::block_number());
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_boolean_and_and_some_condition_false() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 20, 0);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(2), get_condition(1)],
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

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 0);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_boolean_or_and_some_conditions_true() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 30, 1);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(1), get_condition(2)],
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

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 30);
            assert_eq!(resolve_deadline, System::block_number());
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_when_the_logic_is_boolean_or_and_all_conditions_false(
    ) {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 30, 1);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(2), get_condition(2)],
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

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 0);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_vouched_result() {
        ExtBuilder::build().execute_with(|| {   
            test_resolve_payment_by_vouched_result(20);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_vouched_result_pass_when_new_result_is_larger_than_old_result_25(
    ) {
        ExtBuilder::build().execute_with(|| {   
            test_resolve_payment_by_vouched_result(20);
            test_resolve_payment_by_vouched_result(25);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_vouched_result_pass_when_new_result_is_larger_than_old_result_35(
    ) {
        ExtBuilder::build().execute_with(|| {   
            test_resolve_payment_by_vouched_result(20);
            test_resolve_payment_by_vouched_result(25);
            test_resolve_payment_by_vouched_result(35);
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_vouched_result_pass_when_new_result_is_smaller_than_old_result()
    {
        ExtBuilder::build().execute_with(|| {   
            test_resolve_payment_by_vouched_result(20);
            test_resolve_payment_by_vouched_result(25);
            test_resolve_payment_by_vouched_result(35);
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
                amount: 30,
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest,
            };
            let err =
                PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                    .unwrap_err();
            assert_eq!(err, DispatchError::Other("New amount is not larger"));
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_vouched_result_pass_when_exceeding_max_amount() {
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
                amount: 200,
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest,
            };

            let err =
                PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                    .unwrap_err();
            assert_eq!(err, DispatchError::Other("Exceed max transfer amount"));
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_conditions_when_deadline_passed() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 10, 0);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(2), get_condition(1)],
                transfer_func: transfer_func,
                resolve_deadline: 1,
                resolve_timeout: 10,
            };
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)],
            };

            System::set_block_number(3);
            let err =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("Passed pay resolve deadline in cond_pay msg")
            );
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_vouched_result_when_deadline_passed() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 100, 3);
            let shared_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(3), get_condition(4)],
                transfer_func: transfer_func,
                resolve_deadline: 1,
                resolve_timeout: 10,
            };

            let encoded_cond_pay = encode_conditional_pay(shared_pay.clone());
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: shared_pay,
                amount: 20,
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest,
            };
            System::set_block_number(3);
            let err =
                PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                    .unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("Passed pay resolve deadline in cond_pay msg")
            );
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_vouched_result_after_onchain_resolve_pay_deadline() {
        ExtBuilder::build().execute_with(|| {   
            test_resolve_payment_by_vouched_result(20);
            // Advance block number
            System::set_block_number(System::block_number() + 11);

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
                amount: 30,
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest,
            };

            let err =
                PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                    .unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("Passed onchain resolve pay deadline")
            );
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_conditions_after_onchain_resolve_pay_deadline() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 100, 0);
            let shared_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(2), get_condition(1)],
                transfer_func: transfer_func,
                resolve_deadline: 99999,
                resolve_timeout: 10,
            };
            let encoded_cond_pay = encode_conditional_pay(shared_pay.clone());
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: shared_pay.clone(),
                amount: 20,
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest,
            };
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: shared_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)],
            };

            let _ =
                PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                    .unwrap();
            System::set_block_number(System::block_number() + 11);

            let err =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("Passed onchain resolve pay deadline")
            );
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_conditions_with_a_false_hash_lock_condition() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 200, 1);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(1), get_condition(0)],
                transfer_func: transfer_func,
                resolve_deadline: 99999,
                resolve_timeout: 10,
            };
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1), H256::from_low_u64_be(0)],
            };

            let err =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Wrong preimage"));
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_when_numeric_add() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 50, 3);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(3), get_condition(4)],
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

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 35);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_when_numeric_max() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 50, 4);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(3), get_condition(4)],
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

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 25);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_when_numeric_min() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 50, 5);
            let cond_pay = ConditionalPay {
                pay_timestamp: Timestamp::get(),
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0), get_condition(3), get_condition(4)],
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

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 10);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn should_resolve_pay_using_max_amount_with_any_transfer_logic_as_long_as_there_are_no_contract_conditions(
    ) {
        ExtBuilder::build().execute_with(|| {   
            let mut transfer_func: TransferFunction<AccountId, BlockNumber>;
            let mut cond_pay: ConditionalPay<Moment, BlockNumber,  AccountId, H256, Balance>;
            let mut encoded_cond_pay: Vec<u8>;
            let mut pay_hash: H256;
            let mut pay_request: ResolvePaymentConditionsRequest<
                Moment,
                BlockNumber,
                AccountId,
                H256,
                Balance,
            >;
            let mut result: (H256, Balance, BlockNumber);
            for i in 0..6 {
                if i == 2 {
                    continue;
                }
                transfer_func = get_transfer_func(account_key("Alice"), 50, i);
                cond_pay = ConditionalPay {
                    pay_timestamp: Timestamp::get(),
                    src: account_key("src"),
                    dest: account_key("dest"),
                    conditions: vec![get_condition(0)],
                    transfer_func: transfer_func,
                    resolve_deadline: 99999,
                    resolve_timeout: 10,
                };
                encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
                pay_hash = hashing::blake2_256(&encoded_cond_pay).into();
                pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pay,
                    hash_preimages: vec![H256::from_low_u64_be(1)],
                };

                result =
                    PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
                assert_eq!(result.0, calculate_pay_id::<TestRuntime>(pay_hash));
                assert_eq!(result.1, 50);
                assert_eq!(result.2, System::block_number());
            }
        })
    }

    #[test]
    fn should_use_current_block_number_as_onchain_reolve_deadline_if_updated_amount_is_max() {
        ExtBuilder::build().execute_with(|| {   
            let transfer_func = get_transfer_func(account_key("Alice"), 35, 3);
            let cond_pay = ConditionalPay {
                pay_timestamp: 0,
                src: account_key("src"),
                dest: account_key("dest"),
                conditions: vec![get_condition(0)],
                transfer_func: transfer_func,
                resolve_deadline: 99999,
                resolve_timeout: 10,
            };

            // first resolving by vouched result
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: cond_pay.clone(),
                amount: 20,
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest,
            };
            let (pay_id_1, amount_1, resolve_deadline_1) =
                PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                    .unwrap();
            assert_eq!(pay_id_1, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount_1, 20);
            assert_eq!(resolve_deadline_1, System::block_number() + 10);

            // second resolving by conditions
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)],
            };

            let (pay_id_2, amount_2, resolve_deadline_2) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(account_key("Alice"), pay_request).unwrap();
            assert_eq!(pay_id_2, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount_2, 35);
            assert_eq!(resolve_deadline_2, System::block_number());
        })
    }

    fn test_resolve_payment_by_vouched_result(amount: u64) {
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
            amount: amount,
        };
        let vouched_cond_pay_result = VouchedCondPayResult {
            cond_pay_result: cond_pay_result,
            sig_of_src: sig_of_src,
            sig_of_dest: sig_of_dest,
        };
        let (_pay_id, _amount, _resolve_deadline) =
            PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result)
                .unwrap();
        assert_eq!(_pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
        assert_eq!(_amount, amount);
        assert_eq!(_resolve_deadline, System::block_number() + 10);
    }

    pub fn encode_conditional_pay(
        r#cond_pay: ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>,
    ) -> std::vec::Vec<u8> {
        let pay = r#cond_pay;
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
        
        return encoded;
    }

    pub fn get_condition(r#type: u8) -> Condition<H256> {
        if r#type == 0 {
            let condition_hash_lock = Condition {
                condition_type: ConditionType::HashLock,
                hash_lock: Some(H256::from_low_u64_be(1)),
                runtime_module_call_data: None,
                smart_contract_call_data: None,
            };
            return condition_hash_lock;
        } else if r#type == 1 {
            let boolean_args_query_finalization = BooleanArgsQueryFinalization {
                session_id: H256::from_low_u64_be(1),
                query_data: 1,
            };
            let boolean_args_query_outcome = BooleanArgsQueryOutcome {
                session_id: H256::from_low_u64_be(1),
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
                session_id: H256::from_low_u64_be(1),
                query_data: 1,
            };
            let boolean_args_query_outcome = BooleanArgsQueryOutcome {
                session_id: H256::from_low_u64_be(1),
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
                session_id: H256::from_low_u64_be(1),
                query_data: 1,
            };
            let numeric_args_query_outcome = NumericArgsQueryOutcome {
                session_id: H256::from_low_u64_be(1),
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
                session_id: H256::from_low_u64_be(1),
                query_data: 1,
            };
            let numeric_args_query_outcome = NumericArgsQueryOutcome {
                session_id: H256::from_low_u64_be(1),
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

    pub fn get_transfer_func(
        r#account: AccountId,
        r#amount: Balance,
        r#type: u8,
    ) -> TransferFunction<AccountId, Balance> {
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
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount,
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair,
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::BooleanCircut,
                max_transfer: token_transfer,
            };
            return transfer_func;
        } else if r#type == 3 {
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
                logic_type: TransferFunctionType::NumericAdd,
                max_transfer: token_transfer,
            };
            return transfer_func;
        } else if r#type == 4 {
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
                logic_type: TransferFunctionType::NumericMax,
                max_transfer: token_transfer,
            };
            return transfer_func;
        } else {
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
                logic_type: TransferFunctionType::NumericMin,
                max_transfer: token_transfer,
            };
            return transfer_func;
        }
    }
}