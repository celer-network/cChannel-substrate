#[cfg(test)]
pub mod test_pay_resolver {
    use crate::mock::*;
    use sp_core::{hashing, Pair, H256};
    use sp_runtime::DispatchError;
    use crate::pay_resolver::*;
    use codec::{Decode, Encode};

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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap_err();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("Passed onchain resolve pay deadline")
            );
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_conditions_with_a_false_hashLock_condition() {
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
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1), H256::from_low_u64_be(0)],
            };

            let err =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap_err();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
            let mut cond_pay: ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>;
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
                    PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
        encoded.extend(pay.conditions.encode());
        encoded.extend(pay.transfer_func.logic_type.encode());
        encoded.extend(pay.transfer_func.max_transfer.token.token_type.encode());
        encoded.extend(pay.transfer_func.max_transfer.receiver.account.encode());
        encoded.extend(pay.transfer_func.max_transfer.receiver.amt.encode());
        encoded.extend(pay.resolve_deadline.encode());
        encoded.extend(pay.resolve_timeout.encode());
        let condition_len = pay.conditions.len();
        for i in 0..condition_len {
            encoded.extend(pay.conditions[i].clone().condition_type.encode());
            encoded.extend(pay.conditions[i].clone().hash_lock.encode());
            encoded.extend(pay.conditions[i].clone().deployed_contract_address.encode());
            encoded.extend(pay.conditions[i].clone().virtual_contract_address.encode());
            encoded.extend(pay.conditions[i].clone().args_query_finalzation.encode());
            encoded.extend(pay.conditions[i].clone().args_query_outcome.encode());
        }
        return encoded;
    }

    pub fn get_condition(r#type: u8) -> Condition<AccountId, H256> {
        if r#type == 0 {
            let condition_hash_lock = Condition {
                condition_type: ConditionType::HashLock,
                hash_lock: Some(H256::from_low_u64_be(1)),
                deployed_contract_address: None,
                virtual_contract_address: None,
                args_query_finalzation: None,
                args_query_outcome: None,
            };
            return condition_hash_lock;
        } else if r#type == 1 {
            let condition_deployed_true = Condition {
                condition_type: ConditionType::DeployedContract,
                hash_lock: None,
                deployed_contract_address: Some(account_key("deployed")),
                virtual_contract_address: None,
                args_query_finalzation: Some(1),
                args_query_outcome: Some(1),
            };
            return condition_deployed_true;
        } else if r#type == 2 {
            let condition_deployed_false = Condition {
                condition_type: ConditionType::DeployedContract,
                hash_lock: None,
                deployed_contract_address: Some(account_key("deployed")),
                virtual_contract_address: None,
                args_query_finalzation: Some(1),
                args_query_outcome: Some(0),
            };
            return condition_deployed_false;
        } else if r#type == 3 {
            let condition_deployed_numeric_10 = Condition {
                condition_type: ConditionType::DeployedContract,
                hash_lock: None,
                deployed_contract_address: Some(account_key("deployed")),
                virtual_contract_address: None,
                args_query_finalzation: Some(1),
                args_query_outcome: Some(10),
            };
            return condition_deployed_numeric_10;
        } else {
            let condition_deployed_numeric_25 = Condition {
                condition_type: ConditionType::DeployedContract,
                hash_lock: None,
                deployed_contract_address: Some(account_key("deployed")),
                virtual_contract_address: None,
                args_query_finalzation: Some(1),
                args_query_outcome: Some(25),
            };
            return condition_deployed_numeric_25;
        }
    }

    pub fn get_transfer_func(
        r#account: AccountId,
        r#amount: Balance,
        r#type: u8,
    ) -> TransferFunction<AccountId, Balance> {
        if r#type == 0 {
            let token_info = TokenInfo {
                token_type: TokenType::CELER,
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
                token_type: TokenType::CELER,
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
                token_type: TokenType::CELER,
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
                token_type: TokenType::CELER,
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
                token_type: TokenType::CELER,
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
                token_type: TokenType::CELER,
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