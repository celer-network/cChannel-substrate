use codec::{Encode, Decode};
use frame_support::{ensure};
use pallet_timestamp;
use frame_system::{self as system};
use sp_runtime::{ModuleId, DispatchError, RuntimeDebug};
use sp_runtime::traits::{Hash, AccountIdConversion, Zero};
use super::{
    Trait, Module, Error, BalanceOf, 
};
use crate::mock_condition::{MockCondition};
use crate::pay_registry::{PayRegistry};

pub const RESOLVER_ID: ModuleId = ModuleId(*b"Resolver");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum ConditionType {
    HashLock,
    DeployedContract,
    VirtualContract,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Condition<AccountId, Hash> {
    pub condition_type: ConditionType,
    pub hash_lock: Option<Hash>,
    pub deployed_contract_address: Option<AccountId>,
    pub virtual_contract_address: Option<Hash>,
    pub args_query_finalzation: Option<u8>,
    pub args_query_outcome: Option<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum TransferFunctionType {
    BooleanAnd, 
    BooleanOr, 
    BooleanCircut, 
    NumericAdd, 
    NumericMax,
    NumericMin,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum TokenType {
    INVALID,
    CELER,
    ERC20,
}

// Currently native token is only uspported.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenInfo  {
    pub token_type: TokenType
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct AccountAmtPair<AccountId, Balance> {
    pub account: Option<AccountId>,
    pub amt: Balance,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenTransfer<AccountId, Balance> {
    pub token: TokenInfo,
    pub receiver: AccountAmtPair<AccountId, Balance>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TransferFunction<AccountId, Balance> {
    pub logic_type: TransferFunctionType,
    pub max_transfer: TokenTransfer<AccountId, Balance>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct ConditionalPay<Moment, BlockNumber, AccountId, Hash, Balance> {
    pub pay_timestamp: Moment,
    pub src: AccountId,
    pub dest: AccountId,
    pub conditions: Vec<Condition<AccountId, Hash>>,
    pub transfer_func: TransferFunction<AccountId, Balance>,
    pub resolve_deadline: BlockNumber,
    pub resolve_timeout: BlockNumber,
}

pub type ConditionalPayOf<T> = ConditionalPay<
    <T as pallet_timestamp::Trait>::Moment,
    <T as system::Trait>::BlockNumber, 
    <T as system::Trait>::AccountId, 
    <T as system::Trait>::Hash, 
    BalanceOf<T>
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct ResolvePaymentConditionsRequest<Moment, BlockNumber, AccountId, Hash, Balance> {
    pub cond_pay: ConditionalPay<Moment, BlockNumber, AccountId, Hash, Balance>,
    pub hash_preimages: Vec<Hash>,
}

pub type ResolvePaymentConditionsRequestOf<T> = ResolvePaymentConditionsRequest<
    <T as pallet_timestamp::Trait>::Moment,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    <T as system::Trait>::Hash,
    BalanceOf<T>,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CondPayResult<Moment, BlockNumber, AccountId, Hash, Balance> {
    pub cond_pay: ConditionalPay<Moment, BlockNumber, AccountId, Hash, Balance>,
    pub amount: Balance,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct VouchedCondPayResult<Moment, BlockNumber, AccountId, Hash, Balance, Signature> {
    pub cond_pay_result: CondPayResult<Moment, BlockNumber, AccountId, Hash, Balance>,
    pub sig_of_src: Signature,
    pub sig_of_dest: Signature,
}

pub type VouchedCondPayResultOf<T> = VouchedCondPayResult<
    <T as pallet_timestamp::Trait>::Moment,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    <T as system::Trait>::Hash,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;


pub struct PayResolver<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> PayResolver<T> {

    // Resolve a payment by onchain getting its condition outcomes
    pub fn resolve_payment_by_conditions(
        resolve_pay_request: ResolvePaymentConditionsRequestOf<T>
    ) -> Result<(T::Hash, BalanceOf<T>, T::BlockNumber), DispatchError> {
        let pay = resolve_pay_request.cond_pay;

        let mut amount: BalanceOf<T> = Zero::zero();
        let func_type = pay.transfer_func.logic_type.clone();
        if func_type == TransferFunctionType::BooleanAnd {
            amount = calculate_boolean_and_payment::<T>(pay.clone(), resolve_pay_request.hash_preimages)?;
        } else if func_type == TransferFunctionType::BooleanOr {
            amount = calculate_boolean_or_payment::<T>(pay.clone(), resolve_pay_request.hash_preimages)?;
        } else if is_numeric_logic::<T>(func_type.clone()) {
            amount = calculate_numeric_logic_payment::<T>(pay.clone(), resolve_pay_request.hash_preimages, func_type.clone())?;
        } else {
            Err(Error::<T>::Error)?
        }

        let encoded = encode_conditional_pay::<T>(pay.clone());
        let pay_hash = T::Hashing::hash(&encoded);
        return resolve_payment::<T>(pay, pay_hash, amount);
    }

    // Resolve a payment by submitting an offchain vouched result
    pub fn resolve_payment_vouched_result(
        vouched_pay_result: VouchedCondPayResultOf<T>
    ) -> Result<(T::Hash, BalanceOf<T>, T::BlockNumber), DispatchError> {
        let pay_result = vouched_pay_result.cond_pay_result;
        let pay = pay_result.cond_pay;

        ensure!(
            pay_result.amount <= pay.transfer_func.max_transfer.receiver.amt,
            "Exceed max transfer amount"
        );
        // Check signatures
        let encoded = encode_conditional_pay::<T>(pay.clone());
        Module::<T>::check_single_signature(vouched_pay_result.sig_of_src, &encoded, pay.src.clone())?;
        Module::<T>::check_single_signature(vouched_pay_result.sig_of_dest, &encoded, pay.dest.clone())?;

        let pay_hash = T::Hashing::hash(&encoded);
        return resolve_payment::<T>(pay, pay_hash, pay_result.amount);
    } 

}

fn resolve_payment<T: Trait>(
    pay: ConditionalPayOf<T>,
    pay_hash: T::Hash,
    amount: BalanceOf<T>
) -> Result<(T::Hash, BalanceOf<T>, T::BlockNumber), DispatchError> {
    let block_number = <frame_system::Module<T>>::block_number();
    ensure!(
        block_number <= pay.resolve_deadline,
        "Passed pay resolve deadline in cond_pay msg"
    );

    let pay_id = calculate_pay_id::<T>(pay_hash);
    let pay_info: (BalanceOf<T>, T::BlockNumber) = PayRegistry::<T>::get_pay_info(pay_id)?;
    let current_amt = pay_info.0;
    let current_deadline = pay_info.1;

    let zero_blocknumber: T::BlockNumber = Zero::zero();
    // Should never resolve a pay before or not rearching on-chain resolve deadline.
    ensure!(
        current_deadline == zero_blocknumber || block_number <= current_deadline,
        "Passed onchain resolve pay deadline"
    );

    if current_deadline > zero_blocknumber {
        // current_deadline > 0 implies that this pay ha been updated
        // payment amount must be monotone increasing
        ensure!(amount > current_amt, "New amount is not larger");

        if amount == pay.transfer_func.max_transfer.receiver.amt {
            // set resolve deadline = current block number if amount = max
            PayRegistry::<T>::set_pay_info(pay_hash, amount, block_number)?;
            return Ok((pay_id, amount, block_number));
        } else {
            // should not update the onchain resolve deadline if not max amount
            PayRegistry::<T>::set_pay_amount(pay_hash, amount)?;
            return Ok((pay_id, amount, current_deadline));
        }
    } else {
        let new_deadline: T::BlockNumber;

        if amount == pay.transfer_func.max_transfer.receiver.amt {
            new_deadline = block_number.clone();
        } else {
            let timeout = block_number + pay.resolve_timeout;
            if timeout < pay.resolve_deadline {
                new_deadline = block_number + pay.resolve_timeout;
            } else {
                new_deadline = pay.resolve_deadline;
            }
            // 0 is reserved for unresolved status of a payment
            ensure!(
                new_deadline > zero_blocknumber,
                "New resolve deadline is 0"
            );
        }

        PayRegistry::<T>::set_pay_info(pay_hash, amount, new_deadline)?;
        return Ok((pay_id, amount, new_deadline));
    }
}

// Calculate the result amount of BooleanAnd payment
fn calculate_boolean_and_payment<T: Trait>(
    pay: ConditionalPayOf<T>,
    preimages: Vec<T::Hash>
) -> Result<BalanceOf<T>, DispatchError> {
    let mut j: usize = 0;

    let pay_conditions_len = pay.conditions.len();
    let mut has_false_contract_cond: bool = false;
    for i in 0..pay_conditions_len {
        let cond = pay.conditions[i].clone();
        if cond.condition_type == ConditionType::HashLock{
            let hash_lock = match cond.hash_lock {
                Some(lock) => lock,
                None => Err(Error::<T>::HashLockNotExist)?
            };
            
            ensure!(preimages[j] == hash_lock, "Wrong preimage");
            j = j + 1;
        } else if cond.condition_type == ConditionType::DeployedContract || cond.condition_type == ConditionType::VirtualContract {
            let addr: T::AccountId = match get_cond_address::<T>(cond.clone()){
                Some(_addr) => _addr,
                None => Err(Error::<T>::ConditionAddressNotExist)?
            };
            let is_finalized = MockCondition::<T>::is_finalized(&addr, cond.args_query_finalzation);
            ensure!(is_finalized == true, "Condition is not finalized");

            let outcome = MockCondition::<T>::get_outcome(&addr, cond.args_query_outcome);
            if outcome == false {
                has_false_contract_cond = true;
            }
        } else {
            Err(Error::<T>::Error)?
        }
    }

    if has_false_contract_cond == true {
        let zero_balance: BalanceOf<T> = Zero::zero();
        return Ok(zero_balance);
    } else {
        return Ok(pay.transfer_func.max_transfer.receiver.amt);
    }
}

// Calculate the result amount of BooleanOr payment
fn calculate_boolean_or_payment<T: Trait>(
    pay: ConditionalPayOf<T>,
    preimages: Vec<T::Hash>
) -> Result<BalanceOf<T>, DispatchError> {
    let mut j: usize = 0;
    let condition_len = pay.conditions.len();

    // Whether there are any contract based conditions, i.e. DEPLOYED_CONTRACT or VIRTUAL_CONTRACT
    let mut has_contract_cond = false;
    let mut has_true_contract_cond = false;
    for i in 0..condition_len {
        let cond = pay.conditions[i].clone();
        if cond.condition_type == ConditionType::HashLock {
            let hash_lock = match cond.hash_lock {
                Some(lock) => lock,
                None => Err(Error::<T>::HashLockNotExist)?
            };
            ensure!(preimages[j] == hash_lock, "Wrong preimage");
            j += 1;
        } else if cond.condition_type == ConditionType::DeployedContract || cond.condition_type == ConditionType::VirtualContract {
            let addr: T::AccountId = match get_cond_address::<T>(cond.clone()) {
                Some(_addr) => _addr,
                None => Err(Error::<T>::ConditionAddressNotExist)?
            };
            let is_finalized = MockCondition::<T>::is_finalized(&addr, cond.args_query_finalzation);
            ensure!(is_finalized == true, "Condition is not finalized");

            has_contract_cond = true;
            let outcome = MockCondition::<T>::get_outcome(&addr, cond.args_query_outcome);
            if outcome == true {
                has_true_contract_cond = true;
            }
        } else {
            Err(Error::<T>::Error)?
        }
    }

    if has_contract_cond == false || has_true_contract_cond == true {
        return Ok(pay.transfer_func.max_transfer.receiver.amt);
    } else {
        let zero_balance: BalanceOf<T> = Zero::zero();
        return Ok(zero_balance);
    }
}

// Calculate the result amount of numeric logic payment, including NUMERIC_ADD, NUMERIC_MAX and NUMERIC_MIN
fn calculate_numeric_logic_payment<T: Trait>(
    pay: ConditionalPayOf<T>,
    preimages: Vec<T::Hash>,
    func_type: TransferFunctionType
) -> Result<BalanceOf<T>, DispatchError> {
    let mut amount: BalanceOf<T> = <BalanceOf<T>>::zero();

    let mut j: usize = 0;
    let pay_conditions_len = pay.conditions.len();
    let mut has_contract_cond: bool = false;
    for i in 0..pay_conditions_len {
        let cond = pay.conditions[i].clone();
        if cond.condition_type == ConditionType::HashLock {
            let hash_lock = match cond.hash_lock {
                Some(lock) => lock,
                None => Err(Error::<T>::HashLockNotExist)?
            };
            ensure!(preimages[j] == hash_lock, "Wrong preimage");
            j = j + 1;
        } else if cond.condition_type == ConditionType::DeployedContract || cond.condition_type == ConditionType::VirtualContract {
            let addr = match get_cond_address::<T>(cond.clone()) {
                Some(_addr) => _addr,
                None => Err(Error::<T>::Error)?
            };

            let is_finalized: bool = MockCondition::<T>::get_outcome(&addr, cond.args_query_finalzation);
            ensure!(is_finalized == true, "Condition is not finalized");

            let outcome = MockCondition::<T>::get_numeric_outcome(&addr, cond.args_query_outcome);
            if func_type == TransferFunctionType::NumericAdd {
                amount = amount + outcome;
            } else if func_type == TransferFunctionType::NumericMax {
                if outcome > amount {
                    amount = outcome;
                }
            } else if func_type == TransferFunctionType::NumericMin {
                if has_contract_cond == true {
                    if outcome < amount {
                        amount = outcome;
                    }
                } else {
                    amount = outcome;
                }
            } else {
                Err(Error::<T>::Error)?
            }

            has_contract_cond = true;
        } else {
            Err(Error::<T>::Error)?
        }
    }

    if has_contract_cond == true {
        ensure!(amount <= pay.transfer_func.max_transfer.receiver.amt, "Exceed max transfer amount");
        return Ok(amount);
    } else {
        return Ok(pay.transfer_func.max_transfer.receiver.amt);
    }
}

// Get the contract address of the condition
fn get_cond_address<T: Trait>(
    cond: Condition<T::AccountId, T::Hash>
) -> Option<T::AccountId> {
    if cond.condition_type == ConditionType::DeployedContract {
        return cond.deployed_contract_address;
    //} else if cond.condition_type == ConditionType::VIRTUAL_CONTRACT {
        // Implment after implemted of VirtResolver
    } else {
        return None;
    }
}

fn is_numeric_logic<T: Trait>(
    func_type: TransferFunctionType
) -> bool {
    return func_type == TransferFunctionType::NumericAdd ||
        func_type == TransferFunctionType::NumericMax ||
        func_type == TransferFunctionType::NumericMin;
}

// Calculate pay id
pub fn calculate_pay_id<T: Trait>(
    pay_hash: T::Hash,
) -> T::Hash {
    let resolver_account = account_id::<T>();
    let mut encoded = pay_hash.encode();
    encoded.extend(resolver_account.encode());
    let pay_id = T::Hashing::hash(&encoded);
    return pay_id;
} 

// The accountID of the PayResolver.
fn account_id<T: Trait>() -> T::AccountId {
    RESOLVER_ID.into_account()
}

pub fn encode_conditional_pay<T: Trait>(
    pay: ConditionalPayOf<T>
) -> Vec<u8> {
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
    let mut hash_lock_len: usize;
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

#[cfg(test)]
pub mod tests {
    use crate::mock::*;
    use super::*;
    use sp_runtime::DispatchError;
    use sp_core::{H256, hashing, Pair};

    #[test]
    fn test_pass_resolve_payment_by_conditions_boolean_and_condition_true() {
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
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };
  
            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 10);
            assert_eq!(resolve_deadline, System::block_number());
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_boolean_and_condition_false() {
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
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 0);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_conditions_boolean_or_conditions_true() {
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
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            let (pay_id, amount, resolve_deadline) =
                PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 30);
            assert_eq!(resolve_deadline, System::block_number());
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_vouched_result() {
        ExtBuilder::build().execute_with(|| {
            test_resolve_payment_by_vouched_result(20);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_vouched_result_pass_when_new_result_is_larger_than_old_result_25() {
        ExtBuilder::build().execute_with(|| {
            test_resolve_payment_by_vouched_result(25);
        })
    }

    #[test]
    fn test_pass_resolve_payment_by_vouched_result_pass_when_new_result_is_larger_than_old_result_35() {
        ExtBuilder::build().execute_with(|| {
            test_resolve_payment_by_vouched_result(35);
        })
    }

    #[test]
    fn test_fail_resolve_payment_by_vouched_result_pass_when_new_result_is_smaller_than_old_result() {
        ExtBuilder::build().execute_with(|| {
            test_resolve_payment_by_vouched_result(30);
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
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: shared_pay,
                amount: 200
            };
           let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest
            };
        
            let err = PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result).unwrap_err();
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
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            System::set_block_number(3);
            let err = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Passed pay resolve deadline in cond_pay msg"));
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
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: shared_pay,
                amount: 20
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest
            };
            System::set_block_number(3);
            let err = PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result).unwrap_err();
            assert_eq!(err, DispatchError::Other("Passed pay resolve deadline in cond_pay msg"));
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
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: shared_pay,
                amount: 30
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest
            };

            let err = PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result).unwrap_err();
            assert_eq!(err, DispatchError::Other("Passed onchain resolve pay deadline"));
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
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let sig_of_src = account_pair("src").sign(&encoded_cond_pay);
            let sig_of_dest = account_pair("dest").sign(&encoded_cond_pay);
            let cond_pay_result = CondPayResult {
                cond_pay: shared_pay.clone(),
                amount: 20
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest
            };
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: shared_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            let _ = PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result).unwrap();
            System::set_block_number(System::block_number() + 11);

            let err = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap_err();
            assert_eq!(err, DispatchError::Other("Passed onchain resolve pay deadline"));
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
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1), H256::from_low_u64_be(0)]
            };

            let err = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap_err();
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
                resolve_timeout: 10
            };
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };
            
            let (pay_id, amount, resolve_deadline) 
                = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                resolve_timeout: 10
            };
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            let (pay_id, amount, resolve_deadline)
                = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                resolve_timeout: 10
            };
            let encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
            let pay_hash: H256 = hashing::blake2_256(&encoded_cond_pay).into();
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            let (pay_id, amount, resolve_deadline)
                = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
            assert_eq!(pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount, 10);
            assert_eq!(resolve_deadline, System::block_number() + 10);
        })
    }

    #[test]
    fn should_resolve_pay_using_max_amount_with_any_transfer_logic_as_long_as_there_are_no_contract_conditions() {
        ExtBuilder::build().execute_with(|| {
            let mut transfer_func: TransferFunction<AccountId, BlockNumber>;
            let mut cond_pay: ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>;
            let mut encoded_cond_pay: Vec<u8>;
            let mut pay_hash: H256;
            let mut pay_request: ResolvePaymentConditionsRequest<Moment, BlockNumber, AccountId, H256, Balance>;
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
                   resolve_timeout: 10
                };
                encoded_cond_pay = encode_conditional_pay(cond_pay.clone());
                pay_hash = hashing::blake2_256(&encoded_cond_pay).into();
                pay_request = ResolvePaymentConditionsRequest {
                    cond_pay: cond_pay,
                    hash_preimages: vec![H256::from_low_u64_be(1)]
                };

                result = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
                amount: 20
            };
            let vouched_cond_pay_result = VouchedCondPayResult {
                cond_pay_result: cond_pay_result,
                sig_of_src: sig_of_src,
                sig_of_dest: sig_of_dest
            };
            let (pay_id_1, amount_1, resolve_deadline_1) 
                = PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result).unwrap();
            assert_eq!(pay_id_1, calculate_pay_id::<TestRuntime>(pay_hash));
            assert_eq!(amount_1, 20);
            assert_eq!(resolve_deadline_1, System::block_number() + 10);

            // second resolving by conditions
            let pay_request = ResolvePaymentConditionsRequest {
                cond_pay: cond_pay,
                hash_preimages: vec![H256::from_low_u64_be(1)]
            };

            let (pay_id_2, amount_2, resolve_deadline_2)
                = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
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
            amount: amount
        };
       let vouched_cond_pay_result = VouchedCondPayResult {
            cond_pay_result: cond_pay_result,
            sig_of_src: sig_of_src,
            sig_of_dest: sig_of_dest
        };
        let (_pay_id, _amount, _resolve_deadline) 
             = PayResolver::<TestRuntime>::resolve_payment_vouched_result(vouched_cond_pay_result).unwrap();
        assert_eq!(_pay_id, calculate_pay_id::<TestRuntime>(pay_hash));
        assert_eq!(_amount, amount);
        assert_eq!(_resolve_deadline, System::block_number() + 10);
    }

    pub fn encode_conditional_pay(
        r#cond_pay: ConditionalPay<Moment, BlockNumber, AccountId, H256, Balance>
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
        let mut hash_lock_len: usize;
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

    pub fn get_condition(r#type: u8) 
        -> Condition<AccountId, H256>{
        if r#type == 0 {
            let condition_hash_lock = Condition {
                condition_type: ConditionType::HashLock,
                hash_lock: Some(H256::from_low_u64_be(1)),
                deployed_contract_address: None,
                virtual_contract_address: None,
                args_query_finalzation: None,
                args_query_outcome: None
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
        } else if r#type == 3{
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
        r#type: u8
    ) -> TransferFunction<AccountId, Balance> {
        if r#type == 0 {
            let token_info = TokenInfo {
                token_type: TokenType::CELER
            };
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::BooleanAnd,
                max_transfer: token_transfer
            };
            return transfer_func;
        } else if r#type == 1 {
            let token_info = TokenInfo {
                token_type: TokenType::CELER
            };
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::BooleanOr,
                max_transfer: token_transfer
            };
            return transfer_func;
        } else if r#type == 2 {
            let token_info = TokenInfo {
                token_type: TokenType::CELER
            };
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::BooleanCircut,
                max_transfer: token_transfer
            };
            return transfer_func;
        } else if r#type == 3 {
            let token_info = TokenInfo {
                token_type: TokenType::CELER
            };
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::NumericAdd,
                max_transfer: token_transfer
            };
            return transfer_func;
        } else if r#type == 4 {
            let token_info = TokenInfo {
                token_type: TokenType::CELER
            };
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::NumericMax,
                max_transfer: token_transfer
            };
            return transfer_func;
        } else {
            let token_info = TokenInfo {
                token_type: TokenType::CELER
            };
            let account_amt_pair = AccountAmtPair {
                account: Some(r#account),
                amt: r#amount
            };
            let token_transfer = TokenTransfer {
                token: token_info,
                receiver: account_amt_pair
            };
            let transfer_func = TransferFunction {
                logic_type: TransferFunctionType::NumericMin,
                max_transfer: token_transfer
            };
            return transfer_func;
        }
    }

} 
   