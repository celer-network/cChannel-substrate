use super::{BalanceOf, Error, Module as CelerPayModule, RawEvent};
use crate::traits::Trait;
use crate::pay_registry::PayRegistry;
use codec::{Decode, Encode};
use frame_support::{ensure};
use frame_system::{self as system};
use pallet_timestamp;
use sp_runtime::traits::{CheckedAdd, Hash, Zero};
use sp_runtime::{ModuleId, RuntimeDebug, DispatchError};
use sp_std::vec::Vec;

pub const PAY_RESOLVER_ID: ModuleId = ModuleId(*b"Resolver");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum ConditionType {
    HashLock,
    RuntimeModule,
    SmartContract,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct RuntimeModuleCallData {
    pub registration_num: u32, // number of registered celer app into runtime_module_condition_caller file
    pub args_query_finalization: Vec<u8>, // the encoded query finalization of runtime module condition
    pub args_query_outcome: Vec<u8>, // the encoded query outcome of runtime module condition
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SmartContractCallData<Hash> {
    pub virt_addr: Hash, // virtual address which is mapped to deployed smart contract address
    pub is_finalized_call_gas_limit: u64, 
    pub is_finalized_call_input_data: Vec<u8>,
    pub get_outcome_call_gas_limit: u64,
    pub get_outcome_call_input_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Condition<Hash> {
    pub condition_type: ConditionType,
    pub hash_lock: Option<Hash>,
    pub runtime_module_call_data: Option<RuntimeModuleCallData>,
    pub smart_contract_call_data: Option<SmartContractCallData<Hash>>,
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

// Currently native token is only supoorted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum TokenType {
    Invalid,
    Celer, // native token. If Kusama network,change from Celer to Ksm.
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenInfo {
    pub token_type: TokenType,
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
    pub conditions: Vec<Condition<Hash>>,
    pub transfer_func: TransferFunction<AccountId, Balance>,
    pub resolve_deadline: BlockNumber,
    pub resolve_timeout: BlockNumber,
}

pub type ConditionalPayOf<T> = ConditionalPay<
    <T as pallet_timestamp::Trait>::Moment,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    <T as system::Trait>::Hash,
    BalanceOf<T>,
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
        caller: T::AccountId,
        resolve_pay_request: ResolvePaymentConditionsRequestOf<T>,
    ) -> Result<(T::Hash, BalanceOf<T>, T::BlockNumber), DispatchError> {
        let pay = resolve_pay_request.cond_pay;

        let mut amount: BalanceOf<T> = Zero::zero();
        let func_type = pay.transfer_func.logic_type.clone();
        if func_type == TransferFunctionType::BooleanAnd {
            amount = calculate_boolean_and_payment::<T>(
                caller,
                pay.clone(),
                resolve_pay_request.hash_preimages,
            )?;
        } else if func_type == TransferFunctionType::BooleanOr {
            amount = calculate_boolean_or_payment::<T>(
                caller,
                pay.clone(), 
                resolve_pay_request.hash_preimages
            )?;
        } else if is_numeric_logic::<T>(func_type.clone()) {
            amount = calculate_numeric_logic_payment::<T>(
                caller,
                pay.clone(),
                resolve_pay_request.hash_preimages,
                func_type.clone(),
            )?;
        } else {
            Err(Error::<T>::Error)?
        }

        let encoded = encode_conditional_pay::<T>(pay.clone());
        let pay_hash = T::Hashing::hash(&encoded);
        return resolve_payment::<T>(pay, pay_hash, amount);
    }

    // Resolve a payment by submitting an offchain vouched result
    pub fn resolve_payment_vouched_result(
        vouched_pay_result: VouchedCondPayResultOf<T>,
    ) -> Result<(T::Hash, BalanceOf<T>, T::BlockNumber), DispatchError> {
        let pay_result = vouched_pay_result.cond_pay_result;
        let pay = pay_result.cond_pay;

        ensure!(
            pay_result.amount <= pay.transfer_func.max_transfer.receiver.amt,
            "Exceed max transfer amount"
        );

        // Check signatures
        let encoded = encode_conditional_pay::<T>(pay.clone());
        CelerPayModule::<T>::check_single_signature(
            vouched_pay_result.sig_of_src,
            &encoded,
            pay.src.clone(),
        )?;
        CelerPayModule::<T>::check_single_signature(
            vouched_pay_result.sig_of_dest,
            &encoded,
            pay.dest.clone(),
        )?;

        let pay_hash = T::Hashing::hash(&encoded);
        return resolve_payment::<T>(pay, pay_hash, pay_result.amount);
    }
}

fn resolve_payment<T: Trait>(
    pay: ConditionalPayOf<T>,
    pay_hash: T::Hash,
    amount: BalanceOf<T>,
) -> Result<(T::Hash, BalanceOf<T>, T::BlockNumber), DispatchError> {
    let block_number = frame_system::Module::<T>::block_number();
    ensure!(
        block_number <= pay.resolve_deadline,
        "Passed pay resolve deadline in cond_pay msg"
    );

    let pay_id = calculate_pay_id::<T>(pay_hash);
    let pay_info: (BalanceOf<T>, T::BlockNumber) = PayRegistry::<T>::get_pay_info(pay_id)?;
    let current_amt = pay_info.0;
    let current_deadline = pay_info.1;

    // Should never resolve a pay before or not rearching on-chain resolve deadline.
    ensure!(
        current_deadline.is_zero() || block_number <= current_deadline,
        "Passed onchain resolve pay deadline"
    );

    if current_deadline > Zero::zero() {
        // current_deadline > 0 implies that this pay ha been updated
        // payment amount must be monotone increasing
        ensure!(amount > current_amt, "New amount is not larger");

        if amount == pay.transfer_func.max_transfer.receiver.amt {
            // set resolve deadline = current block number if amount = max
            PayRegistry::<T>::set_pay_info(pay_hash, amount, block_number)?;
            
            // Emit ResolvePayment event
            CelerPayModule::<T>::deposit_event(RawEvent::ResolvePayment(
                pay_id,
                amount,
                block_number
            ));
            return Ok((pay_id, amount, block_number));
        } else {
            // should not update the onchain resolve deadline if not max amount
            PayRegistry::<T>::set_pay_amount(pay_hash, amount)?;
            
            // Emit ResolvePayment event
            CelerPayModule::<T>::deposit_event(RawEvent::ResolvePayment(
                pay_id,
                amount,
                current_deadline
            ));
            return Ok((pay_id, amount, current_deadline));
        }
    } else {
        let new_deadline: T::BlockNumber;
        if amount == pay.transfer_func.max_transfer.receiver.amt {
            new_deadline = block_number.clone();
        } else {
            let timeout = block_number.checked_add(&pay.resolve_timeout).ok_or(Error::<T>::OverFlow)?;
            if timeout < pay.resolve_deadline {
                new_deadline = block_number.checked_add(&pay.resolve_timeout).ok_or(Error::<T>::OverFlow)?;
            } else {
                new_deadline = pay.resolve_deadline;
            }
            // 0 is reserved for unresolved status of a payment
            ensure!(new_deadline > Zero::zero(), "New resolve deadline is 0");
        }

        PayRegistry::<T>::set_pay_info(pay_hash, amount, new_deadline)?;
        
        // Emit ResolvePayment event
        CelerPayModule::<T>::deposit_event(RawEvent::ResolvePayment(
            pay_id,
            amount,
            new_deadline
        ));
        return Ok((pay_id, amount, new_deadline));
    }
}

// Calculate the result amount of BooleanAnd payment
fn calculate_boolean_and_payment<T: Trait>(
    caller: T::AccountId,
    pay: ConditionalPayOf<T>,
    preimages: Vec<T::Hash>,
) -> Result<BalanceOf<T>, DispatchError> {
    let mut j: usize = 0;
    let mut has_false_contract_cond: bool = false;
    for i in 0..pay.conditions.len() {
        let cond = pay.conditions[i].clone();
        if cond.condition_type == ConditionType::HashLock {
            let hash_lock = match cond.hash_lock {
                Some(lock) => lock,
                None => Err(Error::<T>::HashLockNotExist)?,
            };
            ensure!(preimages[j] == hash_lock, "Wrong preimage");
            j = j + 1;
        } else if cond.condition_type == ConditionType::RuntimeModule {
            let boolean_module_call_data = match cond.runtime_module_call_data {
                Some(call_data) => call_data,
                None => Err(Error::<T>::BooleanModuleCallDataNotExist)?,
            };
            
            // call is_finalized and get_outcome function of boolean runtime module condition
            let (is_finalized, encoded_outcome) = runtime_module_condition_caller::Module::<T>::call_runtime_module_condition(
                boolean_module_call_data.registration_num,
                boolean_module_call_data.args_query_finalization,
                boolean_module_call_data.args_query_outcome
            )?;
            let outcome = bool::decode(&mut &encoded_outcome[..]).map_err(|_| Error::<T>::MustBeDecodable)?;

            ensure!(
                is_finalized == true,
                "Condition is not finalized"
            );

            if outcome == false {
                has_false_contract_cond = true;
            }
        } else if cond.condition_type == ConditionType::SmartContract {
            let smart_contract_call_data = match cond.smart_contract_call_data {
                Some(call_data) => call_data,
                None => Err(Error::<T>::SmartContractCallDataNotExist)?,
            };

            // call is_finalized of boolean outcome smart contract
            let is_finalized_result = celer_contracts::Module::<T>::call_contract_condition(
                caller.clone(),
                smart_contract_call_data.virt_addr,
                smart_contract_call_data.is_finalized_call_gas_limit,
                smart_contract_call_data.is_finalized_call_input_data,
            )?;
            let is_finalized: bool = bool::decode(&mut &is_finalized_result[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
            ensure!(
                is_finalized == true,
                "Condition is not finalized"
            );

            // call get_outcome of boolean outcome smart contract
            let get_outcome_result = celer_contracts::Module::<T>::call_contract_condition(
                caller.clone(),
                smart_contract_call_data.virt_addr,
                smart_contract_call_data.get_outcome_call_gas_limit,
                smart_contract_call_data.get_outcome_call_input_data,
            )?;
            let outcome: bool = bool::decode(&mut &get_outcome_result[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
            if outcome == false {
                has_false_contract_cond = true;
            }
        } else {
            Err(Error::<T>::Error)?
        }
    }

    if has_false_contract_cond == true {
        return Ok(Zero::zero());
    } else {
        return Ok(pay.transfer_func.max_transfer.receiver.amt);
    }
}

// Calculate the result amount of BooleanOr payment
fn calculate_boolean_or_payment<T: Trait>(
    caller: T::AccountId,
    pay: ConditionalPayOf<T>,
    preimages: Vec<T::Hash>,
) -> Result<BalanceOf<T>, DispatchError> {
    let mut j: usize = 0;
    // Whether there are any smart contract or runtime module based conditions
    let mut has_contract_cond = false;
    let mut has_true_contract_cond = false;
    for i in 0..pay.conditions.len() {
        let cond = pay.conditions[i].clone();
        if cond.condition_type == ConditionType::HashLock {
            let hash_lock = match cond.hash_lock {
                Some(lock) => lock,
                None => Err(Error::<T>::HashLockNotExist)?,
            };
            ensure!(preimages[j] == hash_lock, "Wrong preimage");
            j += 1;
        } else if cond.condition_type == ConditionType::RuntimeModule {
            let boolean_module_call_data = match cond.runtime_module_call_data {
                Some(call_data) => call_data,
                None => Err(Error::<T>::BooleanModuleCallDataNotExist)?,
            };

            // call is_finalized and get_outcome function of boolean runtime module condition
            let (is_finalized, encoded_outcome) = runtime_module_condition_caller::Module::<T>::call_runtime_module_condition(
                boolean_module_call_data.registration_num,
                boolean_module_call_data.args_query_finalization,
                boolean_module_call_data.args_query_outcome
            )?;
            let outcome = bool::decode(&mut &encoded_outcome[..]).map_err(|_| Error::<T>::MustBeDecodable)?;

            ensure!(
                is_finalized == true,
                "Condition is not finalized"
            );
            has_contract_cond = true;

            if outcome == true {
                has_true_contract_cond = true;
            }
        } else if cond.condition_type == ConditionType::SmartContract {
            let smart_contract_call_data = match cond.smart_contract_call_data {
                Some(call_data) => call_data,
                None => Err(Error::<T>::SmartContractCallDataNotExist)?,
            };

            // call is_finalized of boolean outcome smart contract
            let is_finalized_result = celer_contracts::Module::<T>::call_contract_condition(
                caller.clone(),
                smart_contract_call_data.virt_addr,
                smart_contract_call_data.is_finalized_call_gas_limit,
                smart_contract_call_data.is_finalized_call_input_data,
            )?;
            let is_finalized: bool = bool::decode(&mut &is_finalized_result[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
            ensure!(
                is_finalized == true,
                "Condition is not finalized"
            );
            has_contract_cond = true;

            // call get_outcome of boolean outcome smart contract
            let get_outcome_result = celer_contracts::Module::<T>::call_contract_condition(
                caller.clone(),
                smart_contract_call_data.virt_addr,
                smart_contract_call_data.get_outcome_call_gas_limit,
                smart_contract_call_data.get_outcome_call_input_data,
            )?;
            let outcome: bool = bool::decode(&mut &get_outcome_result[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
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
        return Ok(Zero::zero());
    }
}

// Calculate the result amount of numeric logic payment, including NUMERIC_ADD, NUMERIC_MAX and NUMERIC_MIN
fn calculate_numeric_logic_payment<T: Trait>(
    caller: T::AccountId,
    pay: ConditionalPayOf<T>,
    preimages: Vec<T::Hash>,
    func_type: TransferFunctionType,
) -> Result<BalanceOf<T>, DispatchError> {
    let mut amount: BalanceOf<T> = <BalanceOf<T>>::zero();
    let mut j: usize = 0;
    let mut has_contract_cond: bool = false;
    for i in 0..pay.conditions.len() {
        let cond = pay.conditions[i].clone();
        if cond.condition_type == ConditionType::HashLock {
            let hash_lock = match cond.hash_lock {
                Some(lock) => lock,
                None => Err(Error::<T>::HashLockNotExist)?,
            };
            ensure!(preimages[j] == hash_lock, "Wrong preimage");
            j = j + 1;
        } else if cond.condition_type == ConditionType::RuntimeModule {
            let numeric_module_call_data = match cond.runtime_module_call_data {
                Some(call_data) => call_data,
                None => Err(Error::<T>::NumericModuleCallDataNotExist)?,
            };

            // call is_finalized and get_outcome function of boolean runtime module condition
            let (is_finalized, encoded_outcome) = runtime_module_condition_caller::Module::<T>::call_runtime_module_condition(
                numeric_module_call_data.registration_num,
                numeric_module_call_data.args_query_finalization,
                numeric_module_call_data.args_query_outcome
            )?;
            let outcome: BalanceOf<T> = match u32::decode(&mut &encoded_outcome[..]) {
                Ok(_outcome) => _outcome.into(),
                Err(_) => Err(Error::<T>::MustBeDecodable)?,
            };
            
            ensure!(
                is_finalized == true, 
                "Condition is not finalized"
            );
            amount = calculate_numeric_amount::<T>(amount, func_type.clone(), outcome, has_contract_cond)?;
            has_contract_cond = true;
        } else if cond.condition_type == ConditionType::SmartContract {
            let smart_contract_call_data = match cond.smart_contract_call_data {
                Some(call_data) => call_data,
                None => Err(Error::<T>::SmartContractCallDataNotExist)?,
            };

            // call is_finalized of numeric outcome smart contract
            let is_finalized_result = celer_contracts::Module::<T>::call_contract_condition(
                caller.clone(),
                smart_contract_call_data.virt_addr,
                smart_contract_call_data.is_finalized_call_gas_limit,
                smart_contract_call_data.is_finalized_call_input_data,
            )?;
            let is_finalized: bool = bool::decode(&mut &is_finalized_result[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
            ensure!(is_finalized == true, "Condition is not finalized");

            // call get_outcome of numeric outcome smart contract
            let get_outcome_result = celer_contracts::Module::<T>::call_contract_condition(
                caller.clone(),
                smart_contract_call_data.virt_addr,
                smart_contract_call_data.get_outcome_call_gas_limit,
                smart_contract_call_data.get_outcome_call_input_data,
            )?;
            let outcome: BalanceOf<T> = match u32::decode(&mut &get_outcome_result[..]) {
                Ok(_outcome) => _outcome.into(),
                Err(_) => Err(Error::<T>::MustBeDecodable)?,
            };
            amount = calculate_numeric_amount::<T>(amount, func_type.clone(), outcome, has_contract_cond)?;
            has_contract_cond = true;
        } else {
            Err(Error::<T>::Error)?
        }
    }

    if has_contract_cond == true {
        ensure!(
            amount <= pay.transfer_func.max_transfer.receiver.amt,
            "Exceed max transfer amount"
        );
        return Ok(amount);
    } else {
        return Ok(pay.transfer_func.max_transfer.receiver.amt);
    }
}

fn is_numeric_logic<T: Trait>(func_type: TransferFunctionType) -> bool {
    return func_type == TransferFunctionType::NumericAdd
        || func_type == TransferFunctionType::NumericMax
        || func_type == TransferFunctionType::NumericMin;
}

fn calculate_numeric_amount<T: Trait>(
    amount: BalanceOf<T>, 
    func_type: TransferFunctionType,
    outcome: BalanceOf<T>,
    has_contract_cond: bool,
) -> Result<BalanceOf<T>, DispatchError> {
    if func_type == TransferFunctionType::NumericAdd {
        Ok(amount + outcome)
    } else if func_type == TransferFunctionType::NumericMax {
        if outcome > amount {
            Ok(outcome)
        } else {
            Ok(amount)
        }
    } else if func_type == TransferFunctionType::NumericMin {
        if has_contract_cond == true {
            if outcome < amount {
                Ok(outcome)
            } else {
                Ok(amount)
            }
        } else {
            Ok(outcome)
        }
    } else {
        Err(Error::<T>::Error)?
    }
}

// Calculate pay id
pub fn calculate_pay_id<T: Trait>(pay_hash: T::Hash) -> T::Hash {
    let pay_resolver_account = CelerPayModule::<T>::get_pay_resolver_id();
    let mut encoded = pay_hash.encode();
    encoded.extend(pay_resolver_account.encode());
    let pay_id = T::Hashing::hash(&encoded);
    return pay_id;
}

pub fn encode_conditional_pay<T: Trait>(pay: ConditionalPayOf<T>) -> Vec<u8> {
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

