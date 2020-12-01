use super::*;
use traits::Trait;
use sp_std;

pub struct RuntimeModuleConditionCaller<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> RuntimeModuleConditionCaller<T> {
    pub fn call_runtime_module_condition(
        registration_num: u32,
        args_query_finalization: Vec<u8>,
        args_query_outcome: Vec<u8>,
    ) -> Result<(bool, Vec<u8>), DispatchError> {
        if registration_num == 0 { // MockNumerocCondition
            // is_finalized function return bool value
            let is_finalized: bool = match mock_numeric_condition::Module::<T>::is_finalized(args_query_finalization) {
                Ok(_is_finalized) => _is_finalized,
                Err(dispatch_error) => return Err(dispatch_error)?,
            };
            // get_outcome function return encoded u32 value
            let outcome: Vec<u8> = match mock_numeric_condition::Module::<T>::get_outcome(args_query_outcome) {
                Ok(_outcome) => _outcome,
                Err(dispatch_error) => return Err(dispatch_error)?,
            };
            return Ok((is_finalized, outcome));
        } else if registration_num == 1 { // MockBooleanCondition
            // is_finalized function return bool value
            let is_finalized: bool = match mock_boolean_condition::Module::<T>::is_finalized(args_query_finalization) {
                Ok(_is_finalized) => _is_finalized,
                Err(dispatch_error) => return Err(dispatch_error)?,
            };
            // get_outcome function return encoded bool value
            let outcome: Vec<u8> = match mock_boolean_condition::Module::<T>::get_outcome(args_query_outcome) {
                Ok(_outcome) => _outcome,
                Err(dispatch_error) => return Err(dispatch_error)?,
            };
            return Ok((is_finalized, outcome));
        } else {
            return Err(Error::<T>::ConditionNotRegistered)?;
        }
    }
}
