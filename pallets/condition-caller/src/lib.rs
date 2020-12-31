#![recursion_limit = "100"]
#![cfg_attr(not(feature = "std"), no_std)]

use frame_system as system;
use frame_support::{
    decl_module, decl_error,
};
use sp_std::vec::Vec;
use sp_runtime::DispatchError;

pub trait Trait: system::Trait + mock_numeric_condition::Trait + mock_boolean_condition::Trait {}
// ----------------------------^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
// Add Trait of your runtime module condition like above.

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;
    }
}

decl_error! {
    pub enum Error for Module<T: Trait> {
        // A runtime module condition is not regstered into runtime_module_condition_caller file
        RuntimeModuleConditionNotRegistered
    }
}

impl<T: Trait> Module<T> {
    pub fn call_runtime_module_condition(
        registration_num: u32,
        args_query_finalization: Vec<u8>,
        args_query_outcome: Vec<u8>,
    ) -> Result<(bool, Vec<u8>), DispatchError> {
        // In the if block, call query function of your runtime module condition 
        // and return tuple(is_finalized result, encoded boolean or numeic outcome)
        match registration_num {
            0 => { // Register registration_num of your runtime module condition 
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
            },
            1 => { 
                // is_finalized function return bool value
                let is_finalized: bool = match mock_boolean_condition::Module::<T>::is_finalized(args_query_finalization) {
                    Ok(_is_finalized) => _is_finalized,
                    Err(dispatch_error) => return Err(dispatch_error)?,
                };
                // get_outcome function return encoded boolean value
                let outcome: Vec<u8> = match mock_boolean_condition::Module::<T>::get_outcome(args_query_outcome) {
                    Ok(_outcome) => _outcome,
                    Err(dispatch_error) => return Err(dispatch_error)?,
                };
                return Ok((is_finalized, outcome));
            },
            _ => return Err(Error::<T>::RuntimeModuleConditionNotRegistered)?,
        }
    }
}