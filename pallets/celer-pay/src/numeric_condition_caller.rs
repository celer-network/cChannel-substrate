use super::*;
use traits::Trait;
use sp_std;
use mock_numeric_condition;

pub struct NumericConditionCaller<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> NumericConditionCaller<T> {
    pub fn call_is_finalized(
        numeric_app_number: u32, 
        session_id: &T::Hash, 
        args_query_finalization: Option<Vec<u8>>
    ) -> Result<bool, DispatchError> {
        if numeric_app_number == 0 {
            let is_finalized: bool 
                = mock_numeric_condition::Module::<T>::is_finalized(session_id, args_query_finalization)?;
            return Ok(is_finalized);
        } else {
            return Err(Error::<T>::NumericAppNotExist)?;
        }
    }

    pub fn call_get_outcome(
        numeric_app_number: u32, 
        session_id: &T::Hash, 
        args_query_outcome: Option<Vec<u8>>
    ) -> Result<BalanceOf<T>, DispatchError> {
        if numeric_app_number == 0 {
            let outcome: BalanceOf<T> 
                = mock_numeric_condition::Module::<T>::get_outcome(session_id, args_query_outcome).unwrap().into();
            return Ok(outcome);
        } else {
            return Err(Error::<T>::NumericAppNotExist)?;
        }
    }
}