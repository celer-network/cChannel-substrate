use super::{BalanceOf, Trait};
use sp_runtime::traits::{One, Zero};

pub struct MockNumericCondition<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> MockNumericCondition<T> {
    pub fn is_finalized(_condition_address: &T::Hash, number: Option<u8>) -> bool {
        if number.unwrap() == 0 {
            return false;
        } else {
            return true;
        }
    }

    pub fn get_numeric_outcome(
        _condition_address: &T::Hash,
        number: Option<u8>,
    ) -> BalanceOf<T> {
        let zero_balance: BalanceOf<T> = Zero::zero();
        let mut amount = zero_balance;
        for _i in 0..number.unwrap() {
            amount += One::one();
        }
        return amount;
    }
}
