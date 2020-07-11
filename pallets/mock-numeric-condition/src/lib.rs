#![cfg_attr(not(feature = "std"), no_std)]

use codec::Decode;
use frame_support::{decl_module, decl_error};
use frame_system::{self as system};
use sp_runtime::DispatchError;
use sp_std::vec::Vec;

pub trait Trait: system::Trait {}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;
    }
}

decl_error! {
    pub enum Error for Module<T: Trait> {
        // Decode error
        MustBeDecodable,
    }
}

impl<T: Trait> Module<T> {
    pub fn is_finalized(
        _app_id: &T::Hash, 
        query: Option<Vec<u8>>
    ) -> Result<bool, DispatchError> {
        let _query = query.unwrap();
        let number: u8 = Decode::decode(&mut &_query[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
        if number == 0 {
            return Ok(false);
        } else {
            return Ok(true);
        }
    }

    pub fn get_numeric_outcome(
        _app_id: &T::Hash, 
        query: Option<Vec<u8>>
    ) -> Result<u32, DispatchError> {
        let _query = query.unwrap();
        let amount: u32 = Decode::decode(&mut &_query[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
        return Ok(amount);
    }
}

