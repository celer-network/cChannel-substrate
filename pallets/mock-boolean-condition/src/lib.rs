#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Encode, Decode};
use frame_support::{decl_module, decl_error};
use frame_system::{self as system};
use sp_runtime::{DispatchError, RuntimeDebug};
use sp_std::vec::Vec;

pub trait Trait: system::Trait {}

#[derive(PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct BooleanArgsQueryFinalization<Hash> {
    pub session_id: Hash,
    pub query_data: u8,
}

pub type BooleanArgsQueryFinalizationOf<T> = BooleanArgsQueryFinalization<<T as system::Trait>::Hash>;

#[derive(PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct BooleanArgsQueryOutcome<Hash> {
    pub session_id: Hash,
    pub query_data: u8,
}

pub type BooleanArgsQueryOutcomeOf<T> = BooleanArgsQueryOutcome<<T as system::Trait>::Hash>;

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
    /// Query whether boolean runtime module condition is finalized
    ///
    /// Return the boolean value 
    pub fn is_finalized(
        query: Vec<u8>, // encoded args query finalization
    ) -> Result<bool, DispatchError> {
        let decoded_query: BooleanArgsQueryFinalizationOf<T> = BooleanArgsQueryFinalization::decode(&mut &query[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
        if decoded_query.query_data == 0 {
            // when condition is not finalized, return false
            return Ok(false);
        } else {
            // when condition is finalized, return true
            return Ok(true);
        }
    }

    /// Query outcome of boolean runtime module condition
    ///
    /// Return the encoded encoded boolean value
    pub fn get_outcome(
        query: Vec<u8>, // encoded args query outcome
    ) -> Result<Vec<u8>, DispatchError> {
        let decoded_query: BooleanArgsQueryOutcomeOf<T> = BooleanArgsQueryOutcome::decode(&mut &query[..]).map_err(|_| Error::<T>::MustBeDecodable)?;
        if decoded_query.query_data == 0 {
            // when outcome is false, return encoded false value
            let outcome: bool = false;
            return Ok(outcome.encode());
        } else {
            // when outcome is true, return encoded true value
            let outcome: bool = true;
            return Ok(outcome.encode());
        }
    }
}
