#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, ensure};
use frame_system::{self as system, ensure_signed};
use sp_runtime::DispatchResult;

pub trait Trait: system::Trait {}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        #[weight = 10_000]
        pub fn get_outcome(
            origin,
            app_id: T::Hash,
            number: u8
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // If outcome is false, return DispatchError::Other("FalseOutcome")
            ensure!(
                number == 1,
                "FalseOutcome"
            );

            Ok(())
        }

        #[weight = 10_000]
        pub fn is_finalized(
            origin,
            app_id: T::Hash,
            number: u8
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // If app is not finalized return DispatchError::Other("NotFinalized")
            ensure!(
                number == 1,
                "NotFinalized"
            );

            // If app is finalized, return Ok(())
            Ok(())
        }
    }
}