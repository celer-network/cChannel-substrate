use codec::{Decode, Encode};
use frame_system::{self as system};
use pallet_timestamp;
use frame_support::{
    traits::Currency
};
use sp_runtime::traits::{IdentifyAccount, Member, Verify};
use mock_numeric_condition;
use mock_boolean_condition;
pub use crate::weights::WeightInfo;
use super::Event;

pub trait Trait: system::Trait + pallet_timestamp::Trait + celer_contracts::Trait 
   + mock_numeric_condition::Trait + mock_boolean_condition::Trait + single_session_app::Trait
// ----------------------------------------------------------------^^^^^^^^^^^^^^^^^^^^^^^^^^^
// Add single-session-app Trait
{
    type Currency: Currency<Self::AccountId>;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = <Self as Trait>::Public> + Member + Decode + Encode;
    type WeightInfo: WeightInfo;
}

