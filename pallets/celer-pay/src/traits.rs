use codec::{Decode, Encode};
use frame_system::{self as system};
use pallet_timestamp;
use frame_support::{
    traits::Currency
};
use sp_runtime::traits::{IdentifyAccount, Member, Verify};
pub use crate::weights::WeightInfo;
use super::Event;

pub trait Trait: system::Trait + pallet_timestamp::Trait + runtime_module_condition_caller::Trait + celer_contracts::Trait 
{
    type Currency: Currency<Self::AccountId>;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = <Self as Trait>::Public> + Member + Decode + Encode;
    type WeightInfo: WeightInfo;
}

