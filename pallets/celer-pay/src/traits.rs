use codec::{Decode, Encode};
use frame_system::{self as system};
use pallet_timestamp;
use frame_support::{
    Parameter,
    dispatch::{PostDispatchInfo, IsSubType},
    traits::{Currency, IsType},
    weights::GetDispatchInfo,
};
use sp_runtime::traits::{IdentifyAccount, Member, Verify, Dispatchable};
use mock_numeric_condition;
pub use crate::weights::WeightInfo;
use super::Event;
use crate::Call;

pub trait Trait: system::Trait + pallet_timestamp::Trait + celer_contracts::Trait + mock_numeric_condition::Trait {
    type Currency: Currency<Self::AccountId>;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = <Self as Trait>::Public> + Member + Decode + Encode;
    /// The overarching call type
    type Call: Parameter + Dispatchable<Origin=Self::Origin, PostInfo=PostDispatchInfo>
		+ GetDispatchInfo + From<frame_system::Call<Self>> + IsSubType<Call<Self>>
		+ IsType<<Self as frame_system::Trait>::Call>;
    type WeightInfo: WeightInfo;
}

