use codec::{Decode, Encode};
use frame_system as system;
use pallet_timestamp;
use frame_support::{
    Parameter,
    dispatch::{PostDispatchInfo, IsSubType},
    traits::Currency,
    weights::GetDispatchInfo,
};
use sp_runtime::traits::{IdentifyAccount, Member, Verify, Dispatchable};
use mock_numeric_condition;
use super::{Module, Event};

pub trait Trait: system::Trait + pallet_timestamp::Trait + mock_numeric_condition::Trait {
    type Currency: Currency<Self::AccountId>;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = <Self as Trait>::Public> + Member + Decode + Encode;
    /// The overarching call type
    type Call: Parameter + Dispatchable<Origin=Self::Origin, PostInfo=PostDispatchInfo>
		+ GetDispatchInfo + From<system::Call<Self>> + IsSubType<Module<Self>, Self>;
}

