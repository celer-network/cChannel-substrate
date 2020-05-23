#![cfg(test)]

use super::*;
use crate::{Module, Trait};
use sp_runtime::Perbill;
use sp_runtime::traits::{IdentityLookup, BlakeTwo256};
use sp_runtime::testing::Header;
use frame_support::{impl_outer_origin, impl_outer_event, 
        parameter_types, weights::Weight};
use sp_core::{sr25519, Pair, H256};
use frame_system as system;
use pallet_balances::{self, Reasons};


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

pub(crate) type Moment = u64;
pub(crate) type AccountId = sr25519::Public;
pub(crate) type Balance = u64;
pub(crate) type BlockNumber = u64;
pub(crate) type Signature = sr25519::Signature;

mod celer {
    pub use crate::Event;
}

impl_outer_event! {
    pub enum TestEvent for TestRuntime {
        celer<T>,
        pallet_balances<T>,
        system<T>,
    }
}

impl_outer_origin! {
    pub enum Origin for TestRuntime {}
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 1024;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    pub const ExistentialDeposit: u64 = 1; // should be greater than zero
}

impl frame_system::Trait for TestRuntime {
    type Origin = Origin;
    type Call = ();
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = sr25519::Public;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = TestEvent;
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
    type ModuleToIndex = ();
    type AccountData = pallet_balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = 5;
}

impl pallet_balances::Trait for TestRuntime {
    type Balance = u64;
    type Event = TestEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = frame_system::Module<TestRuntime>;
}

impl pallet_timestamp::Trait for TestRuntime {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
}

impl Trait for TestRuntime {
    type Currency = pallet_balances::Module<Self>;
    type Event = TestEvent;
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
}

pub type CelerModule = Module<TestRuntime>;
pub type System = frame_system::Module<TestRuntime>;
pub type Balances = pallet_balances::Module<TestRuntime>;
pub type Timestamp = pallet_timestamp::Module<TestRuntime>;

pub struct ExtBuilder;
impl ExtBuilder {
    pub fn build() -> sp_io::TestExternalities {
        let ALICE: sr25519::Public = account_key("Alice");
        let BOB: sr25519::Public = account_key("Bob");
        let RISA: sr25519::Public = account_key("Risa");
        let CARL: sr25519::Public = account_key("Carl");

        let mut t = system::GenesisConfig::default()
            .build_storage::<TestRuntime>()
            .unwrap();
        pallet_balances::GenesisConfig::<TestRuntime> {
            balances: vec![(ALICE, 1000), (BOB, 1000), (RISA, 1000), (CARL, 100000)],
        }
        .assimilate_storage(&mut t)
        .unwrap();
        sp_io::TestExternalities::new(t)
    }
}

pub(crate) fn account_pair(s: &str) -> sr25519::Pair {
	sr25519::Pair::from_string(&format!("//{}", s), None).expect("static values are valid: qed")
}

pub(crate) fn account_key(s: &str) -> sr25519::Public {
	sr25519::Pair::from_string(&format!("//{}", s), None)
    	.expect("static values are valid; qed")
		.public()
}


