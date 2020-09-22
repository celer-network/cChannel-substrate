#![cfg(test)]

use super::*;
use crate::{Module};
use crate::traits::Trait;
use frame_support::{
    impl_outer_event, impl_outer_origin, impl_outer_dispatch,
    parameter_types, weights::Weight
};
use frame_system as system;
use pallet_balances;
use sp_core::{sr25519, Pair, H256};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::Perbill;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

pub(crate) type Moment = u64;
pub(crate) type AccountId = sr25519::Public;
pub(crate) type Balance = u64;
pub(crate) type BlockNumber = u64;
pub(crate) type Signature = sr25519::Signature;


pub mod celer {
    pub use super::super::*;
}

impl_outer_event! {
    pub enum TestEvent for TestRuntime {
        celer<T>,
        pallet_balances<T>,
        system<T>,
    }
}

impl_outer_dispatch! {
    pub enum Call for TestRuntime where origin: Origin {
        frame_system::System,
        celer_pay::CelerPayModule,
        mock_boolean_condition::MockBooleanCondition,
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
    type BaseCallFilter = ();
    type Origin = Origin;
    type Call = Call;
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
    type DbWeight = ();
	type BlockExecutionWeight = ();
	type ExtrinsicBaseWeight = ();
    type MaximumExtrinsicWeight  = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
    type Version = ();
    type ModuleToIndex = ();
    type AccountData = pallet_balances::AccountData<u64>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
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
    type WeightInfo = ();
}

impl pallet_timestamp::Trait for TestRuntime {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

impl mock_boolean_condition::Trait for TestRuntime {}

impl mock_numeric_condition::Trait for TestRuntime {}

impl Trait for TestRuntime {
    type Currency = pallet_balances::Module<Self>;
    type Event = TestEvent;
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
    type Call = Call;
}

pub type CelerPayModule = Module<TestRuntime>;
pub type System = frame_system::Module<TestRuntime>;
pub type Timestamp = pallet_timestamp::Module<TestRuntime>;
type MockBooleanCondition = mock_boolean_condition::Module<TestRuntime>;

pub struct ExtBuilder;
impl ExtBuilder {
    pub fn build() -> sp_io::TestExternalities {
        let alice: sr25519::Public = account_key("Alice");
        let bob: sr25519::Public = account_key("Bob");
        let risa: sr25519::Public = account_key("Risa");
        let carl: sr25519::Public = account_key("Carl");

        let mut t = system::GenesisConfig::default()
            .build_storage::<TestRuntime>().unwrap();
        pallet_balances::GenesisConfig::<TestRuntime> {
            balances: vec![(alice, 1000), (bob, 1000), (risa, 1000), (carl, 100000)],
        }.assimilate_storage(&mut t).unwrap();
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
