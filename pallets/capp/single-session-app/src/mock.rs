#![cfg(test)]

use super::*;
use crate::{Module, Trait};
use frame_support::{impl_outer_event, impl_outer_origin, parameter_types, weights::Weight};
use frame_system as system;
use pallet_balances;
use sp_core::{sr25519, Pair, H256};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::Perbill;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestRuntime;

pub(crate) type AccountId = sr25519::Public;
pub(crate) type BlockNumber = u64;
pub(crate) type Signature = sr25519::Signature;

pub mod single_app {
    pub use super::super::*;
}

impl_outer_event! {
    pub enum TestEvent for TestRuntime {
        single_app<T>,
        system<T>,
    }
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
}

parameter_types! {
    pub const MinimumPeriod: u64 = 5;
}

impl Trait for TestRuntime {
    type Event = TestEvent;
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
}

pub type SingleApp = Module<TestRuntime>;
pub type System = frame_system::Module<TestRuntime>;

pub struct ExtBuilder;
impl ExtBuilder {
    pub fn build() -> sp_io::TestExternalities {
        let alice: sr25519::Public = account_key("Alice");
        let bob: sr25519::Public = account_key("Bob");
        let risa: sr25519::Public = account_key("Risa");
        let carl: sr25519::Public = account_key("Carl");

        let mut t = system::GenesisConfig::default()
            .build_storage::<TestRuntime>().unwrap();
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
