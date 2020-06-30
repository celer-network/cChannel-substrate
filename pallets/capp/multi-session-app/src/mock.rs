#![cfg(test)]

use super::*;
use crate as multi_app;
use frame_support::{
    impl_outer_event, impl_outer_origin, impl_outer_dispatch, 
    parameter_types, weights::Weight
};
use frame_system as system;
use sp_core::{sr25519, Pair, H256};
use pallet_balances;
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::Perbill;

#[derive(Clone, Eq, PartialEq)]
pub struct TestRuntime;

pub(crate) type AccountId = sr25519::Public;
pub(crate) type BlockNumber = u64;
pub(crate) type Signature = sr25519::Signature;

impl_outer_event! {
    pub enum TestEvent for TestRuntime {
        system<T>,
        pallet_balances<T>,
        multi_app<T>,
    }
}

impl_outer_dispatch! {
    pub enum Call for TestRuntime where origin: Origin {
        frame_system::System,
        pallet_balances::Balances,
        multi_app::MultiApp,
    }
}

impl_outer_origin! {
    pub enum Origin for TestRuntime where system = frame_system  {}
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

impl pallet_balances::Trait for TestRuntime {
	type Balance = u64;
	type Event = TestEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
}

impl Trait for TestRuntime {
    type Event = TestEvent;
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
}

pub type MultiApp = Module<TestRuntime>;
pub type System = frame_system::Module<TestRuntime>;
type Balances = pallet_balances::Module<TestRuntime>;

pub struct ExtBuilder;
impl ExtBuilder {
    pub fn build() -> sp_io::TestExternalities {
        let t = system::GenesisConfig::default()
            .build_storage::<TestRuntime>().unwrap();
        let ext = sp_io::TestExternalities::new(t);
        ext
    }
}

pub(crate) fn account_pair(s: &str) -> sr25519::Pair {
    sr25519::Pair::from_string(&format!("//{}", s), None).expect("static values are valid: qed")
}

pub(crate) fn get_sorted_peer(
    peer_1: sr25519::Pair,
    peer_2: sr25519::Pair,
) -> (Vec<AccountId>, Vec<sr25519::Pair>) {
    if peer_1.public() < peer_2.public() {
        return (
            vec![peer_1.clone().public(), peer_2.clone().public()],
            vec![peer_1, peer_2],
        );
    } else {
        return (
            vec![peer_2.clone().public(), peer_1.clone().public()],
            vec![peer_2, peer_1],
        );
    }
}
