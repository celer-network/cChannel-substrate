#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight for function need for celer_pay_module.
pub trait WeightInfo {
    fn set_balance_limits() -> Weight;
    fn disable_balance_limits() -> Weight;
    fn enable_balance_limits() -> Weight;
    fn open_channel() -> Weight;
    fn deposit() -> Weight;
    fn deposit_in_batch(n: u32, ) -> Weight;
    fn snapshot_states(n: u32, ) -> Weight;
    fn intend_withdraw() -> Weight;
    fn confirm_withdraw() -> Weight;
    fn veto_withdraw() -> Weight;
    fn cooperative_withdraw() -> Weight;
    fn intend_settle(n: u32, m: u32, ) -> Weight;
    fn clear_pays() -> Weight;
    fn confirm_settle() -> Weight;
    fn cooperative_settle() -> Weight;
    fn deposit_pool() -> Weight;
    fn withdraw_from_pool() -> Weight;
    fn approve() -> Weight;
    fn transfer_from() -> Weight;
    fn increase_allowance() -> Weight;
    fn decrease_allowance() -> Weight;
    fn resolve_payment_by_conditions(n: u32, ) -> Weight;
    fn resolve_payment_by_vouched_result(n: u32, ) -> Weight;
}

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Trait> WeightInfo for SubstrateWeight<T> {
    fn set_balance_limits() -> Weight {
        (50_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn disable_balance_limits() -> Weight {
        (50_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn enable_balance_limits() -> Weight {
        (50_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn open_channel() -> Weight {
        (5_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(4 as Weight))
            .saturating_add(T::DbWeight::get().writes(5 as Weight))
    }
    fn deposit() -> Weight {
        (3_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(6 as Weight))
            .saturating_add(T::DbWeight::get().writes(5 as Weight))
    }
    fn deposit_in_batch(n: u32) -> Weight {
        (0 as Weight)
            .saturating_add((3_000_000_000 as Weight).saturating_mul(n as Weight))
            .saturating_add(T::DbWeight::get().reads(6 as Weight).saturating_mul(n as Weight))
            .saturating_add(T::DbWeight::get().writes(5 as Weight).saturating_mul(n as Weight))
    }
    fn snapshot_states(n: u32) -> Weight {
        (5_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(n as Weight))
            .saturating_add(T::DbWeight::get().writes(n as Weight))
    }
    fn intend_withdraw() -> Weight {
        (3_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn confirm_withdraw() -> Weight {
        (7_000_000_000 as Weight) 
            .saturating_add(T::DbWeight::get().reads(4 as Weight))
            .saturating_add(T::DbWeight::get().writes(3 as Weight))
    }
    fn veto_withdraw() -> Weight {
        (1_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn cooperative_withdraw() -> Weight {
        (7_000_000_000 as Weight) 
            .saturating_add(T::DbWeight::get().reads(4 as Weight))
            .saturating_add(T::DbWeight::get().writes(3 as Weight))
    }
    fn intend_settle(n: u32, m: u32) -> Weight {
        (5_000_000_000 as Weight)
            .saturating_add((5_000_000_000 as Weight).saturating_mul(n as Weight))
            .saturating_add(T::DbWeight::get().reads(n as Weight))
            .saturating_add(T::DbWeight::get().reads(m as Weight))
            .saturating_add(T::DbWeight::get().writes(n as Weight))
    }
    fn clear_pays() -> Weight {
        (10_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn confirm_settle() -> Weight {
        (15_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(5 as Weight))
            .saturating_add(T::DbWeight::get().writes(5 as Weight))
    }
    fn cooperative_settle() -> Weight {
        (15_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(6 as Weight))
            .saturating_add(T::DbWeight::get().writes(5 as Weight))
    }
    fn deposit_pool() -> Weight {
        (3_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn withdraw_from_pool() -> Weight {
        (3_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn approve() -> Weight {
        (50_000_000 as Weight)
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn transfer_from() -> Weight {
        (3_000_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(3 as Weight))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
    }
    fn increase_allowance() -> Weight {
        (80_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn decrease_allowance() -> Weight {
        (80_000_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn resolve_payment_by_conditions(n: u32) -> Weight {
        (5_000_000_000 as Weight)
            .saturating_add((1_000_000_000 as Weight).saturating_mul(n as Weight))
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    fn resolve_payment_by_vouched_result(n: u32) -> Weight {
        (5_000_000_000 as Weight)
            .saturating_add((1_000_000_000 as Weight).saturating_mul(n as Weight))
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
}