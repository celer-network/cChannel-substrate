// ! Celer Pay palllet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_system::{self, RawOrigin};
use sp_io::hashing::blake2_256;
use frame_benchmarking::benchmarks;
use sp_runtime::traits::{Bounded, IdentifyAccount};
use crate::ledger_operation::{LedgerOperation, SignedSimplexStateArray};
use crate::pay_resolver::{
    CondPayResult, ConditionalPay, PayResolver,
    ResolvePaymentConditionsRequest, VouchedCondPayResult,
};
use crate::pool::Pool;
use sp_core::{hashing, H256, sr25519, Pair};
use crate::Module as CelerModule;
use sp_application_crypto::RuntimePublic;


fn account<T: Trait>(name: &'static str, index: u32) -> T::AccountId {
	let entropy = (name, index).using_encoded(blake2_256);
	T::AccountId::decode(&mut &entropy[..]).unwrap_or_default()
}

fn account_pair<T: Trait>(s: &str) -> sr25519::Pair {
    sr25519::Pair::from_string(&format!("//{}", s), None).expect("static values are valid: qed")
}


fn get_sorted_peer<T: Trait>() -> (Vec<T::AccountId>, Vec<sr25519::Pair>) {
    let alice_pair = account_pair("Alice");
    let bob_pair = account_pair("Bob");
    let alice_public: T::AccountId = alice_pair.public().into_account();
    let bob_public: T::AccountId = bob_pair.public().into_account();
    
    return (
        vec![alice_public, bob_public],
        vec![alice_pair, bob_pair]
    );
}