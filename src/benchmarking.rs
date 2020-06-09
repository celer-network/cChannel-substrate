// ! Celer Pay palllet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;

use frame_system::RawOrigin;
use sp_io::hashing::blake2_256;
use frame_benchmarking::benchmarks;
use sp_runtime::traits::Bounded;
use crate::ledger_operation::tests::*;
use crate::ledger_operation::{LedgerOperation, SignedSimplexStateArray};
use crate::mock::*;
use crate::pay_resolver::tests::*;
use crate::pay_resolver::{
    CondPayResult, ConditionalPay, PayResolver,
    ResolvePaymentConditionsRequest, VouchedCondPayResult,
};
use crate::pool::Pool;
use sp_core::{hashing, Pair, H256};

use crate::Module as CelerPay;

fn account<T: Trait>(name: &'static str, index: u32) -> T::AccountId {
    let entropy = (name, index).using_encoded(blake2_256);
    T::AccountId::decode(&mut &entropy[..]).unwrap_or_default()
}
fn set_approve<T: Trait>(r: u32) -> (channel_peers: Vec<T::AccountId>, peers_pairs: Vec<sr25519::Pair> {
    let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", i))?;
    let _ = T::Currency::make_free_balance_be(&account::<T>("channel_peer", 2*i))?;
    let (channel_peers, peers_pair) = get_sorted_peer(account::<T>("channel_peer", i), account::<T>("channel_peer", 2*i));
    Pool::<T>::deposit_pool(
        Origin::signed(channel_peers[0]),
        channel_peers[0],
        100,
    );
    approve(channel_peers[0], ledger_addr, 100);

    return (channel_peers, peers_pair);
}

benchmarks! {
    _ { }

    open_channel {
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve(r);
        let open_channel_request = get_open_channel_request(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
    }: _(RawOrigin::Signed(channel_peers[0]), open_channel_request.clone(), 200)

    set_balance_limits(
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve(r);
        let open_channel_request = get_open_channel_request(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerPay::open_channel(Origin::signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
    ): _(RawOrigin::signed(channel_peers[0]), channel_id, 200)

    disable_balance_limits(
        let r in 0 .. 1000;
        let (channel_peers, peers_pair) = set_approve(r);
        let open_channel_request = get_open_channel_request(true, 10000, 50000+r, 10, false, channel_peers.clone(), 1, peers_pair);
        CelerPay::open_channel(Origin::signed(channel_peers[0]), open_channel_request.clone(), 200)?;
        let channel_id = calculate_channel_id(open_channel_request, channel_peers.clone());
    ): _(RawOrigin::signed(channel_peers[0]), channel_id)

    enable_balance_limits(
        let r in 0  .. 1000;
        let (channel_peers, peers_pair) = set_approve(r);
        
    )
}
