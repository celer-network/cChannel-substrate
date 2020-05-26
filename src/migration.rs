use super::*;
use frame_support::storage::migration::{
    StorageIterator, 
    get_storage_value, 
    put_storage_value
};
use crate::ledger_operation::{
    LedgerOperation,
    PeerProfileOf,
    WithdrawIntentOf,
    ChannelOf    
};
use crate::celer_wallet::WalletOf;
use crate::pay_resolver::{TokenInfo, TokenType};

pub fn on_runtime_upgrade<T: Trait>() {
    match StorageVersion::get() {
        Releases::V2_0_0 => return,
        Releases::V1_0_0 => upgrade_v1_to_v2::<T>(),
    }
}

// upgrade Celer runtime module
fn upgrade_v1_to_v2<T: Trait>() {
    sp_runtime::print("Upgrading Celer Ledger...");
    // First, migrate old BalanceLimitEnabled to new Channel.
    // ChannelMap: map T::Hash => Option<Channel>;
    for (hash, balance_limits_enabled) in StorageIterator::<bool>::new(b"CelerModule", b"BalanceLimitsEnabled").drain() {
        let old_channel = get_storage_value::<ChannelOf<T>>(b"CelerModule", b"Channel", &hash);
        if let Some(mut channel) = old_channel {
            channel.balance_limits_enabled = balance_limits_enabled;

            // Do not migrate WithdrawIntent, in other words, migration will implicitly veto pending WithdrawIntent if any.
            let ledger_addr: T::AccountId = LedgerOperation::<T>::ledger_account();
            let init_withdraw_intent = WithdrawIntentOf::<T> {
                receiver: ledger_addr,
                amount: None,
                request_time: None,
                recipient_channel_id: None
            };
            channel.withdraw_intent = init_withdraw_intent;

            // Set default token field
            let token = TokenInfo {
                token_type: TokenType::CELER
            };
            channel.token = token;

            // Set ChannelStatus
            channel.status = ChannelStatus::Operable;

            put_storage_value(b"CelerModule", b"Channel", &hash, channel);
        }
    }

    // Second, migrate old BalanceLimits into new Channel.
    for (hash, balance_limits) in StorageIterator::<BalanceOf<T>>::new(b"CelerModule", b"BalanceLimits").drain() {
        let old_channel = get_storage_value::<ChannelOf<T>>(b"CelerModule", b"Channel", &hash);
        if let Some(mut channel) = old_channel {
            channel.balance_limits = Some(balance_limits);
            put_storage_value(b"CelerModule", b"Channel", &hash, channel);
        }
    }

    // Forth, migrate old DisputeTimeout into new Channel.
    for (hash, dispute_timeout) in StorageIterator::<T::BlockNumber>::new(b"CelerModule", b"DisputeTimeout").drain() {
        let old_channel = get_storage_value::<ChannelOf<T>>(b"CelerModule", b"Channel", &hash);
        if let Some(mut channel) = old_channel {
            channel.dispute_timeout = dispute_timeout;
            put_storage_value(b"CelerModule", b"Channel", &hash, channel);
        }
    }

    // Fifth, migrate old PeerProfiles into new Channel.
    for (hash, peer_profiles) in StorageIterator::<Vec<PeerProfileOf<T>>>::new(b"CelerModule", b"PeerProfiles").drain() {
        let old_channel = get_storage_value::<ChannelOf<T>>(b"CelerModule", b"Channel", &hash);
        if let Some(mut channel) = old_channel {
            channel.peer_profiles  = peer_profiles;
            put_storage_value(b"CelerModule", b"Channel", &hash, channel);
        }
    }

    // Sixth, migrate CooperativeWithdrawSeqNum into new Channel.
    for (hash, cooperative_withdraw_seq_num) in StorageIterator::<u128>::new(b"CelerModule", b"CooperativeWithdrawSeqNum").drain() {
        let old_channel = get_storage_value::<ChannelOf<T>>(b"CelerModule", b"Channel", &hash);
        if let Some(mut channel) = old_channel {
            channel.cooperative_withdraw_seq_num = Some(cooperative_withdraw_seq_num);
            put_storage_value(b"CelerModule", b"Channel", &hash, channel);
        }
    }

    // Seventh, migrate Owners into new Wallet.
    for (hash, owners) in StorageIterator::<Vec<T::AccountId>>::new(b"CelerModule", b"Owners").drain() {
        let old_wallet = get_storage_value::<WalletOf<T>>(b"CelerModule", b"Wallet", &hash);
        if let Some(mut wallet) = old_wallet {
            wallet.owners = owners;
            put_storage_value(b"CelerModule", b"Wallet", &hash, wallet);
        }
    }

    // Eighth, migrate Balance into new Wallet.
    for (hash, balance) in StorageIterator::<BalanceOf<T>>::new(b"CelerModule", b"Balance").drain() {
        let old_wallet = get_storage_value::<WalletOf<T>>(b"CelerModule", b"Wallet", &hash);
        if let Some(mut wallet) = old_wallet {
            wallet.balance = balance;
            put_storage_value(b"CelerModule", b"Wallet", &hash, wallet);
        }
    }

    // Ninth, migrate Balance into new Balances.
    // pub Balances: map T::AccountId => Option<Balance>;
    for (hash, balance) in StorageIterator::<BalanceOf<T>>::new(b"Celermodule", b"Balances").drain() {
        put_storage_value(b"CelerModule", b"Balances", &hash, balance);
    }

    // Tenth, migrate Balance into new Allowed.
    // pub Allowed: double_map T::AccountId, T::AccountId => Option<Balance>;
    for (hash, balance) in StorageIterator::<BalanceOf<T>>::new(b"CelerModule", b"Balance").drain() {
        put_storage_value(b"CelerModule", b"Allowed", &hash, balance);
    }

    StorageVersion::put(Releases::V2_0_0);
}

#[cfg(test)]
pub mod test {
    use crate::*;
    use crate::mock::*;
    use frame_support::assert_ok;
    use sp_runtime::traits::OnRuntimeUpgrade;
    use crate::ledger_operation::{LedgerOperation, WithdrawIntentOf};
    use crate::ledger_operation::tests::*;
    use crate::eth_pool::EthPool;
    use crate::pay_registry::PayRegistry;
    use sp_core::{H256, hashing, sr25519};
    use pay_resolver::*;
    

    #[test]
    fn test_pass_migrate_operable_channel() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            EthPool::<TestRuntime>::deposit_pool(Origin::signed(channel_peers[0]), channel_peers[0], 100);
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request
                = get_open_channel_request(true, 10000, 50000, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request, 200).unwrap();

            <CelerModule as Store>::StorageVersion::put(Releases::V1_0_0);

            migration_test(channel_id, channel_peers.clone());

            let new_status = CelerModule::get_channel_status(channel_id);
            assert_eq!(new_status, ChannelStatus::Operable);

            assert_eq!(<CelerModule as Store>::StorageVersion::get(), Releases::V2_0_0);
        })
    }

    #[test]
    fn test_pass_migrate_settling_channel() {
        ExtBuilder::build().execute_with(|| {
            let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());
            
            EthPool::<TestRuntime>::deposit_pool(Origin::signed(channel_peers[0]), channel_peers[0], 100);
            approve(channel_peers[0], ledger_addr, 100);

            let open_channel_request
                = get_open_channel_request(true, 10000, 50000, 10, false, channel_peers.clone(), 1, peers_pair.clone());
            let channel_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request, 200).unwrap();

            <CelerModule as Store>::StorageVersion::put(Releases::V1_0_0);

            migrate_settling_channel_test(channel_id, channel_peers, peers_pair);

            assert_eq!(<CelerModule as Store>::StorageVersion::get(), Releases::V2_0_0);
        })
    }

    fn migrate_settling_channel_test(
        channel_id: H256, 
        channel_peers: Vec<AccountId>, 
        peers_pair: Vec<sr25519::Pair>
    ) {
        // intendSettle in old ledger
        intend_settle_test(channel_id, channel_peers.clone(), peers_pair.clone());

        // ledger migration
        migration_test(channel_id, channel_peers.clone());

        let mut wallet_balance = CelerModule::get_balance(channel_id).unwrap();
        assert_eq!(wallet_balance, 300);

        // confirmSettle in new ledger
        let settle_balance = confirm_settle_test(channel_id, peers_pair);

        wallet_balance = CelerModule::get_balance(channel_id).unwrap();
        assert_eq!(wallet_balance, 0);
    }

    fn migration_test(channel_id: H256, channel_peers: Vec<AccountId>) {
        let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
        let old_balance_limit = CelerModule::get_balance_limit(channel_id).unwrap();
        let old_balance_limits_enabled = CelerModule::get_balance_limits_enabled(channel_id).unwrap();
        let old_settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id);
        let old_balance_map = CelerModule::get_balance_map(channel_id);
        let old_dispute_timeout = CelerModule::get_dispute_time_out(channel_id).unwrap();
        let old_peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
        let old_wallet_owners = CelerModule::get_wallet_owners(channel_id).unwrap();
        let old_wallet_balance = CelerModule::get_balance(channel_id).unwrap();
        let old_balances_of_pool = CelerModule::balance_of(channel_peers[0].clone()).unwrap();
        let old_allowance = CelerModule::allowance(channel_peers[0].clone(), ledger_addr.clone());

        // Perform upgrade
        CelerModule::on_runtime_upgrade();

        let new_balance_limit = CelerModule::get_balance_limit(channel_id).unwrap();
        let new_balance_limits_enabled = CelerModule::get_balance_limits_enabled(channel_id).unwrap();
        let new_settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id);
        let new_balance_map = CelerModule::get_balance_map(channel_id);
        let new_dispute_timeout = CelerModule::get_dispute_time_out(channel_id).unwrap();
        let new_peers_migration_info = CelerModule::get_peers_migration_info(channel_id).unwrap();
        let new_withdraw_intent = CelerModule::get_withdraw_intent(channel_id).unwrap();
        let new_wallet_owners = CelerModule::get_wallet_owners(channel_id).unwrap();
        let new_wallet_balance = CelerModule::get_balance(channel_id).unwrap();
        let new_balances_of_pool = CelerModule::balance_of(channel_peers[0].clone()).unwrap();
        let new_allowance = CelerModule::allowance(channel_peers[0].clone(), ledger_addr.clone());

        assert_eq!(old_balance_limit, new_balance_limit);
        assert_eq!(old_balance_limits_enabled, new_balance_limits_enabled);
        assert_eq!(old_settle_finalized_time, new_settle_finalized_time);
        assert_eq!(old_balance_map, new_balance_map);
        assert_eq!(old_dispute_timeout, new_dispute_timeout);
        assert_eq!(old_peers_migration_info, new_peers_migration_info);
        assert_eq!(old_wallet_owners, new_wallet_owners);
        assert_eq!(old_wallet_balance, new_wallet_balance);
        assert_eq!(old_balances_of_pool, new_balances_of_pool);
        assert_eq!(old_allowance, new_allowance);

        // Check whether withdraw_intent initialized
        let ledger_addr = LedgerOperation::<TestRuntime>::ledger_account();
        let init_withdraw_intent = WithdrawIntentOf::<TestRuntime> {
            receiver: ledger_addr,
            amount: None,
            request_time: None,
            recipient_channel_id: None
        };
        assert_eq!(new_withdraw_intent.0, init_withdraw_intent.receiver);
    }

    fn intend_settle_test(
        channel_id: H256,
        channel_peers: Vec<AccountId>,
        peers_pair: Vec<sr25519::Pair>
    ) {
        // the meaning of the index: [peer index][pay hash list index][pay index]
        let peers_pay_hash_lists_amts: Vec<Vec<Vec<Balance>>> 
            = vec![vec![vec![1, 2], vec![3, 4]], vec![vec![5, 6], vec![7, 8]]];
        let settle_bundle = get_cosigned_intend_settle(
            vec![channel_id, channel_id],
            peers_pay_hash_lists_amts.clone(),
            vec![1, 1],
            vec![10, 20],
            vec![99999, 99999],
            vec![channel_peers[0], channel_peers[1]],
            vec![channel_peers[0], channel_peers[1]],
            channel_peers[0],
            vec![peers_pair[0].clone(), peers_pair[1].clone()],
            1
        );

        let cond_pays = settle_bundle.2;
        for peer_index in 0..2 {
            for list_index in 0..cond_pays[peer_index as usize].len() {
                for pay_index in 0..cond_pays[peer_index as usize][list_index as usize].len() {
                    let pay_request = ResolvePaymentConditionsRequest {
                        cond_pay: cond_pays[peer_index as usize][list_index as usize][pay_index as usize].clone(),
                        hash_preimages: vec![]
                    };                       
                    let _ = PayResolver::<TestRuntime>::resolve_payment_by_conditions(pay_request).unwrap();
                }
            }
        }

        // pass onchain resolve deadline of all onchain resolved pays
        // but not pass the last pay resolve deadline
        System::set_block_number(System::block_number() + 6);

        let signed_simplex_state_array = settle_bundle.0;
        let _ = LedgerOperation::<TestRuntime>::intend_settle(Origin::signed(channel_peers[0]), signed_simplex_state_array).unwrap();

        let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
        let expected_settle_finalized_time = 10 + System::block_number();
        assert_eq!(settle_finalized_time, expected_settle_finalized_time);

        let status = CelerModule::get_channel_status(channel_id);
        assert_eq!(status, ChannelStatus::Settling);

        let amounts = vec![1, 2, 5, 6];
        for i in 0..2 {
            for j in 0..2 {
                let log_index: usize = i * 2 + j;
                let encoded = encode_conditional_pay::<TestRuntime>(cond_pays[i][0][j].clone());
                let pay_hash = hashing::blake2_256(&encoded).into();
                let pay_id = PayRegistry::<TestRuntime>::calculate_pay_id(pay_hash);
                let expected_event = TestEvent::celer(
                    RawEvent::ClearOnePay(
                        channel_id,
                        pay_id,
                        channel_peers[i as usize],
                        amounts[log_index]
                    )
                );
                assert!(System::events().iter().any(|a| a.event == expected_event));
            }
        }

        let pay_id_list_array = settle_bundle.4;
        for peer_index in 0..2 {
            assert_ok!(
                LedgerOperation::<TestRuntime>::clear_pays(
                    channel_id,
                    channel_peers[peer_index as usize],
                    pay_id_list_array[peer_index as usize][1].clone()
                )
            )
        }
    }

    fn confirm_settle_test(channel_id: H256, peers_pair: Vec<sr25519::Pair>) {
        // pass settle_finalized_time
        let settle_finalized_time = CelerModule::get_settle_finalized_time(channel_id).unwrap();
        System::set_block_number(settle_finalized_time);

        let (_, settle_balance) = LedgerOperation::<TestRuntime>::confirm_settle(channel_id).unwrap();
        let status = CelerModule::get_channel_status(channel_id);

        assert_eq!(settle_balance, [126, 174]);
        assert_eq!(status, ChannelStatus::Closed);
    }
}
