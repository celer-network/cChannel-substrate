use super::*;
use mock::*;
use sp_core::{sr25519, Pair, H256};
use frame_support::{assert_ok, assert_noop};

#[test]
fn test_pass_initiate() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, _) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request
            )
        );
    })
}

#[test]
fn test_pass_update_by_state_state_is_5() {
    ExtBuilder::build().execute_with(|| {
        System::set_block_number(1);
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let state_proof = get_state_proof(1, 5, 2, session_id, players_pair);
    
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        );
        
        let session_info = MultiApp::session_info(session_id).unwrap();
        let expected_session_info = SessionInfo {
            state: 5,
            players: players.clone(),
            player_num: 2,
            seq_num: 1,
            timeout: 2,
            deadline: 3,
            status: SessionStatus::Settle,
        };
        assert_eq!(session_info, expected_session_info);

        assert_ok!(
            MultiApp::get_outcome(
                Origin::signed(players[0]),
                session_id,
                5
            )
        );

        assert_noop!(
            MultiApp::get_finalized(
                Origin::signed(players[0]),
                session_id,
            ),
            Error::<TestRuntime>::NotFinalized
        );
    })
}

#[test]
fn test_fail_update_by_action_before_settle_finalized_time() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let state_proof = get_state_proof(1, 5, 2, session_id, players_pair);
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        );

        assert_noop!(
            MultiApp::update_by_action(
                Origin::signed(players[0]),
                session_id,
                1
            ),
            "app not in action mode"
        );
    })
}

#[test]
fn test_pass_update_by_action_after_settle_finalized_time() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let state_proof = get_state_proof(1, 3, 2, session_id, players_pair);
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        ); 


        let settle_finalized_time = MultiApp::get_settle_finalized_time(session_id).unwrap();
        System::set_block_number(settle_finalized_time + 1);

        assert_ok!(
            MultiApp::update_by_action(
                Origin::signed(players[0]),
                session_id,
                3
            )
        );
    })
}

#[test]
fn test_fail_update_by_state_with_invalid_sequence_number() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let mut state_proof = get_state_proof(1, 3, 2, session_id, players_pair.clone());
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        ); 

        state_proof = get_state_proof(0, 3, 2, session_id, players_pair);
        assert_noop!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            ),
            "invalid sequence number"
        ); 
    })
}

#[test]
fn test_fail_update_by_state_with_different_player_sigs() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let state_proof = get_state_proof(1, 3, 2, session_id, vec![players_pair[0].clone(), account_pair("Carl")]);
        assert_noop!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            ),
            "Check co-sigs failed"
        );
    })
}

#[test]
fn test_pass_update_by_state_with_valid_a_seq_sig() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let mut state_proof = get_state_proof(1, 5, 2, session_id, players_pair.clone());
    
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        ); 

        state_proof = get_state_proof(2, 2, 2, session_id, players_pair);
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        );

        assert_ok!(
            MultiApp::get_outcome(
                Origin::signed(players[0]),
                session_id,
                2
            )
        );
        assert_ok!(
            MultiApp::get_finalized(
                Origin::signed(players[0]),
                session_id
            )
        );
    })
}

#[test]
fn test_fail_update_by_action_after_finalized() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let state_proof = get_state_proof(1, 2, 2, session_id, players_pair.clone());
    
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        ); 

        assert_noop!(
            MultiApp::update_by_action(
                Origin::signed(players[0]),
                session_id,
                2
            ),
            "app state is finalized"
        );
    })
}

#[test]
fn test_fail_update_by_state_after_finalized() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let mut state_proof = get_state_proof(1, 2, 2, session_id, players_pair.clone());
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        ); 

        state_proof = get_state_proof(2, 2, 2, session_id, players_pair);
        assert_noop!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            ),
            "app state is finalized"
        );
    })
}

#[test]
fn test_pass_finalize_on_action_timeout() {
    ExtBuilder::build().execute_with(|| {
        System::set_block_number(1);
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");
        let (players, players_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

        let initiate_request = SessionInitiateRequest {
            nonce: 1,
            player_num: 2,
            players: players.clone(),
            timeout: 2
        };
        assert_ok!(
            MultiApp::session_initiate(
                Origin::signed(players[0]),
                initiate_request.clone()
            )
        );

        let session_id = MultiApp::calculate_session_id(initiate_request);
        let state_proof = get_state_proof(1, 2, 2, session_id, players_pair.clone());
        assert_ok!(
            MultiApp::update_by_state(
                Origin::signed(players[0]),
                state_proof
            )
        );   

        System::set_block_number(5);
        assert_ok!(
            MultiApp::finalize_on_action_timeout(
                Origin::signed(players[0]),
                session_id
            )
        );
    })
}

fn get_state_proof(
    seq: u128,
    state: u8,
    timeout: BlockNumber,
    session_id: H256,
    players_pair: Vec<sr25519::Pair>
) -> StateProof<BlockNumber, H256, Signature> {
    let app_state = AppState {
        seq_num: seq,
        state: state,
        timeout: timeout,
        session_id: session_id
    };

    let encoded = MultiApp::encode_app_state(app_state.clone());
    let sig_1 = players_pair[0].sign(&encoded);
    let sig_2 = players_pair[1].sign(&encoded);
    let state_proof = StateProof {
        app_state: app_state,
        sigs: vec![sig_1, sig_2]
    };

    return state_proof;
}