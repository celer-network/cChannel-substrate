#![cfg_attr(not(feature = "std"), no_std)]
use ink_lang as ink;
use schnorrkel::{PublicKey,Signature,signing_context};

#[ink::contract]
mod boolean_outcome_app {
    use super::*;
    use ink_storage::{
        collections::{
            Vec as StorageVec,
        },
        traits::{
            PackedLayout,
            SpreadLayout,
        },
    };
    use ink_prelude::{vec::Vec, vec};
    use scale::Encode;

    const SIGNING_CTX: &[u8] = b"substrate";

    #[derive(PartialEq, scale::Encode, scale::Decode, Debug, Clone, Copy, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout)
    )]
    pub enum AppStatus {
        Idle = 0,
        Settle = 1,
        Action = 2,
        Finalized = 3, 
    }   

    #[derive(Clone, scale::Encode, scale::Decode, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct AppState {
        pub state: u8,
        pub nonce: u128,
        pub seq_num: u128,
        pub timeout: BlockNumber,
    }

    #[derive(scale::Encode, scale::Decode, SpreadLayout, PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct AppInitiateRequest {
        pub nonce: u128,
        pub players: Vec<AccountId>,
        pub timeout: BlockNumber
    }

    #[ink(storage)]
    pub struct BooleanOutcomeApp {
        state: u8,
        nonce: u128,
        players: StorageVec<AccountId>,
        seq_num: u128,
        timeout: BlockNumber,
        deadline: BlockNumber,
        status: AppStatus,
    }

    #[ink(event)]
    pub struct IntendSettle {
        #[ink(topic)]
        contract_address: AccountId,
        seq_num: u128,
    }

    impl BooleanOutcomeApp {
        #[ink(constructor)]
        pub fn new(
            initiate_request: AppInitiateRequest
        ) -> Self {
            let players: StorageVec<_> = initiate_request.players.iter().copied().collect();
            // Panic if accounts is not asscending order
            assert!(players[0] < players[1]);
            Self {
                state: 0,
                nonce: initiate_request.nonce,
                players: players,
                seq_num: 0,
                timeout: initiate_request.timeout,
                deadline: 0,
                status: AppStatus::Idle
            }
        }

        /// Update state according to an off-chain state proof
        /// 
        /// Parameter:
        /// `app_state`: Signed off-chain app state
        /// `sigs`: Signatures of app_state
        #[ink(message)]
        pub fn update_by_state(
            &mut self,
            app_state: AppState,
            sigs: [u8; 128],
        ) {
            self.intend_settle(app_state.clone(), sigs);
            self.state = app_state.state;
            if app_state.state == 1 || app_state.state == 2 {
                self.status = AppStatus::Finalized;
            }
            self.env().emit_event(IntendSettle {
                contract_address: self.env().account_id(),
                seq_num: app_state.seq_num,
            });
        }

        /// Update state according to an on-chain action
        ///
        /// Parameter:
        /// `_action`: Action data
        #[ink(message)]
        pub fn update_by_action(
            &mut self,
            action: u8,
        ) {
            self.apply_action();
            self.state = action;
            if action == 1 || action == 2 {
                self.status = AppStatus::Finalized;
            }
        }

        /// Check whether app is finalized
        /// Return:
        /// True if app is finalized
        #[ink(message)]
        pub fn is_finalized(&self) -> bool {
            self.status == AppStatus::Finalized 
        }

        /// Get the app outcome
        ///
        /// Parameter:
        /// `_query`: Query key
        ///
        /// Return:
        /// True if query satisfied
        #[ink(message)]
        pub fn get_outcome(
            &self,
            _query: u8,    
        ) -> bool {
            self.state == _query
        }

        /// Get the app state
        #[ink(message)]
        pub fn get_app_state(
            &self
        ) -> u8 {
            self.state
        }

        /// Finalize in case of on-chain action timeout
        #[ink(message)]
        pub fn finalize_on_timeout(&mut self) {
            if self.status == AppStatus::Action {
                // Panic if deadline no passes
                assert!(self.env().block_number() > self.deadline);
            } else if self.status == AppStatus::Settle {
                // Panic if while settling
                assert!(self.env().block_number() > self.deadline + self.timeout);
            } else {
                return;
            }
            self.status = AppStatus::Finalized;
        }

        /// Get AppStatus
        #[ink(message)]
        pub fn get_status(&self) -> u8 {
            self.status as u8
        }

        /// Get state settle finalized time
        #[ink(message)]
        pub fn get_settle_finalized_time(&self) -> Option<BlockNumber> {
            if self.status == AppStatus::Settle {
                return Some(self.deadline);
            }
            None
        }

        /// Get action deadline
        #[ink(message)]
        pub fn get_action_deadline(&self) -> Option<BlockNumber> {
            let current_status = self.status;
            let current_deadline = self.deadline;
            if current_status == AppStatus::Action {
                Some(current_deadline)
            } else if current_status == AppStatus::Settle {
                Some(current_deadline + self.timeout)
            } else {
                None
            }
        }

        /// Get app sequence number
        #[ink(message)]
        pub fn get_seq_num(&self) -> u128 {
            self.seq_num
        }

        fn intend_settle(
            &mut self,
            app_state: AppState,
            sigs: [u8; 128]
        ) {
            // Panic if signature is invalid
            let message = encode_app_state(app_state.clone());
            assert!(self.valid_signers(sigs, &message) == true);
            // Panic if AppStatus is Finalized
            assert!(self.status != AppStatus::Finalized);
            // Panic if app nonce is not match
            assert!(self.nonce == app_state.nonce);
            // Panic if invalid sequence number
            assert!(self.seq_num < app_state.seq_num);

            self.seq_num = app_state.seq_num;
            self.deadline = self.env().block_number() + self.timeout;
            self.status = AppStatus::Settle;
        }

        fn apply_action(&mut self) {
            // Panic if AppStatus is Finalized
            assert!(self.status != AppStatus::Finalized);
            if self.status == AppStatus::Settle && self.env().block_number() > self.deadline {
                self.seq_num += 1;
                self.deadline = self.env().block_number() + self.timeout;  
                self.status = AppStatus::Action;
            } else {
                // Panic if app not in action mode
                assert!(self.status == AppStatus::Action);
                self.seq_num += 1;
                self.deadline = self.env().block_number() + self.timeout;  
                self.status = AppStatus::Action;
            }
        }

        fn valid_signers(
            &mut self, 
            sigs: [u8; 128],
            message: &[u8]
        ) -> bool {
            let signatures = vec![
                Signature::from_bytes(&sigs[..64]).unwrap(),
                Signature::from_bytes(&sigs[64..]).unwrap()
            ];
            let mut i = 0;
            for sig in signatures.into_iter() {
                let signer = self.players[i];
                let context = signing_context(b"this signature does this thing");
                match PublicKey::from_bytes(&signer.encode()) {
                    Ok(pk) => {
                        if pk.verify(context.bytes(message), &sig).is_ok() == false {
                            return false;
                        }
                    },
                    Err(_err) => return false,
                } 
                i += 1;
            }
            true
        }
    }

    fn encode_app_state(
        app_state: AppState,
    ) -> Vec<u8> {
        let mut encoded = app_state.state.encode();
        encoded.extend(app_state.seq_num.encode());
        encoded.extend(app_state.timeout.encode());
        encoded
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_env::test;
        use schnorrkel::{Keypair, signing_context};

        fn accounts_setup() -> (Vec<Keypair>, Vec<AccountId>) {
            let key_pair0 = Keypair::generate();
            let key_pair1 = Keypair::generate();
            let account0 = AccountId::from(key_pair0.public.to_bytes());
            let account1 = AccountId::from(key_pair1.public.to_bytes());
            if account0 < account1 {
                (vec![key_pair0, key_pair1], vec![account0, account1])
            } else {
                (vec![key_pair1, key_pair0], vec![account1, account0])
            }
        }

        fn advance_blocks(num: u64) {
            for _i in 0..num {
                test::advance_block::<ink_env::DefaultEnvironment>().unwrap();
            }
        }

        fn get_initiate_request(
            nonce: u128,
            players: Vec<AccountId>,
            timeout: BlockNumber,
        ) -> AppInitiateRequest {
            AppInitiateRequest {
                nonce: nonce,
                players: players,
                timeout: timeout,
            }
        }

        fn get_state_proof(
            state: u8,
            nonce: u128,
            seq: u128,
            timeout: BlockNumber,
            players_pair: Vec<Keypair>,
        ) -> (AppState, [u8; 128]) {
            let app_state = AppState {
                state: state,
                nonce: nonce,
                seq_num: seq,
                timeout: timeout,
            };
            let message = encode_app_state(app_state.clone());
            let context = signing_context(b"this signature does this thing");
            let sig0 = players_pair[0].sign(context.bytes(&message));
            let sig1 = players_pair[1].sign(context.bytes(&message));
            let mut sigs = [0u8; 128];
            sigs[0..64].copy_from_slice(&sig0.to_bytes());
            sigs[64..128].copy_from_slice(&sig1.to_bytes());

            (app_state, sigs)
        }

        fn encode_app_state(
            app_state: AppState,
        ) -> Vec<u8> {
            let mut encoded = app_state.state.encode();
            encoded.extend(app_state.seq_num.encode());
            encoded.extend(app_state.timeout.encode());
            encoded
        }

        #[test]
        fn initiate_works() {
            let (_, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            BooleanOutcomeApp::new(initiate_request);
        }

       
        #[test]
        #[should_panic]
        fn not_orderd_players() {
            let (_, accounts) = accounts_setup();
            let initiate_request = AppInitiateRequest {
                nonce: 0,
                players: vec![accounts[1], accounts[0]],
                timeout: 2,
            };
            BooleanOutcomeApp::new(initiate_request);
        }

        #[test]
        #[should_panic]
        fn update_by_action_fail() {
            let (_, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            // app not in action mode
            boolean_outcome_app.update_by_action(1);
        }

        #[ink::test]
        fn update_by_state_works() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let state_proof = get_state_proof(5, 0, 2, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            assert_eq!(boolean_outcome_app.get_outcome(5), true);
            assert_eq!(boolean_outcome_app.is_finalized(), false);
        }

        #[ink::test]
        #[should_panic]
        fn invalid_sigs_fail() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let app_state = AppState {
                state: 5,
                nonce: 0,
                seq_num: 2,
                timeout: 2,
            };
            let message = encode_app_state(app_state.clone());
            let context = signing_context(b"this signature does this thing");
            let sig0 = players_pair[0].sign(context.bytes(&message));
            let sig1 = players_pair[1].sign(context.bytes(&message));
            let mut invalid_sigs = [0u8; 128];
            invalid_sigs[0..64].copy_from_slice(&sig1.to_bytes());
            invalid_sigs[64..128].copy_from_slice(&sig0.to_bytes());
            boolean_outcome_app.update_by_state(app_state, invalid_sigs);
        }

        #[ink::test]
        #[should_panic]
        fn update_by_action_before_settle_finalized_time_should_fail() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let state_proof = get_state_proof(5, 0, 2, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            boolean_outcome_app.update_by_action(1);
        }

        #[ink::test]
        fn update_by_action_works() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let state_proof = get_state_proof(5, 0, 2, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            let settle_finalized_time = boolean_outcome_app.get_settle_finalized_time().unwrap();
            advance_blocks(settle_finalized_time + 1);
            boolean_outcome_app.update_by_action(1);
            assert_eq!(boolean_outcome_app.get_outcome(1), true);
        }

        #[ink::test]
        #[should_panic]
        fn update_by_state_with_invalid_seq_num_fail() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            // Invalid sequence number
            let state_proof = get_state_proof(5, 0, 0, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
        }

        #[ink::test]
        fn update_by_state_and_finalized() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let state_proof = get_state_proof(2, 0, 2, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            assert_eq!(boolean_outcome_app.get_outcome(2), true);
            assert_eq!(boolean_outcome_app.is_finalized(), true);
        }

        #[ink::test]
        #[should_panic]
        fn update_by_action_after_finalized_fail() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let state_proof = get_state_proof(2, 0, 2, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            boolean_outcome_app.update_by_action(2);
        }

        #[ink::test]
        #[should_panic]
        fn update_by_state_after_finalized_fail() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let mut state_proof = get_state_proof(2, 0, 2, 2, players_pair.clone());
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            state_proof = get_state_proof(2, 0, 3, 2, players_pair);
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
        }

        #[ink::test]
        fn finalize_on_timeout_works() {
            let (players_pair, accounts) = accounts_setup();
            let initiate_request = get_initiate_request(0, accounts, 2);
            let mut boolean_outcome_app = BooleanOutcomeApp::new(initiate_request);
            let state_proof = get_state_proof(2, 0, 2, 2, players_pair.clone());
            boolean_outcome_app.update_by_state(state_proof.0, state_proof.1);
            advance_blocks(5);
            boolean_outcome_app.finalize_on_timeout();
            assert_eq!(boolean_outcome_app.is_finalized(), true);
        }
    }
}
