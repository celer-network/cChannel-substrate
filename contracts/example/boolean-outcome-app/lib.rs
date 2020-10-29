#![cfg_attr(not(feature = "std"), no_std)]
use ink_lang as ink;

#[ink::contract]
mod boolean_outcome_app {
    use ink_storage::traits::{
        PackedLayout,
        SpreadLayout,
    };

    #[ink(storage)]
    pub struct BooleanOutcomeApp {
        state: u8
    }

    impl BooleanOutcomeApp {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                state: 0,
            }
        }

        /// Update state according to an off-chain state proof
        /// 
        /// Parameter:
        /// `_state`: Signed off-chain app state
        /// 
        /// Return:
        /// If AppStatus will transition, return destination AppStatus(i8),
        /// else return -1(i8).
        #[ink(message)]
        pub fn update_by_state(
            &mut self,
            _state: u8,
        ) -> i8 {
            self.state = _state;
            let mut destination_app_status: i8 = -1;
            if _state == 1 || _state == 2 {
                destination_app_status = AppStatus::Finalized as i8;
            }
            return destination_app_status;
        }

        /// Update state according to an on-chain action
        ///
        /// Parameter:
        /// `_action`: Action data
        ///
        /// Return:
        /// If AppStatus will transition, return destination AppStatus(i8),
        /// else return -1(i8).
        #[ink(message)]
        pub fn update_by_action(
            &mut self,
            _action: u8,
        ) -> i8 {
            self.state = _action;
            let mut destination_app_status: i8 = -1;
            if self.state == 1 || self.state == 2 {
                destination_app_status = AppStatus::Finalized as i8;
            }
            return destination_app_status;
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
            return self.state == _query;
        }

        /// Get the app state
        #[ink(message)]
        pub fn get_app_state(
            &self
        ) -> u8 {
            self.state
        }
    }

    #[derive(scale::Encode, scale::Decode, Clone, Copy, SpreadLayout, PackedLayout)]
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn update_by_state_and_finalized() {
            let mut boolean_outcome_app = BooleanOutcomeApp::new();
            assert_eq!(boolean_outcome_app.update_by_state(1), 3);
            assert_eq!(boolean_outcome_app.get_app_state(), 1);
        }

        #[test]
        fn update_by_action_and_finalized() {
            let mut boolean_outcome_app = BooleanOutcomeApp::new();
            assert_eq!(boolean_outcome_app.update_by_action(1), 3);
            assert_eq!(boolean_outcome_app.get_app_state(), 1);
        }

        #[test]
        fn get_outcome() {
            let mut boolean_outcome_app = BooleanOutcomeApp::new();
            assert_eq!(boolean_outcome_app.update_by_action(1), 3);
            assert_eq!(boolean_outcome_app.get_outcome(1), true);
        }
    }
}
