use super::*;
use crate::{Error, mock::*};
use sp_core::{hashing, Pair, H256};

#[test]
fn test_fail_initiate_and_first_apply_action() {
    ExtBuilder::build().execute_with(|| {
        let alice_pair = account_pair("Alice");
        let bob_pair = account_pair("Bob");        
    }
}