#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use frame_support::{
    decl_module, decl_storage, decl_event, decl_error, ensure,
    storage::StorageMap,
    dispatch::{DispatchResult, DispatchError},
    weights::{Weight},
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{
    Hash, IdentifyAccount, AccountIdConversion, 
    Member, Verify, Zero, 
};
use sp_runtime::{ModuleId, RuntimeDebug};
use sp_std::{prelude::*, vec::Vec};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SessionInitiateRequest<AccountId, BlockNumber> {
    pub nonce: u128,
    pub player_num: u8,
    pub players: Vec<AccountId>,
    pub timeout: BlockNumber,
}

pub type SessionInitiateRequestOf<T> = SessionInitiateRequest<
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct AppState<BlockNumber, Hash> {
    pub seq_num: u128,
    pub state: u8,
    pub timeout: BlockNumber,
    pub session_id: Hash,
}

pub type AppStateOf<T> = AppState<
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::Hash,
>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct StateProof<BlockNumber, Hash, Signature> {
    pub app_state: AppState<BlockNumber, Hash>,
    pub sigs: Vec<Signature>,
}

pub type StateProofOf<T> = StateProof<
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::Hash,
    <T as Trait>::Signature,
>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum SessionStatus {
    Idle = 0,
    Settle = 1,
    Action = 2,
    Finalized = 3,
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SessionInfo<AccountId, BlockNumber> {
    pub state: u8,
    pub players: Vec<AccountId>,
    pub player_num: u8,
    pub seq_num: u128,
    pub timeout: BlockNumber,
    pub deadline: BlockNumber,
    pub status: SessionStatus,
}

pub type SessionInfoOf<T> = SessionInfo<
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
>;

pub const MULTI_SESSION_APP_ID: ModuleId = ModuleId(*b"_multi__");

pub trait Trait: system::Trait + celer_pay::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId>;
    type Signature: Verify<Signer = <Self as Trait>::Public> + Member + Decode + Encode; 
}

decl_storage! {
    trait Store for Module<T: Trait> as SingleSessionApp {
        pub SessionInfoMap get(fn session_info):
            map hasher(blake2_128_concat) T::Hash => Option<SessionInfoOf<T>>;
    }
}

decl_module!  {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        /// Initiate multi session app
        #[weight = 10_000]
        fn session_initiate(
            origin,
            initiate_request: SessionInitiateRequestOf<T>
        ) -> DispatchResult {
            let session_hash = Self::hashing_initiate_request(initiate_request.clone());
            let session_id = Self::calculate_session_id(session_hash);
            ensure!(
                SessionInfoMap::<T>::contains_key(&session_id) == false,
                "session_id is used"
            );

            let session_info = SessionInfoOf::<T> {
                state: 0,
                players: initiate_request.players,
                player_num: initiate_request.player_num,
                seq_num: 0,
                timeout: initiate_request.timeout,
                deadline: Zero::zero(),
                status: SessionStatus::Idle,
            };
            SessionInfoMap::<T>::insert(session_id, session_info);
        
            Ok(())
        }

        /// Update state according to an off-chain state proof
        #[weight = 10_000]
        fn update_by_state(
            origin,
            state_proof: StateProofOf<T>
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // submit ad settle off-chain state
            let mut new_session_info: SessionInfoOf<T> = Self::intend_settle(state_proof.clone())?;
            
            let state = state_proof.app_state.state;
            if state == 1 || state == 2 {
                new_session_info = SessionInfoOf::<T> {
                    state: state,
                    players: new_session_info.players,
                    player_num: new_session_info.player_num,
                    seq_num: new_session_info.seq_num,
                    timeout: new_session_info.timeout,
                    deadline: new_session_info.deadline,
                    status: SessionStatus::Finalized
                }
            } else {
                new_session_info = SessionInfoOf::<T> {
                    state: state,
                    players: new_session_info.players,
                    player_num: new_session_info.player_num,
                    seq_num: new_session_info.seq_num,
                    timeout: new_session_info.timeout,
                    deadline: new_session_info.deadline,
                    status: new_session_info.status
                }
            }
            let session_id = state_proof.app_state.session_id;
            SessionInfoMap::<T>::mutate(&session_id, |session_info| *session_info = Some(new_session_info.clone()));

            // emit IntendSettle event
            Self::deposit_event(Event::<T>::IntendSettle(session_id, new_session_info.seq_num));

            Ok(())
        }
        

        /// Update state according to an on-chain action
        #[weight = 10_000]
        fn update_by_action(
            origin,
            session_id: T::Hash,
            action: u8
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let mut new_session_info: SessionInfoOf<T> = Self::apply_action(session_id)?;
        
            if action == 1 || action == 2 {
                new_session_info = SessionInfoOf::<T> {
                    state: new_session_info.state,
                    players: new_session_info.players,
                    player_num: new_session_info.player_num,
                    seq_num: new_session_info.seq_num,
                    timeout: new_session_info.timeout,
                    deadline: new_session_info.deadline,
                    status: SessionStatus::Finalized,
                }
            } 
            SessionInfoMap::<T>::mutate(&session_id, |session_info| *session_info = Some(new_session_info));

            Ok(())
        }

        /// Finalize in case of on-chain action timeout
        #[weight = 10_000]
        fn finalize_on_action_timeout(
            origin,
            session_id: T::Hash
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let session_info = match SessionInfoMap::<T>::get(session_id) {
                Some(session) => session,
                None => Err(Error::<T>::SessionInfoNotExist)?,
            };
            
            let block_number = frame_system::Module::<T>::block_number();
            if session_info.status == SessionStatus::Action {
                ensure!(
                    block_number >  session_info.deadline,
                    "deadline does not passes"
                );
            } else if session_info.status == SessionStatus::Settle {
                ensure!(
                    block_number > session_info.deadline + session_info.timeout,
                    "while setting"
                );
            } else {
                return Ok(());
            }

            let new_session_info = SessionInfoOf::<T> {
                state: session_info.state,
                players: session_info.players,
                player_num: session_info.player_num,
                seq_num: session_info.seq_num,
                timeout: session_info.timeout,
                deadline: session_info.deadline,
                status: SessionStatus::Finalized,
            };
            SessionInfoMap::<T>::mutate(&session_id, |session_info| *session_info = Some(new_session_info));

            Ok(())
        }

        /// Get the session outcome
        #[weight = 10_000]
        pub fn get_outcome(
            origin,
            session_id: T::Hash,
            query: u8
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let session_info = match SessionInfoMap::<T>::get(session_id) {
                Some(session) => session,
                None => Err(Error::<T>::SessionInfoNotExist)?,
            };

            // If outcome is false, return Error::<T>::OutcomeFalse
            ensure!(
                session_info.state == query,
                Error::<T>::OutcomeFalse
            );

            // If outcome is true, return Ok(())
            Ok(())
        }

        /// Check whether session is finalized
        #[weight = 10_000]
        pub fn get_finalized(
            origin,
            session_id: T::Hash,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let session_info = match SessionInfoMap::<T>::get(session_id) {
                Some(session) => session,
                None => return Err(Error::<T>::SessionInfoNotExist)?,
            };

            // If session is not finlized, return Error::<T>::NotFinalized
            ensure!(
                session_info.status == SessionStatus::Finalized,
                Error::<T>::NotFinalized
            );

            // If session is finalized, return Ok(())
            Ok(())
        }
    }
}

decl_event! (
    pub enum Event<T> where
        <T as system::Trait>::Hash
    {
        /// IntendSettle(session_id, seq_num)
        IntendSettle(Hash, u128),
    }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        // SessionInfo is not exist
        SessionInfoNotExist,
        // App outcome is false
        OutcomeFalse,
        // App status is not Finalized
        NotFinalized,
    }
}

impl<T: Trait> Module<T> {
    fn intend_settle(
        state_proof: StateProofOf<T>
    ) -> Result<SessionInfoOf<T>, DispatchError> {
        let app_state = state_proof.app_state;
        let session_info = match SessionInfoMap::<T>::get(app_state.session_id) {
            Some(session) => session,
            None => Err(Error::<T>::SessionInfoNotExist)?,
        };
        ensure!(
            state_proof.sigs.len() as u8 == session_info.player_num,
            "invalid number of players"
        );
        let encoded = Self::encode_app_state(app_state.clone());
        Self::valid_signers(state_proof.sigs, &encoded, session_info.players.clone())?;
        ensure!(
            session_info.status != SessionStatus::Finalized,
            "app state is finalized"
        );
    
        ensure!(
            session_info.seq_num < app_state.seq_num,
            "invalid sequence number"
        );

        let block_number = frame_system::Module::<T>::block_number();
        let new_session_info = SessionInfoOf::<T> {
            state: session_info.state,
            players: session_info.players,
            player_num: session_info.player_num,
            seq_num: app_state.seq_num,
            timeout: session_info.timeout,
            deadline: block_number + session_info.timeout,
            status: SessionStatus::Settle
        };

        Ok(new_session_info)
    }

    /// Apply an action to the on-chain state
    fn apply_action(
        session_id: T::Hash,
    ) -> Result<SessionInfoOf<T>, DispatchError> {
        let session_info = match SessionInfoMap::<T>::get(session_id) {
            Some(session) => session,
            None => Err(Error::<T>::SessionInfoNotExist)?,
        };
        ensure!(
            session_info.status != SessionStatus::Finalized,
            "app state is finalized"
        );

        let block_number =  frame_system::Module::<T>::block_number();
        let new_session_info: SessionInfoOf<T>;
        if session_info.status == SessionStatus::Action && block_number > session_info.deadline {
            new_session_info = SessionInfoOf::<T> {
                state: session_info.state,
                players: session_info.players,
                player_num: session_info.player_num,
                seq_num:  session_info.seq_num + 1,
                timeout: session_info.timeout,
                deadline: block_number + session_info.timeout,
                status: SessionStatus::Action
            };
        } else {
            ensure!(
                session_info.status ==  SessionStatus::Action,
                "app not in action mode"
            );
            new_session_info = SessionInfoOf::<T> {
                state: session_info.state,
                players: session_info.players,
                player_num: session_info.player_num,
                seq_num:  session_info.seq_num + 1,
                timeout: session_info.timeout,
                deadline: block_number + session_info.timeout,
                status: SessionStatus::Action
            };
        }

        Ok(new_session_info)
    }

    /// get session id
    pub fn calculate_session_id(session_hash: T::Hash) -> T::Hash {
        let multi_session_app_account = Self::app_account();
        let mut encoded = session_hash.encode();
        encoded.extend(multi_session_app_account.encode());
        let session_id = T::Hashing::hash(&encoded);
        return session_id;
    }

    /// get session state
    pub fn get_state(session_id: T::Hash) -> Option<u8> {
        let session_info = match SessionInfoMap::<T>::get(session_id) {
            Some(session) => session,
            None => return None,
        };

        return Some(session_info.state);
    }

    /// get session status
    pub fn get_status(session_id: T::Hash) -> Option<SessionStatus> {
        let session_info = match SessionInfoMap::<T>::get(session_id) {
            Some(session) => session,
            None => return None,
        };

        return Some(session_info.status);
    }

    /// get state settle finalized time
    pub fn get_settle_finalized_time(session_id: T::Hash) -> Option<T::BlockNumber> {
        let session_info = match SessionInfoMap::<T>::get(session_id) {
            Some(session) => session,
            None => return None,
        };

        if session_info.status == SessionStatus::Settle {
            return Some(session_info.deadline);
        }

        return None;
    }

    /// get action deadline
    pub fn get_action_deadline(session_id: T::Hash) -> Option<T::BlockNumber> {
        let session_info = match SessionInfoMap::<T>::get(session_id) {
            Some(session) => session,
            None => return None,
        };
        if session_info.status == SessionStatus::Action {
            return Some(session_info.deadline);
        } else if session_info.status == SessionStatus::Settle {
            return Some(session_info.deadline + session_info.timeout);
        } else {
            return None;
        }
    }

    /// get session sequence number
    pub fn get_seq_num(session_id: T::Hash) -> Option<u128> {
        let session_info = match SessionInfoMap::<T>::get(session_id) {
            Some(session) => session,
            None => return None,
        };     
        return Some(session_info.seq_num);
    }


    /// get multi session app account id
    pub fn app_account() -> T::AccountId {
        MULTI_SESSION_APP_ID.into_account()
    }

    /// check signature
    pub fn valid_signers(
        signatures: Vec<<T as Trait>::Signature>,
        encoded: &[u8],
        signers: Vec<T::AccountId>,
    ) -> Result<(), DispatchError> {
        for i in 0..signers.len() {
            let signature = &signatures[i];
            ensure!(
                signature.verify(encoded, &signers[i]),
                "Checl sigs failed"
            );
        }

        Ok(())
    }

    /// check whether accoun is asscending order
    pub fn boolean_ordered_account(
        players: Vec<T::AccountId>
    ) -> Result<(), DispatchError> {
        let mut prev = &players[0];
        for i in 1..players.len() {
            ensure!(
                prev < &players[1],
                "player is not ascending order"
            );
            prev = &players[i];
        }

        Ok(())
    }

    pub fn hashing_initiate_request(
        initiate_request: SessionInitiateRequestOf<T>
    ) -> T::Hash {
        let app_account = Self::app_account();
        let mut encoded = app_account.encode();
        encoded.extend(initiate_request.nonce.encode());
        encoded.extend(initiate_request.timeout.encode());
        initiate_request.players.into_iter()
            .for_each(|players| { encoded.extend(players.encode()); });
        let session_hash: T::Hash = T::Hashing::hash(&encoded);
        return session_hash;
    }

    pub fn encode_app_state(
        app_state: AppStateOf<T>
    ) -> Vec<u8> {
        let mut encoded = app_state.seq_num.encode();
        encoded.extend(app_state.state.encode());
        encoded.extend(app_state.timeout.encode());
        encoded.extend(app_state.session_id.encode());

        return encoded;
    }
}

   