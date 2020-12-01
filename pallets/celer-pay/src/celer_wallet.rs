use super::{Module as CelerPayModule, BalanceOf, Error, Wallets, RawEvent};
use crate::traits::Trait;
use codec::{Decode, Encode};
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_support::{ensure, storage::StorageMap};
use frame_system::{self as system, ensure_signed};
use sp_std::{vec::Vec, vec};
use sp_runtime::traits::{CheckedAdd, CheckedSub, Hash, Zero};
use sp_runtime::{ModuleId, RuntimeDebug, DispatchError};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Wallet<AccountId, Balance> {
    pub owners: Vec<AccountId>,
    pub balance: Balance,
}

pub type WalletOf<T> = Wallet<<T as system::Trait>::AccountId, BalanceOf<T>>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum MathOperation {
    Add,
    Sub,
}

pub const WALLET_ID: ModuleId = ModuleId(*b"_wallet_");

pub struct CelerWallet<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> CelerWallet<T> {
    // Create a new wallet
    pub fn create_wallet(
        origin: T::Origin,
        peers: Vec<T::AccountId>,
        nonce: T::Hash
    ) -> Result<T::Hash, DispatchError> {
        let caller = ensure_signed(origin)?;
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(caller == celer_ledger_account, "Caler is not Celer Ledger module",);

        let wallet_id = create_wallet_id::<T>(peers.clone(), nonce);

        // Check wallet_id is not exist.
        ensure!(
            Wallets::<T>::contains_key(&wallet_id) == false,
            "Occupied wallet id"
        );

        let wallet = WalletOf::<T> {
            owners: peers.clone(),
            balance: Zero::zero(),
        };
        // Create new wallet
        Wallets::<T>::insert(&wallet_id, &wallet);

        // Emit CreateWallet event
        CelerPayModule::<T>::deposit_event(RawEvent::CreateWallet(
            wallet_id,
            peers
        ));

        Ok(wallet_id)
    }

    // Deposit native token to wallet
    pub fn deposit_native_token(
        caller: T::AccountId,
        wallet_id: T::Hash,
        msg_value: BalanceOf<T>,
    ) -> Result<(T::Hash, BalanceOf<T>), DispatchError> {
        update_balance::<T>(caller, wallet_id.clone(), MathOperation::Add, msg_value.clone())?;

        // Emit DepositToWallet event
        CelerPayModule::<T>::deposit_event(RawEvent::DepositToWallet(
            wallet_id, 
            msg_value
        ));
        return Ok((wallet_id, msg_value));
    }

    // Withdraw funds to an address
    pub fn withdraw(
        origin: T::Origin,
        wallet_id: T::Hash,
        receiver: T::AccountId,
        amount: BalanceOf<T>
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(caller == celer_ledger_account, "Caler is not Celer Ledger module",);

        update_balance::<T>(receiver.clone(), wallet_id, MathOperation::Sub, amount)?;
        
        // Emit WithdrawFromWallet Event
        CelerPayModule::<T>::deposit_event(RawEvent::WithdrawFromWallet(
            wallet_id, 
            receiver, 
            amount
        ));
        Ok(())
    }

    // Transfer funds from one wallet to another wallet with a same owner (as the receriver)
    pub fn transfer_to_wallet(
        origin: T::Origin,
        from_wallet_id: T::Hash,
        to_wallet_id: T::Hash,
        receiver: T::AccountId,
        amount: BalanceOf<T>,
    ) -> Result<(), DispatchError> {
        let caller = ensure_signed(origin)?;
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(caller == celer_ledger_account, "Caler is not Celer Ledger module",);

        ensure!(
            is_wallet_owner::<T>(from_wallet_id, receiver.clone())
                && is_wallet_owner::<T>(to_wallet_id, receiver.clone()),
            "receiver is not wallet owner"
        );

        update_balance::<T>(receiver.clone(), from_wallet_id, MathOperation::Sub, amount)?;
        update_balance::<T>(receiver.clone(), to_wallet_id, MathOperation::Add, amount)?;

        Ok(())
    }
}

fn create_wallet_id<T: Trait>(
    peers: Vec<T::AccountId>,
    nonce: T::Hash
) -> T::Hash {
    let mut encoded = vec![];
    peers.into_iter().for_each(|peer| {
        encoded.extend(peer.encode());
    });
    encoded.extend(nonce.encode());
    let wallet_id = T::Hashing::hash(&encoded);

    return wallet_id;
}

/// Add balance of Wallet
fn update_balance<T: Trait>(
    caller: T::AccountId,
    wallet_id: T::Hash,
    op: MathOperation,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    let mut w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
        Some(_w) => _w,
        None => Err(Error::<T>::WalletNotExist)?,
    };

    let celer_wallet_account = CelerPayModule::<T>::get_celer_wallet_id();
    if op == MathOperation::Sub {
        ensure!(w.balance >= amount, "balance of amount is not deposited");
        
        w.balance = w.balance.checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(w));

        <T as Trait>::Currency::transfer(
            &celer_wallet_account,
            &caller,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;
    } else if op == MathOperation::Add {
        ensure!(
            <T as Trait>::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances"
        );
        
        w.balance = w.balance.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(w));

        <T as Trait>::Currency::transfer(
            &caller,
            &celer_wallet_account,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;
    } else {
        Err(Error::<T>::Error)?
    }

    Ok(())
}

fn is_wallet_owner<T: Trait>(wallet_id: T::Hash, addr: T::AccountId) -> bool {
    let w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
        Some(_w) => _w,
        None => return false,
    };
    for i in 0..w.owners.len() {
        if addr == w.owners[i] {
            return true;
        }
    }
    return false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::ledger_operation::test_ledger_operation::*;
    use crate::ledger_operation::LedgerOperation;
    use crate::mock::*;

    #[test]
    fn test_pass_deposit_native_token() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let wallet_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let (_wallet_id, _amount) = CelerWallet::<TestRuntime>::deposit_native_token(
                channel_peers[0],
                wallet_id,
                100,
            ).unwrap();
            assert_eq!(_wallet_id, wallet_id);
            assert_eq!(_amount, 100);
        })
    }

    #[test]
    fn test_fail_deposit_native_token_because_peer_does_not_have_enough_balance() {
        ExtBuilder::build().execute_with(|| {   
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair) = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let wallet_id = LedgerOperation::<TestRuntime>::open_channel(
                Origin::signed(channel_peers[1]),
                open_channel_request.clone(),
                0,
            ).unwrap();

            let err = CelerWallet::<TestRuntime>::deposit_native_token(
                channel_peers[0],
                wallet_id,
                2000,
            ).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Other("caller does not have enough balances")
            );
        })
    }
}
