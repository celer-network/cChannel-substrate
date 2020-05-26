use codec::{Encode, Decode};
use frame_support::{ensure, storage::{StorageMap}};
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_system::{self as system, ensure_signed};
use sp_runtime::{ModuleId, DispatchError, RuntimeDebug};
use sp_runtime::traits::{AccountIdConversion, CheckedAdd};
use super::{
    Trait, Error, BalanceOf, Wallets,
};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Wallet<AccountId, Balance> {
    pub owners: Vec<AccountId>,
    pub balance: Balance,
}

pub type WalletOf<T> = Wallet<<T as system::Trait>::AccountId, BalanceOf<T>>;

pub const WALLET_ID: ModuleId = ModuleId(*b"_wallet_");

pub struct CelerWallet<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> CelerWallet<T> {

    pub fn deposit_celer(
        origin: T::Origin,
        wallet_id: T::Hash,
        amount: BalanceOf<T>
    ) -> Result<(T::Hash, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances"
        );

        update_balance::<T>(caller, wallet_id.clone(), amount.clone())?;
        
        return Ok((wallet_id, amount));
    }

    
    // Currently CELER is only supported.
}

/// Add balance of Wallet
fn update_balance<T: Trait>(
    caller: T::AccountId,
    wallet_id: T::Hash,
    amount: BalanceOf<T>,
) -> Result<(), DispatchError> {
    let w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
        Some(_w) => _w,
        None => Err(Error::<T>::WalletNotExist)?
    };

    let wallet_account = celer_wallet_account::<T>();

    // Currently ETH is only supported.
    let new_amount = w.balance.checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
    
    let new_wallet: WalletOf<T> = WalletOf::<T> {
        owners: w.owners,
        balance: new_amount,
    };
    
    Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));
    
    T::Currency::transfer(
        &caller, 
        &wallet_account, 
        amount, 
        ExistenceRequirement::AllowDeath
    )?;

    Ok(())
}

fn celer_wallet_account<T: Trait>() -> T::AccountId {
    WALLET_ID.into_account()
}

#[cfg(test)]
mod tests {
    use crate::mock::*;
    use super::*;
    use crate::ledger_operation::{LedgerOperation};
    use crate::ledger_operation::tests::*;

    #[test]
    fn test_pass_deposit_celer() {
        ExtBuilder::build().execute_with(|| {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let wallet_id = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            let (_wallet_id, _amount) 
                = CelerWallet::<TestRuntime>::deposit_celer(Origin::signed(channel_peers[0]), wallet_id, 100).unwrap();
            assert_eq!(_wallet_id, wallet_id);
            assert_eq!(_amount, 100);
        })
    }

    #[test]
    fn test_fail_deposit_celer_because_peer_does_not_have_enough_balance() {
        ExtBuilder::build().execute_with(||  {
            let alice_pair = account_pair("Alice");
            let bob_pair = account_pair("Bob");
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let wallet_id = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            let err = CelerWallet::<TestRuntime>::deposit_celer(Origin::signed(channel_peers[0]), wallet_id, 2000).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller does not have enough balances")); 
        })
    }
}
