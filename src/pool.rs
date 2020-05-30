
use frame_support::{ensure, storage::{StorageMap, StorageDoubleMap}};
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_system::ensure_signed;
use sp_runtime::{ModuleId, DispatchError};
use sp_runtime::traits::{AccountIdConversion, CheckedAdd, CheckedSub};
use super::{
    Trait, Module, Error, BalanceOf, Balances, Allowed, Wallets
};
use crate::celer_wallet::{WALLET_ID, WalletOf};
use crate::ledger_operation::{CELER_LEDGER_ID};

pub const POOL_ID: ModuleId = ModuleId(*b"_pool_id");

pub struct Pool<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> Pool<T> {
    // Dposit Celer to Pool
    pub fn deposit_pool(
        origin: T::Origin,
        receiver: T::AccountId,
        amount: BalanceOf<T>,
    ) -> Result<(T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        ensure!(
            T::Currency::free_balance(&caller) >= amount,
            "caller does not have enough balances"
        );
        
        let pool_account = pool_account::<T>();
        ensure!(
            receiver != pool_account,
            "receiver address is pool account"
        );

        if Balances::<T>::contains_key(&receiver) == false {
            Balances::<T>::insert(&receiver, &amount);
        } else {
            let balances = Balances::<T>::get(&receiver).unwrap();
            let new_balances = balances
                    .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;
            Balances::<T>::mutate(&receiver, |balances| *balances = Some(new_balances));
        }

        T::Currency::transfer(
            &caller, 
            &pool_account, 
            amount, 
            ExistenceRequirement::AllowDeath
        )?;

        return Ok((receiver, amount));
    }

    // Withdraw celer from Pool
    pub fn withdraw( 
        origin: T::Origin,
        value: BalanceOf<T>
    ) -> Result<(T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;
        let exist_address: bool = Balances::<T>::contains_key(&caller);
        ensure!(exist_address == true, "caller's address is not exist in Pool Balances");

        let balances = Balances::<T>::get(&caller).unwrap();
        ensure!(balances >= value, "caller does not have enough balances");

        let new_balances = balances
                .checked_sub(&value).ok_or(Error::<T>::UnderFlow)?;
        Balances::<T>::mutate(&caller, |balance| *balance = Some(new_balances));

        let pool_account = pool_account::<T>();
        T::Currency::transfer(
            &pool_account, 
            &caller, 
            value, 
            ExistenceRequirement::AllowDeath
        )?;

        return Ok((caller, value));
    }

    // Approve the passed address the spend the specified amount of Celer on behalf of caller.
    pub fn approve(
        origin: T::Origin,
        spender: T::AccountId,
        value: BalanceOf<T>
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        Allowed::<T>::insert(&caller, &spender, &value);

        return Ok((caller, spender, value));
    }

    // Transfer native token from one address to another
    pub fn transfer_from(
        origin: T::Origin,
        from: T::AccountId,
        to: T::AccountId,
        value: BalanceOf<T>
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;
        
        let exist_allowed: bool = Allowed::<T>::contains_key(&from, &caller);
        ensure!(exist_allowed == true, "Corresponding Allowed not exist");
        let allowed_balances = Allowed::<T>::get(&from, &caller).unwrap();
        ensure!(allowed_balances >= value, "spender does not have enough allowed balances");
        let new_allowed_balances = allowed_balances
                .checked_sub(&value).ok_or(Error::<T>::UnderFlow)?;

        let exist_address: bool = Balances::<T>::contains_key(&from);
        ensure!(exist_address == true, "from's address is not exist in Balances");
        let balances = Balances::<T>::get(&from).unwrap();
        ensure!(balances >= value, "from address does not have enough balances");

        // Decrease Allowed balances of spender
        Allowed::<T>::mutate(&from, &caller, |balance| *balance = Some(new_allowed_balances));
        Module::<T>::emit_approval_event(from.clone(), caller.clone(), new_allowed_balances)?;

        _transfer::<T>(from.clone(), to.clone(), value)?;

        return Ok((from, to, value));
    }

    // Transfer native token from one address to a wallet in CelerWallet Module.
    pub fn transfer_to_celer_wallet(
        origin: T::Origin,
        from: T::AccountId,
        wallet_id: T::Hash,
        amount: BalanceOf<T>
    ) -> Result<(T::Hash, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;
        let w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
            Some(_w) => _w,
            None => Err(Error::<T>::WalletNotExist)?
        };

        let exist_allowed: bool = Allowed::<T>::contains_key(&from, &caller);
        ensure!(exist_allowed == true, "Corresponding Allowed not exist");

        let pool_balances = match Balances::<T>::get(&from) {
            Some(_balance) => _balance,
            None => Err(Error::<T>::BalancesNotExist)?
        };
        ensure!(pool_balances >= amount, "Wallet owner does not deposit to pool enough value");

        let allowed_balances = Allowed::<T>::get(&from, &caller).unwrap();
        ensure!(allowed_balances >= amount, "spender not have enough allowed balances");
        let new_allowed_balances = allowed_balances
                .checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        Allowed::<T>::mutate(&from, &caller, |balance| *balance = Some(new_allowed_balances));

        // Increase owner's wallet balances
        let new_wallet_balance_amount = w.balance
                .checked_add(&amount).ok_or(Error::<T>::OverFlow)?;    
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_wallet_balance_amount,
        };
        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));

        // Decrease Pool Balances
        let new_pool_balances = pool_balances
                .checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        Balances::<T>::mutate(&from, |balances| *balances = Some(new_pool_balances));

        let pool_account = pool_account::<T>();
        let wallet_account = wallet_account::<T>();
        T::Currency::transfer(&pool_account, &wallet_account, amount, ExistenceRequirement::AllowDeath)?;
        
        return Ok((wallet_id, wallet_account, amount));
    }

    // Transfer native token from one address to a wallet in CelerWallet Module.
    // This function called by Celer Ledger.
    pub fn transfer_to_celer_wallet_by_ledger(
        ledger_addr: T::AccountId,
        from: T::AccountId,
        wallet_id: T::Hash,
        amount: BalanceOf<T>
    ) -> Result<(T::Hash, T::AccountId, BalanceOf<T>), DispatchError> {
        let account = ledger_account::<T>();
        ensure!(
            ledger_addr == account,
            "Ledger Account is not invalid",
        );

        let w: WalletOf<T> = match Wallets::<T>::get(wallet_id) {
            Some(_w) => _w,
            None => return Err(Error::<T>::WalletNotExist)?
        };

        let pool_balances = match Balances::<T>::get(&from) {
            Some(_balance) => _balance,
            None => Err(Error::<T>::BalancesNotExist)?
        };
        ensure!(pool_balances >= amount, "Wallet owner does not deposit to pool enough value");

        let exist_allowed: bool = Allowed::<T>::contains_key(&from, &ledger_addr);
        ensure!(exist_allowed == true, "Corresponding Allowed not exist");

        let allowed_balances = Allowed::<T>::get(&from, &ledger_addr).unwrap();
        ensure!(allowed_balances >= amount, "spender not have enough allowed balances");
        let new_allowed_balances = allowed_balances
                .checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        Allowed::<T>::mutate(&from, &ledger_addr, |balance| *balance = Some(new_allowed_balances));

        let new_wallet_balance_amount = w.balance + amount;
        let new_wallet = WalletOf::<T> {
            owners: w.owners,
            balance: new_wallet_balance_amount,
        };
        Wallets::<T>::mutate(&wallet_id, |wallet| *wallet = Some(new_wallet));

        // Decrease Pool Balances
        let new_pool_balances = pool_balances
                .checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        Balances::<T>::mutate(&from, |balances| *balances = Some(new_pool_balances));

        let pool_account = pool_account::<T>();
        let wallet_account = wallet_account::<T>();
        T::Currency::transfer(
            &pool_account, 
            &wallet_account, 
            amount, 
            ExistenceRequirement::AllowDeath
        )?;
        
        return Ok((wallet_id, wallet_account, amount));
    }

    // Increase the amount of native token that an owner allowed to a spender.
    pub fn increase_allowance(
        origin: T::Origin,
        spender: T::AccountId,
        added_value: BalanceOf<T>
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        // Get allowed spender balances.
        let balances = match Allowed::<T>::get(&caller, &spender) {
            Some(_allowed) => _allowed,
            None => Err(Error::<T>::AllowedNotExist)?
        };
        let new_balances = balances
                .checked_add(&added_value).ok_or(Error::<T>::OverFlow)?;
        Allowed::<T>::mutate(&caller, &spender, |balance| *balance = Some(new_balances.clone()));
        
        return Ok((caller, spender, new_balances));
    }

    // Decrease the amount of native token that an owner allowed to a spender.
    pub fn decrease_allowance(
        origin: T::Origin,
        spender: T::AccountId,
        subtracted_value: BalanceOf<T>
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        // Get allowd spender balances.
        let balances = match Allowed::<T>::get(&caller, &spender) {
            Some(_balance) => _balance,
            None => Err(Error::<T>::AllowedNotExist)?
        };
        let new_balances = balances
                .checked_sub(&subtracted_value).ok_or(Error::<T>::UnderFlow)?;

        Allowed::<T>::mutate(&caller, &spender, |balance| *balance = Some(new_balances.clone()));

        return Ok((caller, spender, new_balances));
    }
}

// Transfer Celer for a specified addresses.
fn _transfer<T: Trait>(
    from: T::AccountId,
    to: T::AccountId,
    value: BalanceOf<T>
) -> Result<(), DispatchError> {
    
    // Increase Pool balances of from address
    let balances = Balances::<T>::get(&from).unwrap();
    let new_balances = balances.checked_sub(&value).ok_or(Error::<T>::OverFlow)?;
    Balances::<T>::mutate(&from, |balance| *balance = Some(new_balances));

    let pool_account = pool_account::<T>();
    T::Currency::transfer(
        &pool_account, 
        &to, 
        value, 
        ExistenceRequirement::AllowDeath
    )?;

    Ok(())
}

fn pool_account<T: Trait>() -> T::AccountId {
    POOL_ID.into_account()
}

fn wallet_account<T: Trait>() -> T::AccountId {
    WALLET_ID.into_account()
}

fn ledger_account<T: Trait>() -> T::AccountId {
    CELER_LEDGER_ID.into_account()
}

#[cfg(test)]
mod tests {
    use crate::mock::*;
    use super::*;
    use sp_runtime::DispatchError;
    use crate::ledger_operation::LedgerOperation;
    use crate::ledger_operation::tests::*;

    #[test]
    fn test_pass_deposit_pool() {
        ExtBuilder::build().execute_with(|| {
            deposit_pool(account_key("Bob"), 100);
        })
    }

    #[test]
    fn test_fail_deposit_pool_because_of_owner_does_not_enough_balance() {
        ExtBuilder::build().execute_with(|| {
            let bob = account_key("Bob");
            let err = Pool::<TestRuntime>::deposit_pool(Origin::signed(bob), bob, 2000).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller does not have enough balances"));
        })
    }

    #[test]
    fn test_fail_withdraw_because_of_no_deposit() {
        ExtBuilder::build().execute_with(|| {
            let alice = account_key("Alice");
            let err = Pool::<TestRuntime>::withdraw(Origin::signed(alice), 10).unwrap_err();
            assert_eq!(err, DispatchError::Other("caller's address is not exist in Pool Balances"));
        })
    }

    #[test]
    fn test_pass_withdraw() {
        ExtBuilder::build().execute_with(|| {
            let bob = account_key("Bob");
            deposit_pool(bob, 100);
            let (receiver, value) 
                = Pool::<TestRuntime>::withdraw(Origin::signed(bob), 100).unwrap();
            assert_eq!(receiver, bob);
            assert_eq!(value, 100);
        })
    }

    #[test]
    fn test_pass_approve() {
        ExtBuilder::build().execute_with(|| {
            let bob = account_key("Bob"); // owner address 
            let risa = account_key("Risa"); // spender address
            approve(bob, risa, 200);
        })
    }

    #[test]
    fn test_pass_transfer_from() {
        ExtBuilder::build().execute_with(|| {
            let alice = account_key("Alice"); // to address
            let bob = account_key("Bob"); // from address
            let risa = account_key("Risa"); // spender address
            
            deposit_pool(bob, 200);
            approve(bob, risa, 150);
            
            let (from, to, value) 
                = Pool::<TestRuntime>::transfer_from(Origin::signed(risa), bob, alice, 150).unwrap();
            assert_eq!(from, bob);
            assert_eq!(to, alice);
            assert_eq!(value, 150);
        })
    }

    #[test]
    fn test_fail_transfer_from_because_approved_amount_is_not_enough() {
        ExtBuilder::build().execute_with(|| {
            let alice = account_key("Alice"); // to address
            let bob = account_key("Bob"); // from address
            let risa = account_key("Risa"); // spender address
            
            deposit_pool(bob, 200);
            approve(bob, risa, 100);

            let err = Pool::<TestRuntime>::transfer_from(Origin::signed(risa), bob, alice, 200).unwrap_err();
            assert_eq!(err, DispatchError::Other("spender does not have enough allowed balances"));
        })
    }

    #[test]
    fn test_pass_increase_allowance() {
        ExtBuilder::build().execute_with(|| {
            let bob = account_key("Bob"); // owner address
            let risa = account_key("Risa"); // spender address
            
            approve(bob, risa, 100);

            let (owner, spender, new_allowed_balances) 
                = Pool::<TestRuntime>::increase_allowance(Origin::signed(bob), risa, 50).unwrap();
            assert_eq!(owner, bob);
            assert_eq!(spender, risa);
            assert_eq!(new_allowed_balances, 150);
        })
    }

    #[test]
    fn test_pass_decrease_allowance() {
        ExtBuilder::build().execute_with(|| {
            let bob = account_key("Bob"); // owner address
            let risa = account_key("Risa"); // spender address

            approve(bob, risa, 100);

            let (owner, spender, new_allowed_balances)
                = Pool::<TestRuntime>::decrease_allowance(Origin::signed(bob), risa, 50).unwrap();
            assert_eq!(owner, bob);
            assert_eq!(spender, risa);
            assert_eq!(new_allowed_balances, 50);
        })
    }

    #[test]
    fn test_pass_transfer_celer_wallet() {
        ExtBuilder::build().execute_with(|| {
            let risa = account_key("Risa"); // spender address
            let alice_pair = account_pair("Alice"); // owner address
            let bob_pair = account_pair("Bob"); // owner address
            let (channel_peers, peers_pair)
                = get_sorted_peer(alice_pair.clone(), bob_pair.clone());

            let open_channel_request 
                = get_open_channel_request(false, 0, 500001, 10, true, channel_peers.clone(), 1, peers_pair);
            let wallet_id 
                = LedgerOperation::<TestRuntime>::open_channel(Origin::signed(channel_peers[1]), open_channel_request.clone(), 0).unwrap();
            
            // Depost native token to pool
            deposit_pool(channel_peers[0], 200);
            // Approve risa to use native token
            approve(channel_peers[0], risa, 200);

            // Transfer to native token wallet by risa
            let (_wallet_id, _, _amount)
                = Pool::<TestRuntime>::transfer_to_celer_wallet(Origin::signed(risa), channel_peers[0], wallet_id, 200).unwrap();
            assert_eq!(_wallet_id, wallet_id);
            assert_eq!(_amount, 200);
        })
    }

    fn deposit_pool(receiver: AccountId, value: Balance) {
        let (_receiver, _value) 
            = Pool::<TestRuntime>::deposit_pool(Origin::signed(receiver), receiver, value).unwrap();
        assert_eq!(_receiver, receiver);
        assert_eq!(_value, value);
    }

    fn approve(owner: AccountId, spender: AccountId, value: Balance) {
        let (_owner, _spender, _value)
            = Pool::<TestRuntime>::approve(Origin::signed(owner), spender, value).unwrap();
        assert_eq!(_owner, owner);
        assert_eq!(_spender, spender);
        assert_eq!(_value, value);
    }

}