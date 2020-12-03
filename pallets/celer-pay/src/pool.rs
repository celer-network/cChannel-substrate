use super::{
    Module as CelerPayModule, Allowed, BalanceOf, 
    PoolBalances, Error, RawEvent
};
use crate::traits::Trait;
use crate::celer_wallet::CelerWallet;
use frame_support::traits::{Currency, ExistenceRequirement};
use frame_support::{
    ensure,
    storage::{StorageDoubleMap, StorageMap},
};
use frame_system::ensure_signed;
use sp_runtime::traits::{CheckedAdd, CheckedSub, Zero};
use sp_runtime::{ModuleId, DispatchError};

pub const POOL_ID: ModuleId = ModuleId(*b"_pool_id");

pub struct Pool<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> Pool<T> {
    // Dposit Celer to Pool
    pub fn deposit_pool(
        origin: T::Origin,
        receiver: T::AccountId,
        msg_value: BalanceOf<T>,
    ) -> Result<(T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        ensure!(
            <T as Trait>::Currency::free_balance(&caller) >= msg_value,
            "caller does not have enough balances"
        );

        let pool_account = CelerPayModule::<T>::get_pool_id();
        ensure!(receiver != pool_account, "receiver address is pool account");

        match PoolBalances::<T>::get(&receiver) {
            Some(pool_balances) => {
                let new_balances = pool_balances.checked_add(&msg_value).ok_or(Error::<T>::OverFlow)?;
                PoolBalances::<T>::mutate(&receiver, |balances| *balances = Some(new_balances));
            },
            None => PoolBalances::<T>::insert(&receiver, &msg_value),
        }

        <T as Trait>::Currency::transfer(
            &caller,
            &pool_account,
            msg_value,
            ExistenceRequirement::AllowDeath,
        )?;

        // Emit DepositToPool event
        CelerPayModule::<T>::deposit_event(RawEvent::DepositToPool(
            receiver.clone(),
            msg_value
        ));
        return Ok((receiver, msg_value));
    }

    // Withdraw native token from Pool
    pub fn withdraw(
        origin: T::Origin,
        value: BalanceOf<T>,
    ) -> Result<(T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;
        
        let balances = match PoolBalances::<T>::get(&caller) {
            Some(_balances) => _balances,
            None => Err(Error::<T>::PoolBalancesNotExist)?
        };

        ensure!(balances >= value, "caller does not have enough balances");

        let new_balances = balances.checked_sub(&value).ok_or(Error::<T>::UnderFlow)?;
        PoolBalances::<T>::mutate(&caller, |balance| *balance = Some(new_balances));

        let pool_account = CelerPayModule::<T>::get_pool_id();
        <T as Trait>::Currency::transfer(
            &pool_account,
            &caller,
            value,
            ExistenceRequirement::AllowDeath,
        )?;

        // Emit WithdrawFromPool event
        CelerPayModule::<T>::deposit_event(RawEvent::WithdrawFromPool(
            caller.clone(),
            value
        ));
        return Ok((caller, value));
    }

    // Approve the passed address the spend the specified amount of Celer on behalf of caller.
    pub fn approve(
        origin: T::Origin,
        spender: T::AccountId,
        value: BalanceOf<T>,
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        Allowed::<T>::insert(&caller, &spender, &value);

        // Emit Approval event
        CelerPayModule::<T>::deposit_event(RawEvent::Approval(
            caller.clone(),
            spender.clone(),
            value
        ));
        return Ok((caller, spender, value));
    }

    // Transfer native token from one address to another
    pub fn transfer_from(
        origin: T::Origin,
        from: T::AccountId,
        to: T::AccountId,
        value: BalanceOf<T>,
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        let allowed_balances = match Allowed::<T>::get(&from, &caller) {
            Some(_allowed_balances) => _allowed_balances,
            None => Err(Error::<T>::AllowedNotExist)?
        };

        ensure!(
            allowed_balances >= value,
            "spender does not have enough allowed balances"
        );
        let new_allowed_balances = allowed_balances.checked_sub(&value)
                .ok_or(Error::<T>::UnderFlow)?;

        let balances = match PoolBalances::<T>::get(&from) {
            Some(_balances) => _balances,
            None => Err(Error::<T>::PoolBalancesNotExist)?
        };

        ensure!(
            balances >= value,
            "from address does not have enough balances"
        );

        // Decrease Allowed balances of spender
        Allowed::<T>::mutate(&from, &caller, |balance| {*balance = Some(new_allowed_balances)});
        
        // Emit Approval event
        CelerPayModule::<T>::deposit_event(RawEvent::Approval(
            from.clone(),
            caller.clone(),
            new_allowed_balances,
        ));

        _transfer::<T>(from.clone(), to.clone(), value)?;

        return Ok((from, to, value));
    }

    // Transfer native token from one address to a wallet in CelerWallet Module.
    // This function called by Celer Ledger.
    pub fn transfer_to_celer_wallet_by_ledger(
        origin: T::Origin,
        from: T::AccountId,
        wallet_id: T::Hash,
        amount: BalanceOf<T>,
    ) -> Result<(T::Hash, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin.clone())?;
        let celer_ledger_account = CelerPayModule::<T>::get_celer_ledger_id();
        ensure!(caller == celer_ledger_account, "Caler is not Celer Ledger module",);

        let pool_balances = match PoolBalances::<T>::get(&from) {
            Some(_balance) => _balance,
            None => Err(Error::<T>::PoolBalancesNotExist)?,
        };
        ensure!(
            pool_balances >= amount,
            "Wallet owner does not deposit to pool enough value"
        );

        let allowed_balances = match Allowed::<T>::get(&from, &celer_ledger_account) {
            Some(_allowed_balances) => _allowed_balances,
            None => Err(Error::<T>::AllowedNotExist)?
        };

        ensure!(
            allowed_balances >= amount,
            "spender not have enough allowed balances"
        );
        let new_allowed_balances = allowed_balances
                .checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        Allowed::<T>::mutate(&from, &celer_ledger_account, |balance| {
            *balance = Some(new_allowed_balances)
        });

        // Emit Approval event
        CelerPayModule::<T>::deposit_event(RawEvent::Approval(
            from.clone(),
            celer_ledger_account.clone(),
            new_allowed_balances
        ));

        // Deposit native token to CelerWallet
        CelerWallet::<T>::deposit_native_token(
            from.clone(),
            wallet_id,
            amount
        )?;

        // Decrease Pool Balances
        let new_pool_balances = pool_balances
                .checked_sub(&amount).ok_or(Error::<T>::UnderFlow)?;
        PoolBalances::<T>::mutate(&from, |balances| *balances = Some(new_pool_balances));

        let pool_account = CelerPayModule::<T>::get_pool_id();
        let celer_wallet_account = CelerPayModule::<T>::get_celer_wallet_id();
        <T as Trait>::Currency::transfer(
            &pool_account,
            &celer_wallet_account,
            amount,
            ExistenceRequirement::AllowDeath,
        )?;

        return Ok((wallet_id, celer_wallet_account, amount));
    }

    // Increase the amount of native token that an owner allowed to a spender.
    pub fn increase_allowance(
        origin: T::Origin,
        spender: T::AccountId,
        added_value: BalanceOf<T>,
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        // Get allowed spender balances.
        let balances = match Allowed::<T>::get(&caller, &spender) {
            Some(_allowed) => _allowed,
            None => Err(Error::<T>::AllowedNotExist)?,
        };
        let new_balances = balances.checked_add(&added_value)
                .ok_or(Error::<T>::OverFlow)?;
        Allowed::<T>::mutate(&caller, &spender, |balance| {*balance = Some(new_balances.clone())});

        // Emit Approval event
        CelerPayModule::<T>::deposit_event(RawEvent::Approval(
            caller.clone(),
            spender.clone(),
            new_balances.clone()
        ));
        return Ok((caller, spender, new_balances));
    }

    // Decrease the amount of native token that an owner allowed to a spender.
    pub fn decrease_allowance(
        origin: T::Origin,
        spender: T::AccountId,
        subtracted_value: BalanceOf<T>,
    ) -> Result<(T::AccountId, T::AccountId, BalanceOf<T>), DispatchError> {
        let caller = ensure_signed(origin)?;

        // Get allowd spender balances.
        let balances = match Allowed::<T>::get(&caller, &spender) {
            Some(_balance) => _balance,
            None => Err(Error::<T>::AllowedNotExist)?,
        };
        let new_balances = balances.checked_sub(&subtracted_value)
                .ok_or(Error::<T>::UnderFlow)?;
        Allowed::<T>::mutate(&caller, &spender, |balance| {
            *balance = Some(new_balances.clone())
        });

        // Emit Approval event
        CelerPayModule::<T>::deposit_event(RawEvent::Approval(
            caller.clone(),
            spender.clone(),
            new_balances.clone()
        ));
        return Ok((caller, spender, new_balances));
    }
}

// Transfer native token for a specified addresses.
fn _transfer<T: Trait>(
    from: T::AccountId,
    to: T::AccountId,
    value: BalanceOf<T>,
) -> Result<(), DispatchError> {
    // Increase Pool balances of from address
    let balances = PoolBalances::<T>::get(&from).unwrap_or(Zero::zero());
    let new_balances = balances.checked_sub(&value).ok_or(Error::<T>::OverFlow)?;
    PoolBalances::<T>::mutate(&from, |balance| *balance = Some(new_balances));

    let pool_account = CelerPayModule::<T>::get_pool_id();
    <T as Trait>::Currency::transfer(&pool_account, &to, value, ExistenceRequirement::AllowDeath)?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::mock::*;
    use sp_runtime::DispatchError;

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
            assert_eq!(
                err,
                DispatchError::Other("caller does not have enough balances")
            );
        })
    }

    #[test]
    fn test_fail_withdraw_because_of_no_deposit() {
        ExtBuilder::build().execute_with(|| {   
            let alice = account_key("Alice");
            let err = Pool::<TestRuntime>::withdraw(Origin::signed(alice), 10).unwrap_err();
            assert_eq!(
                err,
                DispatchError::Module { index: 0, error: 11, message: Some("PoolBalancesNotExist") }
            );
        })
    }

    #[test]
    fn test_pass_withdraw() {
        ExtBuilder::build().execute_with(|| {   
            let bob = account_key("Bob");
            deposit_pool(bob, 100);
            let (receiver, value) =
                Pool::<TestRuntime>::withdraw(Origin::signed(bob), 100).unwrap();
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

            let (from, to, value) =
                Pool::<TestRuntime>::transfer_from(Origin::signed(risa), bob, alice, 150).unwrap();
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
            assert_eq!(
                err,
                DispatchError::Other("spender does not have enough allowed balances")
            );
        })
    }

    #[test]
    fn test_pass_increase_allowance() {
        ExtBuilder::build().execute_with(|| {   
            let bob = account_key("Bob"); // owner address
            let risa = account_key("Risa"); // spender address

            approve(bob, risa, 100);

            let (owner, spender, new_allowed_balances) =
                Pool::<TestRuntime>::increase_allowance(Origin::signed(bob), risa, 50).unwrap();
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

            let (owner, spender, new_allowed_balances) =
                Pool::<TestRuntime>::decrease_allowance(Origin::signed(bob), risa, 50).unwrap();
            assert_eq!(owner, bob);
            assert_eq!(spender, risa);
            assert_eq!(new_allowed_balances, 50);
        })
    }

    pub fn deposit_pool(receiver: AccountId, value: Balance) {
        let (_receiver, _value) =
            Pool::<TestRuntime>::deposit_pool(Origin::signed(receiver), receiver, value).unwrap();
        assert_eq!(_receiver, receiver);
        assert_eq!(_value, value);
    }

    pub fn approve(owner: AccountId, spender: AccountId, value: Balance) {
        let (_owner, _spender, _value) =
            Pool::<TestRuntime>::approve(Origin::signed(owner), spender, value).unwrap();
        assert_eq!(_owner, owner);
        assert_eq!(_spender, spender);
        assert_eq!(_value, value);
    }
}
