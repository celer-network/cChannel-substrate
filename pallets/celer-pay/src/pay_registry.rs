use super::{BalanceOf, PayInfoMap, Module as CelerPayModule, RawEvent};
use crate::traits::Trait;
use codec::{Decode, Encode};
use frame_support::{ensure, storage::StorageMap};
use frame_system::{self as system};
use sp_runtime::traits::{Hash, Zero};
use sp_runtime::{RuntimeDebug, DispatchError};
use sp_std::{vec, vec::Vec};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PayInfo<Balance, BlockNumber> {
    pub amount: Option<Balance>,
    pub resolve_deadline: Option<BlockNumber>,
}

pub type PayInfoOf<T> = PayInfo<BalanceOf<T>, <T as system::Trait>::BlockNumber>;

pub struct PayRegistry<T>(sp_std::marker::PhantomData<T>);

impl<T: Trait> PayRegistry<T> {
    pub fn calculate_pay_id(pay_hash: T::Hash) -> T::Hash {
        let pay_resolver_account = CelerPayModule::<T>::get_pay_resolver_id();
        let mut encoded = pay_hash.encode();
        encoded.extend(pay_resolver_account.encode());
        let pay_id = T::Hashing::hash(&encoded);
        return pay_id;
    }

    pub fn set_pay_amount(pay_hash: T::Hash, amt: BalanceOf<T>) -> Result<(), DispatchError> {
        let pay_id = Self::calculate_pay_id(pay_hash);
        match PayInfoMap::<T>::get(&pay_id) {
            Some(mut pay_info) => {
                PayInfoMap::<T>::mutate(&pay_id, |info| {
                    pay_info.amount = Some(amt);
                    *info = Some(pay_info.clone())
                });
            
                // Emit PayInfoUpdate event
                CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                    pay_id, 
                    amt, 
                    pay_info.resolve_deadline.unwrap_or(Zero::zero())
                ));
            },
            None => {
                let new_pay_info = PayInfoOf::<T> {
                    amount: Some(amt),
                    resolve_deadline: None,
                };
                PayInfoMap::<T>::insert(pay_id, new_pay_info);
            
                // Emit PayInfoUpdate event
                CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                    pay_id,
                    amt,
                    Zero::zero(),
                ));
            }
        }

        Ok(())
    }

    pub fn set_pay_deadline(
        pay_hash: T::Hash,
        deadline: T::BlockNumber,
    ) -> Result<(), DispatchError> {
        let pay_id = Self::calculate_pay_id(pay_hash);
        match PayInfoMap::<T>::get(&pay_id) {
            Some(mut pay_info) => {
                PayInfoMap::<T>::mutate(&pay_id, |info| {
                    pay_info.resolve_deadline = Some(deadline);
                    *info = Some(pay_info.clone())
                });
            
                // Emit PayInfoUpdate event
                CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                    pay_id,
                    pay_info.amount.unwrap_or(Zero::zero()),
                    deadline,
                ));
            },
            None => {
                let new_pay_info = PayInfoOf::<T> {
                    amount: None,
                    resolve_deadline: Some(deadline),
                };
                PayInfoMap::<T>::insert(pay_id, new_pay_info);

                // Emit PayInfoUpdate event
                CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                    pay_id,
                    Zero::zero(),
                    deadline
                ));
            }
        }

        Ok(())
    }

    pub fn set_pay_info(
        pay_hash: T::Hash,
        amt: BalanceOf<T>,
        deadline: T::BlockNumber,
    ) -> Result<(), DispatchError> {
        let pay_id = Self::calculate_pay_id(pay_hash);
        let new_pay_info = PayInfoOf::<T> {
            amount: Some(amt),
            resolve_deadline: Some(deadline),
        };
        <PayInfoMap<T>>::mutate(&pay_id, |info| *info = Some(new_pay_info));
        
        // Emit PayInfoUpdate event
        CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
            pay_id,
            amt,
            deadline,
        ));

        Ok(())
    }

    pub fn set_pay_amounts(
        pay_hashes: Vec<T::Hash>,
        amts: Vec<BalanceOf<T>>,
    ) -> Result<(), DispatchError> {
        ensure!(pay_hashes.len() == amts.len(), "Lengths do not match");

        for i in 0..pay_hashes.len() {
            let pay_id = Self::calculate_pay_id(pay_hashes[i]);
            match PayInfoMap::<T>::get(&pay_id) {
                Some(mut pay_info) => {
                    PayInfoMap::<T>::mutate(&pay_id, |info| {
                        pay_info.amount = Some(amts[i]);
                        *info = Some(pay_info.clone())
                    });
                
                    // Emit PayInfoUpdate event
                    CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                        pay_id,
                        amts[i],
                        pay_info.resolve_deadline.unwrap()
                    ));
                }, 
                None => {
                    let new_pay_info = PayInfoOf::<T> {
                        amount: Some(amts[i]),
                        resolve_deadline: None,
                    };
                    PayInfoMap::<T>::insert(pay_id, new_pay_info);

                    // Emit PayInfoUpdate event
                    CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                        pay_id,
                        amts[i],
                        Zero::zero(),
                    ));
                }
            }
        }

        Ok(())
    }

    pub fn set_pay_deadlines(
        pay_hashes: Vec<T::Hash>,
        deadlines: Vec<T::BlockNumber>,
    ) -> Result<(), DispatchError> {
        ensure!(pay_hashes.len() == deadlines.len(), "Lengths do not match");

        for i in 0..pay_hashes.len() {
            let pay_id = Self::calculate_pay_id(pay_hashes[i]);
            match PayInfoMap::<T>::get(&pay_id) {
                Some(mut pay_info) => {
                    PayInfoMap::<T>::mutate(&pay_id, |info| {
                        pay_info.resolve_deadline = Some(deadlines[i]);
                        *info = Some(pay_info.clone())
                    });
                
                    // Emit PayInfoUpdate event
                    CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                        pay_id,
                        pay_info.amount.unwrap(),
                        deadlines[i],
                    ));
                },
                None => {
                    let new_pay_info = PayInfoOf::<T> {
                        amount: None,
                        resolve_deadline: Some(deadlines[i]),
                    };
                    PayInfoMap::<T>::insert(pay_id, new_pay_info);
                
                    // Emit PayInfoUpdate event
                    CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                        pay_id,
                        Zero::zero(),
                        deadlines[i],
                    ));
                }
            } 
        }

        Ok(())
    }

    pub fn set_pay_infos(
        pay_hashes: Vec<T::Hash>,
        amts: Vec<BalanceOf<T>>,
        deadlines: Vec<T::BlockNumber>,
    ) -> Result<(), DispatchError> {
        ensure!(pay_hashes.len() == amts.len(), "Lengths do not match");

        for i in 0..pay_hashes.len() {
            let pay_id = Self::calculate_pay_id(pay_hashes[i]);

            PayInfoMap::<T>::mutate(&pay_id, |info| {
                let new_pay_info = PayInfoOf::<T> {
                    amount: Some(amts[i]),
                    resolve_deadline: Some(deadlines[i]),
                };
                *info = Some(new_pay_info)
            });
            
            // Emit PayInfoUpdate event
            CelerPayModule::<T>::deposit_event(RawEvent::PayInfoUpdate(
                pay_id,
                amts[i],
                deadlines[i]
            ));
        }

        Ok(())
    }

    pub fn get_pay_amounts(
        pay_ids: Vec<T::Hash>,
        last_pay_resolve_deadline: T::BlockNumber,
    ) -> Result<Vec<BalanceOf<T>>, DispatchError> {
        let mut amounts: Vec<BalanceOf<T>> = vec![];
        for i in 0..pay_ids.len() {
            match PayInfoMap::<T>::get(&pay_ids[i]) {
                Some(pay_info) => {
                    if pay_info.resolve_deadline.unwrap_or(Zero::zero()) == Zero::zero() {
                        // should pass last pay resolve deadline if never resolved
                        ensure!(
                            frame_system::Module::<T>::block_number() > last_pay_resolve_deadline,
                            "Payment is not finalized"
                        );  
                    } else {
                        // should pass resolve deadline if resolved
                        ensure!(
                            frame_system::Module::<T>::block_number() > pay_info.resolve_deadline.unwrap(),
                            "Payment is not finalized"
                        );
                    }
                    amounts.push(pay_info.amount.unwrap_or(Zero::zero()));
                },
                None => {
                    // should pass last pay resolve deadline if never resolved
                    ensure!(
                        frame_system::Module::<T>::block_number() > last_pay_resolve_deadline,
                        "Payment is not finalized"
                    );
                    amounts.push(Zero::zero());
                }
            }
        }

        return Ok(amounts);
    }

    pub fn get_pay_info(pay_id: T::Hash) -> Result<(BalanceOf<T>, T::BlockNumber), DispatchError> {
        match PayInfoMap::<T>::get(&pay_id) {
            Some(pay_info) => {
                return Ok((pay_info.amount.unwrap_or(Zero::zero()), pay_info.resolve_deadline.unwrap_or(Zero::zero())));
            },
            None => {
                let pay_info = PayInfoOf::<T> {
                    amount: Some(Zero::zero()),
                    resolve_deadline: Some(Zero::zero()),
                };
                PayInfoMap::<T>::insert(&pay_id, &pay_info);
                return Ok((Zero::zero(), Zero::zero()));
            }
        }
    }
}
