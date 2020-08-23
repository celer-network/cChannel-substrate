//! RPC interface for the transaction payment module.

use jsonrpc_core::{Error as RpcError, ErrorCode, Result};
use jsonrpc_derive::rpc;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
use std::sync::Arc;
use celer_pay_runtime_api::CelerPayModuleApi as CelerPayModuleRuntimeApi;

/// Celer Pay Module RPC methods
#[rpc]
pub trait CelerPayModuleApi<BlockHash, AccountId, Hash> {
    #[rpc(name = "celerPayModule_getCelerLedgerId")]
    fn get_celer_ledger_id(&self, at: Option<BlockHash>) -> Result<AccountId>;

    #[rpc(name = "celerPayModule_getCelerWalletId")]
    fn get_celer_wallet_id(&self, at: Option<BlockHash>) -> Result<AccountId>;

    #[rpc(name = "celerPayModule_getPoolId")]
    fn get_pool_id(&self, at: Option<BlockHash>) -> Result<AccountId>;

    #[rpc(name = "celerPayModule_getPayResolverId")]
    fn get_pay_resolver_id(&self, at: Option<BlockHash>) -> Result<AccountId>;

    #[rpc(name = "celerPayModule_calculatePayId")]
    fn calculate_pay__id(&self, at: Option<BlockHash>) -> Result<Hash>;
}

/// A struct that implements the `CelerPayModuleApi'
pub struct CelerPayModule<C, M> {
    client: Arc<C>,
    _marker: std::marker::PhantomData<M>,
}

impl<C, M> CelerPayModule<C, M> {
    pub fn new (client: Arc<C>) -> Self {
        Self {
            client,
            _marker: Default::default(),
        }
    }
}

impl<C, Block, AccountId, Hash> 
    CelerPayModuleApi<
        <Block as BlockT>::Hash, 
        AccountId,
        Hash,
    > for CelerPayModule<C, Block>
where
    C: Send + Sync + 'static,
	C: ProvideRuntimeApi<Block>,
	C: HeaderBackend<Block>,
    C::Api: CelerPayModuleRuntimeApi<Block, AccountId, Hash>,
    AccountId: Codec,
    Hash: Codec,
{
    fn get_celer_ledger_id(&self, at: Option<<Block as BlockT>::Hash>) -> Result<AccountId> {
        let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash));

        let runtime_api_result = api.get_celer_ledger_id(&at);
        runtime_api_result.map_err(|e| RpcError {
            code: ErrorCode::ServerError(9876),
            message: "Can't get celer ledger id".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn get_celer_wallet_id(&self, at: Option<<Block as BlockT>::Hash>) -> Result<AccountId> {
        let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash));

        let runtime_api_result = api.get_celer_wallet_id(&at);
        runtime_api_result.map_err(|e| RpcError {
            code: ErrorCode::ServerError(9876),
            message: "Can't get celer wallet id".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn get_celer_pool_id(&self, at: Option<<Block as BlockT>::Hash>) -> Result<AccountId> {
        let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash));

        let runtime_api_result = api.get_celer_pool_id(&at);
        runtime_api_result.map_err(|e| RpcError {
            code: ErrorCode::ServerError(9876),
            message: "Can't get pool id".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn get_pay_resolver_id(&self, at: Option<<Block as BlockT>::Hash>) -> Result<AccountId> {
        let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash));

        let runtime_api_result = api.get_pay_resolver_id(&at);
        runtime_api_result.map_err(|e| RpcError {
            code: ErrorCode::ServerError(9876),
            message: "Can't get pay resolver id".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }

    fn calculate_pay_id(&self, at: Option<<Block as BlockT>::Hash>) -> Result<Hash> {
        let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			// If the block hash is not supplied assume the best block.
			self.client.info().best_hash));

        let runtime_api_result = api.calculate_pay_id(&at);
        runtime_api_result.map_err(|e| RpcError {
            code: ErrorCode::ServerError(9876),
            message: "Can't calculate pay id".into(),
            data: Some(format!("{:?}", e).into()),
        })
    }
}
