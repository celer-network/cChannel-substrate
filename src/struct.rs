use codec::{Encode, Decode};
use sp_runtime::RuntimeDebug;
use frame_system::{self as system};
use super::{Trait, BalanceOf};

// ==================================== Channel =================================
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum ChannelStatus {
    Uninitialized = 0,
    Operable = 1,
    Settling = 2,
    Closed = 3,
    Migrated = 4,
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PeerState<Hash, BlockNumber, Balance> {
    pub seq_num: u128,
    pub transfer_out: Balance,
    pub next_pay_id_list_hash: Hash,
    pub last_pay_resolve_deadline: BlockNumber,
    pub pending_pay_out: Balance,
}

pub type PeerStateOf<T> = PeerState<<T as system::Trait>::Hash, <T as system::Trait>::BlockNumber, BalanceOf<T>>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PeerProfile<AccountId, Balance, BlockNumber, Hash> {
    pub peer_addr: AccountId,
    pub deposit: Balance,
    pub withdrawal: Option<Balance>,
    pub state: Option<PeerState<Hash, BlockNumber, Balance>>,
}

pub type PeerProfileOf<T> = PeerProfile<<T as system::Trait>::AccountId, BalanceOf<T>, <T as system::Trait>::BlockNumber, <T as system::Trait>::Hash>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct WithdrawIntent<AccountId, Balance, BlockNumber, Hash> {
    pub receiver: AccountId,
    pub amount: Balance,
    pub request_time: BlockNumber,
    pub recipient_channel_id: Hash,
}

pub type WithdrawIntentOf<T> = WithdrawIntent<<T as system::Trait>::AccountId, BalanceOf<T>, <T as system::Trait>::BlockNumber, <T as system::Trait>::Hash>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Channel<AccountId, BlockNumber, Balance, Hash> {
    pub settle_finalized_time: Option<BlockNumber>,
    pub dispute_timeout: BlockNumber,
    pub token: TokenInfo,
    pub status: ChannelStatus,
    pub peer_profiles: Vec<PeerProfile<AccountId, Balance, BlockNumber, Hash>>,
    pub cooperative_withdraw_seq_num: Option<u128>,
    pub withdraw_intent: Option<WithdrawIntent<AccountId, Balance, BlockNumber, Hash>>,
}

pub type ChannelOf<T> = Channel<<T as system::Trait>::AccountId, <T as system::Trait>::BlockNumber, BalanceOf<T>, <T as system::Trait>::Hash>;

// =============================== Celer Wallet =================================
// Currently ETH is only supported.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct Wallet<AccountId, Balance> {
    pub owners: Vec<AccountId>,
    pub balance: Balance,
}

pub type WalletOf<T> = Wallet<<T as system::Trait>::AccountId, BalanceOf<T>>;

// ================================= LedgerOperation =============================
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum TokenType {
    INVALID,
    CELER,
    ERC20,
}

// Currently ETH is only uspported.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenInfo  {
    pub token_type: TokenType
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct AccountAmtPair<AccountId, Balance> {
    pub account: Option<AccountId>,
    pub amt: Balance,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenDistribution<AccountId, Balance> {
    pub token: TokenInfo,
    pub distribution: Vec<AccountAmtPair<AccountId, Balance>>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PaymentChannelInitializer<AccountId, BlockNumber, Balance> {
    pub init_distribution: TokenDistribution<AccountId, Balance>,
    pub open_deadline: BlockNumber,
    pub dispute_timeout: BlockNumber,
    pub msg_value_receiver: u8,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct OpenChannelRequest<AccountId, BlockNumber, Balance, Signature> {
    pub channel_initializer: PaymentChannelInitializer<AccountId, BlockNumber, Balance>,
    pub sigs: Vec<Signature>,
}

pub type OpenChannelRequestOf<T> = OpenChannelRequest<
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PayIdList<Hash> {
    pub pay_ids: Vec<Hash>,
    pub next_list_hash: Hash,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct TokenTransfer<AccountId, Balance> {
    pub token: TokenInfo,
    pub receiver: AccountAmtPair<AccountId, Balance>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SimplexPaymentChannel<Hash, AccountId, BlockNumber, Balance> {
    pub channel_id: Hash,
    pub peer_from: AccountId,
    pub seq_num: u128,
    pub transfer_to_peer: TokenTransfer<AccountId, Balance>,
    pub pending_pay_ids: PayIdList<Hash>,
    pub last_pay_resolve_deadline: BlockNumber,
    pub total_pending_amount: Balance,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SignedSimplexState<Hash, AccountId, BlockNumber, Balance, Signature> {
    pub simplex_state: SimplexPaymentChannel<Hash, AccountId, BlockNumber, Balance>,
    pub sigs: Vec<Signature>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct SignedSimplexStateArray<Hash, AccountId, BlockNumber, Balance, Signature> {
    pub signed_simplex_states: Vec<SignedSimplexState<Hash, AccountId, BlockNumber, Balance, Signature>>,
}

pub type SignedSimplexStateArrayOf<T> = SignedSimplexStateArray<
    <T as system::Trait>::Hash,
    <T as system::Trait>::AccountId,
    <T as system::Trait>::BlockNumber,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeWithdrawInfo<Hash, BlockNumber, AccountId, Balance> {
    pub channel_id: Hash,
    pub seq_num: u128,
    pub withdraw: AccountAmtPair<AccountId, Balance>,
    pub withdraw_deadline: BlockNumber,
    pub recipient_channel_id: Hash,
}

pub type CooperativeWithdrawInfoOf<T> = CooperativeWithdrawInfo<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeWithdrawRequest<Hash, BlockNumber, AccountId, Balance, Signature> {
    pub withdraw_info: CooperativeWithdrawInfo<Hash, BlockNumber, AccountId, Balance>,
    pub sigs: Vec<Signature>,
}

pub type CooperativeWithdrawRequestOf<T> = CooperativeWithdrawRequest<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeSettleInfo<Hash, BlockNumber, AccountId, Balance> {
    pub channel_id: Hash,
    pub seq_num: u128,
    pub settle_balance: Vec<AccountAmtPair<AccountId, Balance>>,
    pub settle_deadline: BlockNumber,
}

pub type CooperativeSettleInfoOf<T> = CooperativeSettleInfo<<T as system::Trait>::Hash, <T as system::Trait>::BlockNumber, <T as system::Trait>::AccountId, BalanceOf<T>>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct CooperativeSettleRequest<Hash, BlockNumber, AccountId, Balance, Signature> {
    pub settle_info: CooperativeSettleInfo<Hash, BlockNumber, AccountId, Balance>,
    pub sigs: Vec<Signature>,
}

pub type CooperativeSettleRequestOf<T> = CooperativeSettleRequest<
    <T as system::Trait>::Hash,
    <T as system::Trait>::BlockNumber,
    <T as system::Trait>::AccountId,
    BalanceOf<T>,
    <T as Trait>::Signature,
>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum MathOperation {
    Add,
    Sub,
}

// ================================ PayRegistry ==================================
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub struct PayInfo<Balance, BlockNumber> {
    pub amount: Option<Balance>,
    pub resolve_deadline: Option<BlockNumber>,
}   

pub type PayInfoOf<T> = PayInfo<BalanceOf<T>, <T as system::Trait>::BlockNumber>;
