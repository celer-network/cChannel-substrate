# How to add Celer Pay runtime module to your chain

1. Install Celer Pay runtime module

```
git clone git@github.com:celer-network/cChannel-substrate.git
```

2. Install the Node Template

```
git clone -b v2.0.0-rc1 --depth 1 https://github.com/substrate-developer-hub/substrate-node-template
```

3. Copy and Paste Celer Pay file(Cargo.toml, Cargo.lock, src) in pallets/celer-pay

4. Register your native token name

`pallets/celer-pay/src`  
```
/// Modify following block (code line is 46)
// Currently native token is only supoorted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, RuntimeDebug)]
pub enum TokenType {
    INVALID,
    CELER, // native token. If Kusama network,change from CELER to KSM.
}
```

5. Add crate as a dependency in the node's runtime Cargo.toml. 

`runtime/Cargo.toml`
```
--snip--
[dependencies.celer-pay]
default-features = false
package = 'celer-pay-module'
path = '../pallets/celer-pay'
version = '0.8.1'

# toward the bottom
[features]
default = ['std']
std = [
    # --snip--
    'celer-pay/std',
]
```

6. Update `runtime/src/lib.rs` to actually use celer-pay runtime module, by adding a trait 
implementation with celer-pay and it in construct_runtime! macro.

``` rust
// add this import at the top. (code line is 11)
use sp_runtime::MultiSigner;

/// Add this line. (code line is 45)
pub use celer_pay;

/// Add following code block. (code line is 257 ~ 262)
/// Used for the celer-pay module
impl celer_pay::Trait for Runtime {
  type Currency = balances::Module<Runtime>;
  type Event = Event;
  type Public = MultiSigner;
  type Signature = Signature;
}

construct_runtime!(
  pub enum Runtime where
  Block = Block,
  NodeBlock = opaque::Block,
  UncheckedExtrinsic = UncheckedExtrinsic
  {
    # --snip--
    // Add following sentence. (code line is 279)
    CelerPayModule: celer_pay::{Module, Call, Storage, Event<T>},
  }
);
```

7. Build


Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Initialize your Wasm Build environment:

```bash
./scripts/init.sh
```

Build Wasm and native code:

```bash
cargo build --release
```

8. Run

Purge any existing developer chain state:

```bash
./target/release/node-template purge-chain --dev
```

Start a development chain with:

```bash
./target/release/node-template --dev
```

Detailed logs may be shown by running the node with the following environment variables set: `RUST_LOG=debug RUST_BACKTRACE=1 cargo run -- --dev`.


__WARNING__: Celer state channel network is composed of Celer-pay Onchain runtime module and Celer-pay Offchain protocol. This repository is Celer-pay Onchain runtime module. Celer-pay Offchain protocol is not implemented yet. 
