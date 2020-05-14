# cChannel-substrate

## Building and Testing
1. Fast Installation

Mac OS, Arch, or a Debian-based OS like Ubuntu

```
curl https://getsubstrate.io -sSf | bash -s -- --fast
```

Debian

```
sudo apt install -y cmake pkg-config libssl-dev git gcc build-essential clang libclang-dev
```

MacOS

```
brew install openssl cmake llvm
```

2. Rust Developer Environment

```
curl https://sh.rustup.rs -sSf | sh
```

```
rustup default stable
```

3. Wasm Compilation

```
rustup update nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```

4. Rustup Update

```
rustup update
```

5. Build celer pallet

```
cd frame
cargo build --release
```

6. Test celer pallet

```
cargo test -p celer-module
```


