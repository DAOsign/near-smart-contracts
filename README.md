# near-smart-contracts

cargo-near-new-project-description

## How to Build Locally?

Install [`cargo-near`](https://github.com/near/cargo-near) and run:

```bash
cargo near build
```

## How to Test Locally?

```bash
cargo test
```

## How to Deploy?

Deployment of the `daosign_app` contract to the test network:

```bash
# Automatically deploy the wasm in a new account
near account create-account sponsor-by-faucet-service <my-new-dev-account>.testnet autogenerate-new-keypair save-to-keychain network-config testnet create

near contract deploy <my-new-dev-account>.testnet use-file target/wasm32-unknown-unknown/release/daosign_app.wasm without-init-call network-config testnet sign-with-keychain
```

```bash
cargo near deploy <account-id>
```

## Lint

(optional)

```bash
rustup default nightly
```

Linting
```bash
cargo +nightly fmt
```

## Docs

```bash
sudo chmod +x ./gen-docs.sh && ./gen-docs.sh
```

## Useful Links

- [cargo-near](https://github.com/near/cargo-near) - NEAR smart contract development toolkit for Rust
- [near CLI](https://near.cli.rs) - Iteract with NEAR blockchain from command line
- [NEAR Rust SDK Documentation](https://docs.near.org/sdk/rust/introduction)
- [NEAR Documentation](https://docs.near.org)
- [NEAR StackOverflow](https://stackoverflow.com/questions/tagged/nearprotocol)
- [NEAR Discord](https://near.chat)
- [NEAR Telegram Developers Community Group](https://t.me/neardev)
- NEAR DevHub: [Telegram](https://t.me/neardevhub), [Twitter](https://twitter.com/neardevhub)



// cargo build -p daosign_eip712 --target wasm32-unknown-unknown --profile=contract