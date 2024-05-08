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

### Prerequisites

```bash
chmod +x ./scripts/*
```

### Deployment
Deployment of the `daosign_app` contract to the test network:

1. Run `./scripts/build.sh`.
2. Run `./scripts/random-acc.sh` and paste the generated account id to the `dev.env` file after `DEPLOYER_ACCOUNT_ID=`.
3. Run `./scripts/deploy.sh`.
4. (optional) Test that deployment is successful by running `./scripts/get-domain.sh`. It should return DAOsignApp.domain object.

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