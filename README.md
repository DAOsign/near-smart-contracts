# DaoSign Deployment Guide

This guide will walk you through setting up and deploying your DaoSign contracts on the NEAR testnet. Follow each step carefully to ensure a successful deployment.

## 📥 Clone the Repository

```sh
git clone https://github.com/DAOsign/near-smart-contracts.git && cd ./near-smart-contracts
```

### Switch to the dao_signV2.0.2

```sh
git checkout dao_signV2.0.2
```

## 🛠️ Setting Up DaoSign

### Installing Rust and Cargo

Before starting, ensure you have Rust and Cargo installed on your system. If you haven't used Rust before, follow these steps:

Install Rust using rustup:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen instructions to complete the installation.

Verify the installation:

```sh
rustc --version
cargo --version
```

This should output the installed Rust and Cargo versions.

Add the necessary components:

```sh
rustup update
```

### Installing NEAR CLI and Logging In

To interact with the NEAR blockchain, install the NEAR CLI and log in:

Install NEAR CLI:

```sh
sudo npm install -g near-cli
```

## 🏗️ Build Contracts

### Navigate to the Contract Directory and Build NFT Contract

```sh
cd ./contracts/daosign_nft
```

Build the NFT Contract:

```sh
cargo near build && cp ../../target/near/non_fungible_token/non_fungible_token.wasm ../../res
```

### Build Factory Contract

```sh
cd ../daosign_factory
cargo near build && cp ../../target/near/daosign_factory/daosign_factory.wasm ../../res
```

### Build DaoSign_App Contract

```sh
cd ../daosign_app
cargo near build && cp ../../target/near/daosign_app/daosign_app.wasm ../../res
```

In the `res` folder, the following `.wasm` files should appear:

- `daosign_app.wasm`
- `daosign_factory.wasm`
- `non_fungible_token.wasm`

### Running Tests with Cargo

Before proceeding with deployment, run the tests to verify that everything is working correctly:

```sh
cargo test
```

## 🚀 Deploying Contracts

### Login to your NEAR Account to Deploy the Factory Contract

```sh
near login
```

Follow the prompts to authorize access.

### Deploying the Factory Contract to NEAR

```sh
near deploy --accountId=<your-near-account.testnet> --wasmFile=./res/daosign_factory.wasm --initFunction='new' --initArgs='{}'
```

Replace `<your-near-account>` with your NEAR testnet account ID.

#### Result:

```
Transaction Id: 6yzjmHnmJBqQtWb9rNWgmcBCvdvp21uu7oynxuoKzRxQ
Open the explorer for more info: https://testnet.nearblocks.io/txns/6yzjmHnmJBqQtWb9rNWgmcBCvdvp21uu7oynxuoKzRxQ
```

### Login to Your Another NEAR Account to Deploy the App Contract

```sh
near login
```

Follow the prompts to authorize access.

⚠️ You need to use a different account than the one used for the Factory Contract.

### Deploying the DaoSign Contract to NEAR

```sh
near deploy --accountId=<your-near-account.testnet> --wasmFile=./res/daosign_app.wasm --initFunction='new' --initArgs='{}'
```

Replace `<your-near-account>` with your NEAR testnet account ID.

#### Result:

```
Transaction Id: 6yzjmHnmJBqQtWb9rNWgmcBCvdvp21uu7oynxuoKzRxQ
Open the explorer for more info: https://testnet.nearblocks.io/txns/6yzjmHnmJBqQtWb9rNWgmcBCvdvp21uu7oynxuoKzRxQ
```

## 📌 After Deployment

After deployment, use external scripts from the `res/utils` section to integrate with the smart contract.

Copy the `utils` folder into another project.

Install dependencies:

```sh
npm i dotenv near-api-js
```

Create a `.env` file based on `.env.example` and configure the following data:

```ini
NEAR_ACCOUNT_ID="user.testnet"
PRIVATE_KEY="ed25519:00000000..."
DEPOSIT_AMOUNT="4"
APP_CONTRACT_ID="daosignapp.testnet"
FACTORY_CONTRACT_ID="daosignfactory.testnet"
NFT_ACCOUNT_ID="daosignschema.daosignfactory.testnet"
```

- `APP_CONTRACT_ID` & `FACTORY_CONTRACT_ID` refer to the account IDs where you deployed the respective smart contracts.
- `NFT_ACCOUNT_ID` is the name of an NFT collection (e.g., `name.factory_account_id.testnet`).

### Deploy NFT Collection

```sh
node deploy_nft.js
```

#### Result:

```
✅ Transaction sent successfully!
📜 Transaction hash: 3NkyVRMdpzwCzCnHxSQQW8Y5xNncxpRagpwe4tyV5PjT
🔗 Explorer link: https://explorer.testnet.near.org/transactions/3NkyVRMdpzwCzCnHxSQQW8Y5xNncxpRagpwe4tyV5PjT
```

⚠️ You may need to change `schema_id` and `attestation_id` inside scripts when running them multiple times, as some of them (like revoke and PoS) will conflict.

### Create Schema

```sh
node create_schema.js
```

### Create Attestation

```sh
node create_attestation.js
```

### Create Proof of Signature

```sh
node deploy_nft.js
```

### Revoke Attestation

```sh
node revoke_attestation.js
```
