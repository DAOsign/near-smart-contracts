#!/bin/bash
set -eox pipefail

echo ">> Building contract"

rustup target add wasm32-unknown-unknown
cargo build -p daosign_eip712 --target wasm32-unknown-unknown --profile=contract

cp ./target/wasm32-unknown-unknown/contract/daosign_eip712.wasm res/daosign_eip712.wasm
