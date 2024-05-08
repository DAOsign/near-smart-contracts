#!/bin/bash
set -eox pipefail

echo ">> Building contract"

rustup target add wasm32-unknown-unknown
cargo build -p daosign_proof_of_authority --target wasm32-unknown-unknown --profile=contract

cp ./target/wasm32-unknown-unknown/contract/daosign_proof_of_authority.wasm res/daosign_proof_of_authority.wasm
