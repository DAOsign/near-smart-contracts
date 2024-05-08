#!/bin/sh

source dev.env

./scripts/build-eip712.sh

if [ $? -ne 0 ]; then
  echo ">> Error building contract"
  exit 1
fi

echo ">> Deploying contract"

near contract deploy $DEPLOYER_ACCOUNT_ID use-file res/daosign_proof_of_authority.wasm without-init-call network-config testnet sign-with-keychain send