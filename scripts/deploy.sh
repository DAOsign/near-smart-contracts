#!/bin/sh

source dev.env

make build

if [ $? -ne 0 ]; then
  echo ">> Error building contract"
  exit 1
fi

echo ">> Deploying contract"

near contract deploy $DEPLOYER_ACCOUNT_ID use-file res/daosign_app.wasm with-init-call new json-args '{"domain": {"name": "daosign", "version": "0.1.0", "chain_id": 1, "verifying_contract": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}' prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send

# without init call
# near contract deploy $DEPLOYER_ACCOUNT_ID use-file res/daosign_app.wasm without-init-call network-config testnet sign-with-keychain send