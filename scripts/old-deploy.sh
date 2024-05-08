export DEPLOYER_ACCOUNT_ID=misha-near.testnet

# near deploy --accountId $DEPLOYER_ACCOUNT_ID --wasmFile res/daosign_app.wasm --initFunction init --initArgs '{"token_account_id": "'"$TOKEN_ACCOUNT_ID"'", "manager": "'"$ADMIN_ACCOUNT_ID"'", "fee_account_id": "'"$FEE_ACCOUNT_ID"'"}'
near contract deploy $DEPLOYER_ACCOUNT_ID use-file res/daosign_app.wasm without-init-call network-config testnet sign-with-keychain send
near contract deploy $DEPLOYER_ACCOUNT_ID use-file res/daosign_app.wasm --initFunction new --initArgs '{}' network-config testnet sign-with-keychain send

near contract deploy $DEPLOYER_ACCOUNT_ID use-file res/daosign_app.wasm --initFunction new --initArgs '{"domain": {"name": "DAOSign", "version": "1.0", "chain_id": 1313161554, "verifying_contract": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}' --network-config testnet --sign-with-keychain --send
near deploy --accountId $DEPLOYER_ACCOUNT_ID --wasmFile res/daosign_app.wasm --initFunction new --initArgs '{"domain": {"name": "DAOSign", "version": "1.0", "chain_id": 1313161554, "verifying_contract": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}'
near contract deploy misha-near.testnet use-file res/daosign_app.wasm with-init-call new json-args '{"domain": {"name": "DAOSign", "version": "1.0", "chain_id": 1313161554, "verifying_contract": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}' prepaid-gas '30 TeraGas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
near contract deploy misha-near.testnet use-file res/daosign_app.wasm with-init-call new json-args '{}' prepaid-gas '30 TeraGas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send



near contract call-function as-read-only $DEPLOYER_ACCOUNT_ID get_proof_of_authority network-config testnet now