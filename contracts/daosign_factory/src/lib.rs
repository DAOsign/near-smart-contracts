mod daosign_factory {
    use borsh::{BorshDeserialize, BorshSerialize};
    use near_contract_standards::non_fungible_token::metadata::NFTContractMetadata;
    use near_sdk::{
        env, log, near_bindgen,
        serde::{Deserialize, Serialize},
        serde_json::json,
        AccountId, Gas, NearToken, Promise,
    };
    const FT_WASM_CODE: &[u8] = include_bytes!("../../../res/non_fungible_token.wasm");
    const NEAR_PER_STORAGE: NearToken = NearToken::from_yoctonear(10u128.pow(19)); // 10e19yⓃ
    const TGAS: Gas = Gas::from_tgas(5); // Adjusted to standard usage
    const NO_DEPOSIT: NearToken = NearToken::from_near(0); // 0yⓃ

    #[near_bindgen]
    #[derive(
        Default,
        BorshDeserialize,
        BorshSerialize,
        Serialize,
        Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
    )]
    pub struct DaoSignFactory {}

    #[near_bindgen]
    impl DaoSignFactory {
        #[init]
        pub fn new() -> Self {
            Self {}
        }

        #[payable] // Allows NEAR deposit
        pub fn deploy_nft(&mut self, schema_id: u128, nft_acc: String) -> Promise {
            let current_account = env::current_account_id();
            let code = FT_WASM_CODE;

            // Convert the NFT account string into an AccountId
            let nft_acc: AccountId = nft_acc.parse().expect("Invalid account ID");

            // Calculate storage cost
            let contract_bytes = code.len() as u128;
            let contract_storage_cost = NEAR_PER_STORAGE.saturating_mul(contract_bytes);
            let minimum_needed =
                contract_storage_cost.saturating_add(NearToken::from_millinear(100));

            // Get the attached deposit
            let attached_deposit = env::attached_deposit();
            assert!(
                attached_deposit >= minimum_needed,
                "Attach at least {} yⓃ to cover deployment costs",
                minimum_needed
            );

            let nft_args = Self::get_nft_metadata();
            let args = json!({
                "owner_id": current_account,
                "metadata": nft_args
            })
            .to_string()
            .into_bytes();

            log!(
                "Deploying contract to {} with schema_id {}",
                nft_acc,
                schema_id
            );

            Promise::new(nft_acc.clone())
            .create_account()
            .transfer(attached_deposit) // Use the attached deposit
            .deploy_contract(code.to_vec())
            .function_call("new".to_owned(), args, NO_DEPOSIT, TGAS)
        }

        pub fn get_nft_metadata() -> NFTContractMetadata {
            NFTContractMetadata {
                spec: String::from("nft-1.0.0"),
                name: "Example NEAR non-fungible token".to_string(),
                symbol: "EXAMPLE".to_string(),
                icon: None,
                base_uri: None,
                reference: None,
                reference_hash: None,
            }
        }
    }
}
