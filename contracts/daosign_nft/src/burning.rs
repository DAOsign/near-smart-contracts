use crate::*;
use near_sdk::{self, env, near_bindgen, serde_json::json, NearToken}; // ✅ Import Contract from lib.rs

#[near_bindgen]
impl Contract {
    // -------------------------- change methods ---------------------------

    /// 🔥 The token will be permanently removed from this contract. Burn each
    /// token_id in `token_ids`.
    #[payable]
    pub fn nft_burn(&mut self, token_id: String) {
        let attached_deposit = env::attached_deposit();
        assert!(attached_deposit >= NearToken::from_yoctonear(1));

        // Ensure token exists
        let token = self.nft_token(token_id.clone());
        require!(token.is_some(), "Token does not exist");
        let token = token.unwrap();

        let owner_id = token.owner_id.clone();

        // ✅ Remove from owner_by_id
        self.tokens.owner_by_id.remove(&token_id);

        // ✅ Remove metadata (if exists)
        if let Some(ref mut metadata_by_id) = self.tokens.token_metadata_by_id {
            metadata_by_id.remove(&token_id);
        }

        // ✅ Remove token from tokens_per_owner
        if let Some(tokens_per_owner) = &mut self.tokens.tokens_per_owner {
            let mut owned_tokens = tokens_per_owner
                .get(&owner_id)
                .unwrap_or_else(|| env::panic_str("Owner does not own any tokens"));

            owned_tokens.remove(&token_id);
            if owned_tokens.is_empty() {
                tokens_per_owner.remove(&owner_id); // Remove the owner if they have no tokens left
            } else {
                tokens_per_owner.insert(&owner_id, &owned_tokens);
            }
        }

        // ✅ Remove approvals (if enabled)
        if let Some(approvals_by_id) = &mut self.tokens.approvals_by_id {
            approvals_by_id.remove(&token_id);
        }

        // ✅ Log NEP-171 burn event
        env::log_str(
            &json!({
                "standard": "nep171",
                "version": "1.0.0",
                "event": "nft_burn",
                "data": [{
                    "owner_id": owner_id,
                    "authorized_id": null,
                    "token_ids": [token_id],
                    "memo": "NFT burned"
                }]
            })
            .to_string(),
        );
    }
}
