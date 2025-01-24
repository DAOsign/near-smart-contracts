use std::collections::HashMap;

use daosign_attestation::Attestation;
use daosign_ed25519::recover;
use daosign_schema::{Schema, SignatoryPolicy};
use ed25519_dalek::{PublicKey, Signature};
use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    env, AccountId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json;

/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSchema,
)]
pub struct ProofOfSignature {
    pub attestation_id: u128,
    pub creator: String,
    pub created_at: u64,
    pub signature: Vec<u8>,
}

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    JsonSchema,
)]
pub struct ProofOfSignatureMessage {
    pub attestation_id: u128,
    pub creator: String,
}

impl ProofOfSignature {
    pub fn to_ed25519_message(&self) -> Vec<u8> {
        let pos = ProofOfSignatureMessage {
            attestation_id: self.attestation_id,
            creator: self.creator.clone(),
        };
        // Serialize the message to JSON and convert to bytes
        serde_json::to_vec(&pos).expect("Failed to serialize message") // directly return the serialized vector
    }

    pub fn validate(
        &self,
        a: Attestation,
        s: Schema,
        user_a: &HashMap<u128, HashMap<String, Vec<Attestation>>>,
    ) {
        assert!(!a.is_revoked, "attestation revoked.");

        assert!(
            is_signatory(a.signatories, env::signer_account_id()),
            "Invalid signatory address."
        );
        let caller_id = env::signer_account_id();

        validate_signatory_policy(s, user_a, caller_id.clone());

        let signature = Signature::from_bytes(&self.signature).expect("Invalid signature");

        let caller_pk = env::signer_account_pk(); // ✅ Extract raw bytes from `near_sdk::PublicKey`

        // ✅ Ensure it's 33 bytes and remove the first byte (prefix)
        let ed25519_bytes = &caller_pk.as_bytes()[1..]; // Extract only the last 32 bytes
        let caller =
            PublicKey::from_bytes(ed25519_bytes).expect("❌ Failed to parse Dalek PublicKey");

        assert!(
            recover(caller, signature, &self.to_ed25519_message()),
            "invalid signature"
        );
    }
}

fn is_signatory(signatories: Vec<String>, caller: AccountId) -> bool {
    let mut res: bool = false;
    for signatory in signatories {
        let signatory_id: AccountId = signatory.parse().expect("Invalid address");
        if signatory_id == caller {
            res = true;
        }
    }
    res
}

fn validate_signatory_policy(
    s: Schema,
    user_a: &HashMap<u128, HashMap<String, Vec<Attestation>>>,
    signer: AccountId,
) {
    let policy_count = s.signatory_policy.len();

    if policy_count == 0 {
        return;
    }

    for policy in s.signatory_policy {
        let is_satisfied = is_policy_satisfied(policy, user_a, signer.clone());
        assert!(is_satisfied, "insufficient attestations.")
    }
}

fn is_policy_satisfied(
    policy: SignatoryPolicy,
    user_a: &HashMap<u128, HashMap<String, Vec<Attestation>>>,
    signer: AccountId,
) -> bool {
    let required_attestation_count = policy.required_schema_id.len();
    if required_attestation_count == 0 {
        return true;
    }

    let mut result = false;
    for (i, &schema_id) in policy.required_schema_id.iter().enumerate() {
        let has_attestation = get_user_attestations(user_a, schema_id, signer.clone()).len() > 0;

        match policy.operator {
            0x01 => {
                if i == 0 {
                    result = true;
                }
                result = result && has_attestation;
                if !result {
                    break;
                }
            }
            0x02 => {
                result = result || has_attestation;
                if result {
                    break;
                }
            }
            0x03 => {
                if i == 0 {
                    result = true;
                }
                result = result && !has_attestation;
                if !result {
                    break;
                }
            }
            _ => panic!("Unsupported operator"),
        }
    }

    result
}

fn get_user_attestations(
    user_a: &HashMap<u128, HashMap<String, Vec<Attestation>>>,
    schema_id: u128,
    caller: AccountId,
) -> Vec<Attestation> {
    user_a
        .get(&schema_id) // Get the map for schema_id
        .and_then(|caller_map| caller_map.get(&String::from(caller.as_str()))) // Get the attestations for caller
        .cloned() // Clone the vector (Option<Vec<Attestation>>)
        .unwrap_or_else(Vec::new) // If None, return an empty Vec
}

#[cfg(test)]
mod tests {
    use super::*;
    use daosign_ed25519::recover;
    use ed25519_dalek::{Keypair, Signature, Signer};
    use rand::rngs::OsRng;

    fn create_signer() -> Keypair {
        let mut csprng = OsRng {};
        Keypair::generate(&mut csprng)
    }

    fn sign_transaction(message: &[u8], signer: &Keypair) -> Signature {
        signer.sign(message)
    }

    #[test]
    fn check_pos() {
        // Create a signer (keypair)
        let signer = create_signer();

        let pos = ProofOfSignature {
            attestation_id: 0,                     // Default ID value
            creator: String::from("creator.test"), // The creator's address
            created_at: 0, // Default creation timestamp (you can set this to the current time if desired)
            signature: vec![0; 65], // Placeholder for the signature, e.g., 65 bytes for some types (e.g., ECDSA)
        };
        // Serialize the schema to message and sign it
        let message = pos.to_ed25519_message();
        let signature = sign_transaction(&message, &signer);

        // Verify the signature
        let success = recover(signer.public, signature, &message);

        // Assert that the signature is valid
        assert!(success, "The signature should be valid.");
    }
}
