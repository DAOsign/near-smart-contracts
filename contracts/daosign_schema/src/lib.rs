use daosign_ed25519::recover;
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
pub struct SchemaMetadata {
    pub name: String,
    pub description: String,
    pub attestation_type: String,
    pub nft_name: String,
    pub nft_symbol: String,
    pub collection_id: String,
    pub creator: String, // Use String to represent address
    pub created_at: u64,
    pub is_nft: bool,
    pub is_public: bool,
    pub is_revokable: bool,
    pub expire_in: u64,
}
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
pub struct SignatoryPolicy {
    pub operator: u8, // bytes1 in Solidity can be represented as u8
    pub signatory_description: String,
    pub required_schema_id: Vec<u128>, // uint256 is a large number, best suited to `u128` or `u256` library
}

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
pub struct SchemaDefinition {
    pub definition_type: String,
    pub definition_name: String,
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
pub struct Schema {
    pub schema_id: u128, // Assuming large ids
    pub metadata: SchemaMetadata,
    pub signatory_policy: Vec<SignatoryPolicy>,
    pub schema_definition: Vec<SchemaDefinition>,
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
pub struct SchemaMessage {
    schema_id: u128, // Assuming large ids
    metadata: SchemaMetadata,
    signatory_policy: Vec<SignatoryPolicy>,
    schema_definition: Vec<SchemaDefinition>,
}

impl Schema {
    pub fn to_ed25519_message(&self) -> Vec<u8> {
        let schema = SchemaMessage {
            schema_id: self.schema_id,
            metadata: self.metadata.clone(),
            signatory_policy: self.signatory_policy.clone(),
            schema_definition: self.schema_definition.clone(),
        };
        // Serialize the message to JSON and convert to bytes
        serde_json::to_vec(&schema).expect("Failed to serialize message") // directly return the serialized vector
    }

    pub fn validate(&self) {
        // Check if the sender of the request is the creator of the schema
        let creator_id: AccountId = self.metadata.creator.parse().expect("Invalid address");

        assert!(
            creator_id == env::signer_account_id(),
            "unauthorized schema creator!"
        );

        // Ensure that the schema's definition is not empty
        assert!(
            self.schema_definition.len() != 0,
            "empty schema definition!"
        );

        let signature = Signature::from_bytes(&self.signature).expect("Invalid signature");

        println!("{:?}", env::signer_account_pk());

        let caller_pk = env::signer_account_pk(); // ✅ Extract raw bytes from `near_sdk::PublicKey`

        // ✅ Ensure it's 33 bytes and remove the first byte (prefix)
        let ed25519_bytes = &caller_pk.as_bytes()[1..]; // Extract only the last 32 bytes
        let caller =
            PublicKey::from_bytes(ed25519_bytes).expect("❌ Failed to parse Dalek PublicKey");

        //Wrong signature
        assert!(
            recover(caller, signature, &self.to_ed25519_message()),
            "invalid signature"
        );
    }
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
    fn test_schema() {
        // Create a signer (keypair)
        let signer = create_signer();

        // Create the message instance
        let schema = Schema {
            schema_id: 0,
            metadata: SchemaMetadata {
                name: String::from("daosign_vacancy"),
                description: String::from("Blockchain developer vacancy"),
                attestation_type: String::from("agreement"),
                nft_name: String::from("vacancy collection"),
                nft_symbol: String::from("vcc"),
                collection_id: "coolection.testnet"
                    .parse()
                    .expect("Invalid schema account ID!"),
                creator: "creator.testnet"
                    .parse()
                    .expect("Invalid schema account ID!"), // Example address as hex
                created_at: 1,
                is_nft: true,
                is_public: false,
                is_revokable: true,
                expire_in: 0,
            },
            signatory_policy: vec![SignatoryPolicy {
                operator: 0x01, // For example, "AND" operation
                signatory_description: String::from("Main Signatory"),
                required_schema_id: vec![0],
            }],
            schema_definition: vec![SchemaDefinition {
                definition_type: String::from("string"),
                definition_name: String::from("vacancies"),
            }],
            //TODO: set default Signature instance
            signature: vec![0; 65],
        };

        // Serialize the schema to message and sign it
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &signer);

        // Verify the signature
        let success = recover(signer.public, signature, &message);

        // Assert that the signature is valid
        assert!(success, "The signature should be valid.");
    }
}
