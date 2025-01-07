use daosign_ed25519::recover;
use ed25519_dalek::{PublicKey, Signature};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json;

/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SchemaMetadata {
    pub name: String,
    pub description: String,
    pub attestation_type: String,
    pub nft_name: String,
    pub nft_symbol: String,
    pub creator: [u8; 32], // Use String to represent address
    pub created_at: u32,
    pub is_nft: bool,
    pub is_public: bool,
    pub is_revokable: bool,
    pub expire_in: u32,
}
/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignatoryPolicy {
    pub operator: u8, // bytes1 in Solidity can be represented as u8
    pub signatory_description: String,
    pub required_schema_id: Vec<u128>, // uint256 is a large number, best suited to `u128` or `u256` library
}

/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SchemaDefinition {
    pub definition_type: String,
    pub definition_name: String,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    pub schema_id: u128, // Assuming large ids
    pub metadata: SchemaMetadata,
    pub signatory_policy: Vec<SignatoryPolicy>,
    pub schema_definition: Vec<SchemaDefinition>,
    //TODO: change to Signature instance
    pub signature: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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

    pub fn validate(&self, caller: PublicKey) {
        // Check if the sender of the request is the creator of the schema
        assert!(
            self.metadata.creator == caller.to_bytes(),
            "unauthorized schema creator!"
        );

        // Ensure that the schema's definition is not empty
        assert!(self.schema_definition.len() == 0, "empty schema definition");

        //TODO: modify to send Signature obj into recover
        let signature = Signature::from_bytes(&self.signature).expect("Invalid signature");

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
                creator: [0u8; 32], // Example address as hex
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
