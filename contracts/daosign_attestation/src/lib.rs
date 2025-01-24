use daosign_ed25519::recover;
use daosign_schema::Schema;
use ed25519_dalek::{PublicKey, Signature};
use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    env,
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
pub struct Attestation {
    pub attestation_id: u128,
    pub schema_id: u128,
    pub attestation_result: Vec<AttestationResult>,
    pub creator: String,
    pub recipient: String,
    pub created_at: u64, // Use String to represent address
    pub signatories: Vec<String>,
    pub signature: Vec<u8>,
    pub is_revoked: bool,
    pub revoked_at: u64,
    pub revoke_signature: Vec<u8>,
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
pub struct AttestationMessage {
    attestation_id: u128,
    schema_id: u128,
    attestation_result: Vec<AttestationResult>,
    creator: String,
    recipient: String,
    created_at: u64, // Use String to represent address
    signatories: Vec<String>,
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
pub struct AttestationResult {
    pub attestation_result_type: String,
    pub name: String,
    pub value: Vec<u8>,
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
pub struct RevokeMessage {
    attestation_id: u128,
}

impl Attestation {
    pub fn to_ed25519_message(&self) -> Vec<u8> {
        let attestaion = AttestationMessage {
            attestation_id: self.attestation_id,
            schema_id: self.schema_id,
            attestation_result: self.attestation_result.clone(),
            creator: self.creator.clone(),
            recipient: self.recipient.clone(),
            created_at: self.created_at,
            signatories: self.signatories.clone(),
        };
        // Serialize the message to JSON and convert to bytes
        serde_json::to_vec(&attestaion).expect("Failed to serialize message") // directly return the serialized vector
    }

    pub fn to_ed25519_message_revoke(&self) -> Vec<u8> {
        let revoke = RevokeMessage {
            attestation_id: self.attestation_id,
        };
        // Serialize the message to JSON and convert to bytes
        serde_json::to_vec(&revoke).expect("Failed to serialize message") // directly return the serialized vector
    }

    pub fn validate(&self, s: Schema) {
        // Ensure that if the schema is private, the sender is the creator of the attestation.
        if !s.metadata.is_public {
            assert!(
                self.creator == env::signer_account_id(),
                "unauthorized attestator!"
            );
        }

        // Get the current block timestamp in seconds
        let current_timestamp = env::block_timestamp();

        // Check if the schema has expired based on its metadata
        if s.metadata.expire_in != 0 {
            assert!(
                (s.metadata.created_at + s.metadata.expire_in
                    < current_timestamp.try_into().unwrap()),
                "schema already expired!"
            );
        }

        // Ensure that the length of attestation results matches the length of the schema definition
        assert!(
            self.attestation_result.len() == s.schema_definition.len(),
            "attestation length mismatch!"
        );

        let mut i = 0;
        while i < s.schema_definition.len() {
            // Check that the names match between the schema definition and the attestation result
            assert!(
                s.schema_definition[i].definition_name == self.attestation_result[i].name,
                "attestation name mismatch!"
            );
            // Check that the types match between the schema definition and the attestation result
            assert!(
                s.schema_definition[i].definition_type
                    == self.attestation_result[i].attestation_result_type,
                "attestation type mismatch!"
            );
            i += 1;
        }

        let signature = Signature::from_bytes(&self.signature).expect("Invalid signature");

        let caller_pk = env::signer_account_pk(); // ✅ Extract raw bytes from `near_sdk::PublicKey`

        // ✅ Ensure it's 33 bytes and remove the first byte (prefix)
        let ed25519_bytes = &caller_pk.as_bytes()[1..]; // Extract only the last 32 bytes
        let caller =
            PublicKey::from_bytes(ed25519_bytes).expect("❌ Failed to parse Dalek PublicKey");
        //Check signature
        assert!(
            recover(caller, signature, &self.to_ed25519_message()),
            "invalid signature"
        );
    }

    pub fn validate_revoke(&self, s: Schema, sig: Vec<u8>) {
        assert!(s.metadata.is_revokable, "attestation can't be revoked!");

        // Check if the sender is the original creator of the attestation before revoking it
        assert!(
            self.creator == env::signer_account_id(),
            "unauthorized attestator!"
        );

        let signature = Signature::from_bytes(&sig).expect("Invalid signature");

        let caller_pk = env::signer_account_pk(); // ✅ Extract raw bytes from `near_sdk::PublicKey`

        // ✅ Ensure it's 33 bytes and remove the first byte (prefix)
        let ed25519_bytes = &caller_pk.as_bytes()[1..]; // Extract only the last 32 bytes
        let caller =
            PublicKey::from_bytes(ed25519_bytes).expect("❌ Failed to parse Dalek PublicKey");
        //Check signature
        assert!(
            recover(caller, signature, &self.to_ed25519_message_revoke()),
            "invalid signature"
        );
    }
}

#[cfg(test)]
mod test {
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
    fn test_attestation() {
        let signer = create_signer();

        // Create a vector of AttestationResults
        let attestation_results = vec![
            AttestationResult {
                attestation_result_type: String::from("string"),
                name: String::from("vacancies"),
                value: vec![18, 52, 86, 171, 205, 239, 255, 255], // Example byte data; adjust as needed
            },
            AttestationResult {
                attestation_result_type: String::from("uint256"),
                name: String::from("salary"),
                value: vec![16, 0], // Another example byte data
            },
        ];

        // Create the Attestation message with multiple results
        let attestation = Attestation {
            attestation_id: 0,
            schema_id: 0,
            attestation_result: attestation_results, // Assign the vector of results
            creator: "test.collection.testnet".parse().expect("Invalid address"), // Encode the creator's address
            recipient: "test.collection.testnet".parse().expect("Invalid address"), // Encode the recipient's address
            created_at: 1,                                                          // Timestamp
            signatories: vec![
                "test.collection.testnet".parse().expect("Invalid address"), // First signatory address
                "test.collection.testnet".parse().expect("Invalid address"), // Second signatory address
            ],
            signature: vec![0; 65],
            is_revoked: false,
            revoked_at: 0,
            revoke_signature: vec![0; 65],
        };
        // Serialize the schema to message and sign it
        let message = attestation.to_ed25519_message();
        let signature = sign_transaction(&message, &signer);

        // Verify the signature
        let success = recover(signer.public, signature, &message);

        // Assert that the signature is valid
        assert!(success, "The signature should be valid.");
    }

    #[test]
    fn test_revoke() {
        let signer = create_signer();

        // Create a vector of AttestationResults
        let attestation_results = vec![
            AttestationResult {
                attestation_result_type: String::from("string"),
                name: String::from("vacancies"),
                value: vec![18, 52, 86, 171, 205, 239, 255, 255], // Example byte data; adjust as needed
            },
            AttestationResult {
                attestation_result_type: String::from("uint256"),
                name: String::from("salary"),
                value: vec![16, 0], // Another example byte data
            },
        ];

        // Create the Attestation message with multiple results
        let attestation = Attestation {
            attestation_id: 0,
            schema_id: 0,
            attestation_result: attestation_results, // Assign the vector of results
            creator: "test.collection.testnet".parse().expect("Invalid address"), // Encode the creator's address
            recipient: "test.collection.testnet".parse().expect("Invalid address"), // Encode the recipient's address
            created_at: 1,                                                          // Timestamp
            signatories: vec![
                "test.collection.testnet".parse().expect("Invalid address"), // First signatory address
                "test.collection.testnet".parse().expect("Invalid address"), // Second signatory address
            ],
            signature: vec![0; 65],
            is_revoked: false,
            revoked_at: 0,
            revoke_signature: vec![0; 65],
        };
        // Serialize the schema to message and sign it
        let message = attestation.to_ed25519_message_revoke();
        let signature = sign_transaction(&message, &signer);

        // Verify the signature
        let success = recover(signer.public, signature, &message);

        // Assert that the signature is valid
        assert!(success, "The signature should be valid.");
    }
}
