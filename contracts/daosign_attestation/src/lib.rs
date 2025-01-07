use daosign_ed25519::recover;
use daosign_schema::Schema;
use ed25519_dalek::{PublicKey, Signature};
use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    env,
};
use serde::{Deserialize, Serialize};
use serde_json;

/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub attestation_id: u128,
    pub schema_id: u128,
    pub attestation_result: Vec<AttestationResult>,
    pub creator: [u8; 32],
    pub recipient: [u8; 32],
    pub created_at: u32, // Use String to represent address
    pub signatories: Vec<[u8; 32]>,
    pub signature: Vec<u8>,
    pub is_revoked: bool,
    pub revoked_at: u32,
    pub revoke_signature: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestationMessage {
    attestation_id: u128,
    schema_id: u128,
    attestation_result: Vec<AttestationResult>,
    creator: [u8; 32],
    recipient: [u8; 32],
    created_at: u32, // Use String to represent address
    signatories: Vec<[u8; 32]>,
}
/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestationResult {
    pub attestation_result_type: String,
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RevokeMessage {
    attestation_id: u128,
}

impl Attestation {
    pub fn to_ed25519_message(&self) -> Vec<u8> {
        let attestaion = AttestationMessage {
            attestation_id: self.attestation_id,
            schema_id: self.schema_id,
            attestation_result: self.attestation_result.clone(),
            creator: self.creator,
            recipient: self.recipient,
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

    pub fn validate(&self, s: Schema, caller: PublicKey) {
        // Ensure that if the schema is private, the sender is the creator of the attestation.
        assert!(
            !s.metadata.is_public && self.creator != caller.to_bytes(),
            "unauthorized attestator"
        );
        // Get the current block timestamp in seconds
        let current_timestamp = env::block_timestamp();

        // Check if the schema has expired based on its metadata
        assert!(
            s.metadata.expire_in != 0
                && (s.metadata.created_at + s.metadata.expire_in
                    < current_timestamp.try_into().unwrap()),
            "schema already expired"
        );

        // Ensure that the length of attestation results matches the length of the schema definition
        assert!(
            self.attestation_result.len() != s.schema_definition.len(),
            "attestation length mismatch"
        );

        let mut i = 0;
        while i < s.schema_definition.len() {
            // Check that the names match between the schema definition and the attestation result
            assert!(
                s.schema_definition[i].definition_name == self.attestation_result[i].name,
                "attestation name mismatch"
            );
            // Check that the types match between the schema definition and the attestation result
            assert!(
                s.schema_definition[i].definition_type
                    == self.attestation_result[i].attestation_result_type,
                "attestation type mismatch"
            );
            i += 1;
        }

        //TODO: modify to send Signature obj into recover
        let signature = Signature::from_bytes(&self.signature).expect("Invalid signature");

        //Check signature
        assert!(
            recover(caller, signature, &self.to_ed25519_message()),
            "invalid signature"
        );
    }

    pub fn validate_revoke(&self, s: Schema, caller: PublicKey) {
        assert!(!s.metadata.is_revokable, "attestation can't be revoked");

        // Check if the sender is the original creator of the attestation before revoking it
        assert!(self.creator != caller.to_bytes(), "unauthorized attestator");

        //TODO: modify to send Signature obj into recover
        let signature = Signature::from_bytes(&self.revoke_signature).expect("Invalid signature");

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
            creator: [0; 32],                        // Encode the creator's address
            recipient: [0; 32],                      // Encode the recipient's address
            created_at: 1,                           // Timestamp
            signatories: vec![
                [0; 32], // First signatory address
                [0; 32], // Second signatory address
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
            creator: [0; 32],                        // Encode the creator's address
            recipient: [0; 32],                      // Encode the recipient's address
            created_at: 1,                           // Timestamp
            signatories: vec![
                [0; 32], // First signatory address
                [0; 32], // Second signatory address
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
