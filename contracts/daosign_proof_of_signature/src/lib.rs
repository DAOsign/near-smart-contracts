use daosign_attestation::Attestation;
use daosign_ed25519::recover;
use daosign_schema::{Schema, SignatoryPolicy};
use ed25519_dalek::{PublicKey, Signature};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json;

/// ProofOfSignature struct representing the Proof-of-Signature parameters.
// #[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfSignature {
    pub attestation_id: u128,
    pub creator: String,
    pub created_at: u32,
    pub signature: Vec<u8>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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

    pub fn validate(&self, a: Attestation, s: Schema, caller: PublicKey) {
        assert!(a.is_revoked, "attestation revoked.");

        assert!(
            is_signatory(a.signatories, caller),
            "Invalid signatory address."
        );

        // validate_signatory_policy(self, s, caller);

        //TODO: modify to send Signature obj into recover
        let signature = Signature::from_bytes(&self.signature).expect("Invalid signature");

        assert!(
            recover(caller, signature, &self.to_ed25519_message()),
            "invalid signature"
        );
    }
}
fn is_signatory(signatories: Vec<[u8; 32]>, caller: PublicKey) -> bool {
    let res: bool = false;
    for signator in signatories {
        let signator_key = PublicKey::from_bytes(&signator).unwrap();
        if signator_key == caller {
            res == true;
        }
    }
    res
}

// fn validate_signatory_policy(pos: &ProofOfSignature, s: Schema, signer: PublicKey) {
//     let policy_count = s.signatory_policy.len();

//     if policy_count == 0 {
//         return;
//     }

//     for policy in s.signatory_policy {
//         let is_satisfied = is_policy_satisfied(pos.clone(), policy, signer);
//         assert!(is_satisfied, "insufficient attestations.")
//     }
// }

// fn is_policy_satisfied(pos: ProofOfSignature, policy: SignatoryPolicy, signer: PublicKey) -> bool {
//     let required_attestation_count = policy.required_schema_id.len();
//     if required_attestation_count == 0 {
//         return true;
//     }

//     let mut result = false;
//     for (i, &schema_id) in policy.required_schema_id.iter().enumerate() {
//         let has_attestation = get_user_attestations().len() > 0;

//         match policy.operator {
//             0x01 => {
//                 if i == 0 {
//                     result = true;
//                 }
//                 result = result && has_attestation;
//                 if !result {
//                     break;
//                 }
//             }
//             0x02 => {
//                 result = result || has_attestation;
//                 if result {
//                     break;
//                 }
//             }
//             0x03 => {
//                 if i == 0 {
//                     result = true;
//                 }
//                 result = result && !has_attestation;
//                 if !result {
//                     break;
//                 }
//             }
//             _ => panic!("Unsupported operator"),
//         }
//     }

//     result
// }

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
            attestation_id: 0,             // Default ID value
            creator: hex::encode([0; 20]), // The creator's address
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
