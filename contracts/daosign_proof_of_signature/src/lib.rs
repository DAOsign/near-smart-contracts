use daosign_eip712::{
    eip712_domain_type, EIP712Domain, EIP712Message, EIP712PropertyType, Packable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
// use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use schemars::JsonSchema;

static PROOF_OF_SIGNATURE_TYPEHASH: [u8; 32] = [
    121, 27, 217, 70, 217, 77, 222, 106, 102, 69, 3, 201, 6, 50, 65, 200, 192, 203, 113, 79, 199,
    225, 197, 114, 141, 23, 169, 246, 181, 166, 163, 38,
];

fn proof_of_signature_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("attestation_id"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("creator"),
            r#type: String::from("address"),
        },
    ]
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
pub struct ProofOfSignature {
    pub attestation_id: u128,
    pub creator: [u8; 20],
    pub created_at: u32,
    pub signature: Vec<u8>,
}

impl ProofOfSignature {
    pub fn to_eip712_message(&self, domain: &EIP712Domain) -> EIP712Message<ProofOfSignature> {
        EIP712Message {
            types: HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("ProofOfSignature"), proof_of_signature_type()),
            ]),
            domain: domain.clone(),
            primary_type: String::from("ProofOfSignature"),
            message: self.clone(),
        }
    }
}

impl Packable for ProofOfSignature {
    fn pack(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        // 1. Add the type hash at the beginning
        encoded.extend_from_slice(&PROOF_OF_SIGNATURE_TYPEHASH);

        // 2. Pack attestation_id
        encoded.extend_from_slice(&self.attestation_id.to_be_bytes());

        // 3. Pack creator address
        encoded.extend_from_slice(&self.creator);

        // Return the encoded data
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daosign_eip712::sha3;
    use hex::FromHex;

    const SOME_ADDR: [u8; 20] = [
        243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185,
        34, 102,
    ];

    fn domain() -> EIP712Domain {
        EIP712Domain {
            name: String::from("daosign"),
            version: String::from("0.1.0")
        }
    }

    #[test]
    fn check_typehash() {
        assert_eq!(
            PROOF_OF_SIGNATURE_TYPEHASH,
            sha3(b"ProofOfSignature(uint256 attestation_id,address creator)")
        );
    }

    #[test]
    fn check_type() {
        let message = ProofOfSignature {
            attestation_id: 0,      // Default ID value
            creator: SOME_ADDR,     // The creator's address
            created_at: 0, // Default creation timestamp (you can set this to the current time if desired)
            signature: vec![0; 65], // Placeholder for the signature, e.g., 65 bytes for some types (e.g., ECDSA)
        };

        let expected_hash: [u8; 32] = <[u8; 32]>::from_hex(
            "2728e05cad9264c189d6efc92cd42288f9ac0d77454d603a24558c35c2192c62",
        )
        .unwrap();
        assert_eq!(expected_hash, daosign_eip712::hash(&message));

        let signature = <[u8; 65]>::from_hex("77d2146c392a9bbc8ac4a6219f54fa09f26f717acab0334de1430aee8182692e2b546435d1b93e265516cb03375d758af9d9e262d05291e8f00fcd8e70efdc721b").unwrap();
        let recovered = daosign_eip712::recover(&domain(), &message, &signature);
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
