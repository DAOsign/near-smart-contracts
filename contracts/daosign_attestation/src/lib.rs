use daosign_eip712::{
    eip712_domain_type, sha3, EIP712Domain, EIP712Message, EIP712PropertyType, Packable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
// use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use schemars::JsonSchema;

//ATTESTATION_TYPE_HASH
// 0x0a36d53742706ba39b8199d65805e5938e9f5d384d5ee1c5da817c83e782af24
static ATTESTATION_TYPEHASH: [u8; 32] = [
    10, 54, 213, 55, 66, 112, 107, 163, 155, 129, 153, 214, 88, 5, 229, 147, 142, 159, 93, 56, 77,
    94, 225, 197, 218, 129, 124, 131, 231, 130, 175, 36,
];

//ATTESTATION_RESULT_TYPE_HASH
// 0x5286ea1618f89486895380f01ab3cc41fe93f50b22a5cb5ea532c2fdedf300ab
static ATTESTATION_RESULT_TYPEHASH: [u8; 32] = [
    82, 134, 234, 22, 24, 248, 148, 134, 137, 83, 128, 240, 26, 179, 204, 65, 254, 147, 245, 11,
    34, 165, 203, 94, 165, 50, 194, 253, 237, 243, 0, 171,
];

fn attestation_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("attestation_id"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("schema_id"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("attestation_result"),
            r#type: String::from("AttestationResult[]"),
        },
        EIP712PropertyType {
            name: String::from("creator"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("recipient"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("created_at"),
            r#type: String::from("uint32"),
        },
        EIP712PropertyType {
            name: String::from("signatories"),
            r#type: String::from("address[]"),
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
pub struct Attestation {
    attestation_id: u128,
    schema_id: u128,
    attestation_result: Vec<AttestationResult>,
    creator: [u8; 20],
    recipient: [u8; 20],
    created_at: u32, // Use String to represent address
    signatories: Vec<[u8; 20]>,
    signature: Vec<u8>,
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
    attestation_result_type: String,
    name: String,
    value: Vec<u8>,
}

impl Attestation {
    pub fn to_eip712_message(&self, domain: &EIP712Domain) -> EIP712Message<Attestation> {
        EIP712Message {
            types: HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("Attestation"), attestation_type()),
            ]),
            domain: domain.clone(),
            primary_type: String::from("Attestation"),
            message: self.clone(),
        }
    }
}

impl Packable for Attestation {
    fn pack(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        // 1. Add the type hash at the beginning
        encoded.extend_from_slice(&ATTESTATION_TYPEHASH);

        // 2. Encode attestation_id
        encoded.extend_from_slice(&self.attestation_id.to_be_bytes());

        // 3. Encode schema_id
        encoded.extend_from_slice(&self.schema_id.to_be_bytes());

        // 4. Encode attestation results using the new function
        encoded.extend_from_slice(&sha3(&pack_attestation_result(&self.attestation_result)));

        // 5. Encode creator address
        encoded.extend_from_slice(&self.creator);

        // 6. Encode recipient address
        encoded.extend_from_slice(&self.recipient);

        // 7. Encode created_at
        encoded.extend_from_slice(&self.created_at.to_be_bytes());

        // 8. Encode signatories
        encoded.extend_from_slice(&pack_signatories(self.signatories.clone()));

        // Return the encoded data
        encoded
    }
}

fn pack_attestation_result(attestation_results: &[AttestationResult]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    // 1. Iterate over each AttestationResult and pack its fields
    for result in attestation_results {
        // 2. Add the type hash at the beginning
        encoded.extend_from_slice(&ATTESTATION_RESULT_TYPEHASH);

        // 3. Encode attestation_result_type
        encoded.extend_from_slice(&sha3(result.attestation_result_type.as_bytes()));

        // 4. Encode name
        encoded.extend_from_slice(&sha3(result.name.as_bytes()));

        // 5. Encode the value (assumed to be bytes)
        encoded.extend_from_slice(&result.value);
    }

    // Return the encoded data
    encoded
}

fn pack_signatories(signatories: Vec<[u8; 20]>) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    // 1. Iterate over each signatory and pack its address
    for signer in signatories {
        // 2. Decode the hex string to bytes
        encoded.extend_from_slice(&signer);
    }

    // Return the encoded data
    encoded
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::FromHex;

    const OWNER_ADDR: [u8; 20] = [
        243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185,
        34, 102,
    ];
    const OTHER_ADDR: [u8; 20] = [
        112, 153, 121, 112, 197, 24, 18, 220, 58, 1, 12, 125, 1, 181, 14, 13, 23, 220, 121, 200,
    ];
    const SOME_ADDR: [u8; 20] = [
        60, 68, 205, 221, 182, 169, 0, 250, 43, 88, 93, 210, 153, 224, 61, 18, 250, 66, 147, 188,
    ];
    fn domain() -> EIP712Domain {
        EIP712Domain {
            name: String::from("daosign"),
            version: String::from("0.1.0"),
        }
    }

    #[test]
    fn check_typehash() {
        assert_eq!(ATTESTATION_TYPEHASH, sha3(b"Attestation(uint256 attestation_id,uint256 schema_id,AttestationResult[] attestation_result,address creator,address recipient,uint32 created_at,address[] signatories)AttestationResult(string attestation_result_type,string name,bytes value)"))
    }

    #[test]
    fn check_type() {
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
        let message = Attestation {
            attestation_id: 0,
            schema_id: 0,
            attestation_result: attestation_results, // Assign the vector of results
            creator: OWNER_ADDR,                     // Encode the creator's address
            recipient: OTHER_ADDR,                   // Encode the recipient's address
            created_at: 1,                           // Timestamp
            signatories: vec![
                OTHER_ADDR, // First signatory address
                SOME_ADDR,  // Second signatory address
            ],
            signature: Vec::new(),
        };
        let expected_hash: [u8; 32] = <[u8; 32]>::from_hex(
            "a658657462f8eccf97d075b6b2ca03617bf9ebcb4b27f615d74b1ad50106eb6c",
        )
        .unwrap();
        assert_eq!(expected_hash, daosign_eip712::hash(&message));

        let signature = <[u8; 65]>::from_hex("54534ed61073d0beba225616c8220f02acd3a819d2cd378533778d4f6d3986057b012e4855ba9e7bfba086afad2c927cd416acd9c30e260433ac9dc9b10e82c01c").unwrap();
        let recovered = daosign_eip712::recover(&domain(), &message, &signature);
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
