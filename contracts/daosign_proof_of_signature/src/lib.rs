use daosign_eip712::{
    eip712_domain_type, sha3, EIP712Domain, EIP712Message, EIP712PropertyType, Packable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

static PROOF_OF_SIGNATURE_TYPEHASH: [u8; 32] = [
    121, 27, 217, 70, 217, 77, 222, 106, 102, 69, 3, 201, 6, 50, 65, 200, 192, 203, 113, 79, 199,
    225, 197, 114, 141, 23, 169, 246, 181, 166, 163, 38,
];

fn proof_of_signature_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("signer"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("authorityCID"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("timestamp"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("string"),
        },
    ]
}

/// ProofOfSignature struct representing the Proof-of-Signature parameters.
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfSignature {
    pub name: String,
    pub signer: [u8; 20],
    pub authority_cid: String,
    pub timestamp: u64,
    pub metadata: String,
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
        encoded.extend_from_slice(&PROOF_OF_SIGNATURE_TYPEHASH.clone());
        encoded.extend_from_slice(&sha3(self.name.as_bytes()));
        encoded.extend_from_slice(<[u8; 12]>::default().as_slice());
        encoded.extend_from_slice(&self.signer.clone());
        encoded.extend_from_slice(&sha3(self.authority_cid.as_bytes()));
        encoded.extend_from_slice(<[u8; 24]>::default().as_slice());
        encoded.extend_from_slice(&self.timestamp.to_be_bytes());
        encoded.extend_from_slice(&sha3(self.metadata.as_bytes()));
        encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    const SOME_ADDR: [u8; 20] = [
        243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185,
        34, 102,
    ];

    fn domain() -> EIP712Domain {
        EIP712Domain {
            name: String::from("daosign"),
            version: String::from("0.1.0"),
            chain_id: 1,
            verifying_contract: <[u8; 20]>::from_hex("0000000000000000000000000000000000000000")
                .expect("bad address"),
        }
    }

    #[test]
    fn check_typehash() {
        assert_eq!(PROOF_OF_SIGNATURE_TYPEHASH, sha3(b"ProofOfSignature(string name,address signer,string authorityCID,uint256 timestamp,string metadata)"));
    }

    #[test]
    fn check_type() {
        let message = ProofOfSignature {
            name: String::from("Proof-of-Signature"),
            signer: SOME_ADDR.clone(),
            authority_cid: String::from("authorityCID"),
            timestamp: 1710330067,
            metadata: String::from("metadata"),
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
