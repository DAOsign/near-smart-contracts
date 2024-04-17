use daosign_eip712::{
    eip712_domain_type, sha3, EIP712Domain, EIP712Message, EIP712PropertyType, Packable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

static PROOF_OF_AGREEMENT_TYPEHASH: [u8; 32] = [
    185, 27, 12, 51, 75, 214, 207, 181, 70, 113, 59, 190, 184, 233, 248, 119, 28, 64, 225, 24, 110,
    118, 31, 55, 253, 52, 142, 191, 198, 65, 42, 150,
];

fn proof_of_agreement_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("authorityCID"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("signatureCIDs"),
            r#type: String::from("string[]"),
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

/// ProofOfAgreement struct representing the Proof-of-Agreement parameters.
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfAgreement {
    pub authority_cid: String,
    pub signature_cids: Vec<String>,
    pub timestamp: u64,
    pub metadata: String,
}

impl ProofOfAgreement {
    pub fn to_eip712_message(&self, domain: &EIP712Domain) -> EIP712Message<ProofOfAgreement> {
        EIP712Message {
            types: HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("ProofOfAgreement"), proof_of_agreement_type()),
            ]),
            domain: domain.clone(),
            primary_type: String::from("ProofOfAgreement"),
            message: self.clone(),
        }
    }
}

impl Packable for ProofOfAgreement {
    fn pack(&self) -> Vec<u8> {
        let mut signature_cids = Vec::new();
        for string in self.signature_cids.iter() {
            signature_cids.extend(sha3(string.as_bytes()))
        }
        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&PROOF_OF_AGREEMENT_TYPEHASH.clone());
        encoded.extend_from_slice(&sha3(self.authority_cid.as_bytes()));
        encoded.extend_from_slice(&sha3(signature_cids.as_slice()));
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
        assert_eq!(PROOF_OF_AGREEMENT_TYPEHASH, sha3(b"ProofOfAgreement(string authorityCID,string[] signatureCIDs,uint256 timestamp,string metadata)"));
    }

    #[test]
    fn check_type() {
        let message = ProofOfAgreement {
            authority_cid: String::from("authorityCID"),
            signature_cids: vec![String::from("signatureCID0"), String::from("signatureCID1")],
            timestamp: 1710330067,
            metadata: String::from("metadata"),
        };

        let expected_hash: [u8; 32] = <[u8; 32]>::from_hex(
            "70b7103d5b78c366091856f2051002ec537e2e3279f9364e800322aaa231a28b",
        )
        .unwrap();
        assert_eq!(expected_hash, daosign_eip712::hash(&message));

        let signature = <[u8; 65]>::from_hex("f69f89ea63a0289b15089c94a0a1243d8e9815950770652ffc708a0d20419fed1de5406476301fda2e0f073b4a872d7dd63f7b3445f60c1cfe4f8c8c0dabb21c1c").unwrap();
        let recovered = daosign_eip712::recover(&domain(), &message, &signature);
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
