use daosign_eip712::{
    eip712_domain_type, hash, sha3, EIP712Domain, EIP712Message, EIP712PropertyType, Packable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

static SIGNER_TYPEHASH: [u8; 32] = [
    103, 170, 64, 210, 111, 136, 159, 68, 236, 95, 236, 210, 27, 129, 43, 67, 175, 9, 116, 187,
    197, 231, 66, 131, 176, 30, 54, 206, 178, 114, 150, 111,
];
static PROOF_OF_AUTHORITY_TYPEHASH: [u8; 32] = [
    157, 240, 238, 100, 52, 126, 69, 120, 179, 231, 89, 1, 129, 99, 110, 234, 211, 144, 165, 157,
    35, 179, 74, 111, 235, 144, 166, 180, 175, 24, 244, 124,
];

pub fn signer_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("addr"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("string"),
        },
    ]
}

/// Signer struct representing an address and associated metadata.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub addr: [u8; 20],
    pub metadata: String,
}

impl Packable for Signer {
    fn pack(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&SIGNER_TYPEHASH.clone());
        encoded.extend_from_slice(<[u8; 12]>::default().as_slice());
        encoded.extend_from_slice(&self.addr.clone());
        encoded.extend_from_slice(&sha3(self.metadata.as_bytes()));
        encoded
    }
}

pub fn proof_of_authority_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("from"),
            r#type: String::from("address"),
        },
        EIP712PropertyType {
            name: String::from("agreementCID"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("signers"),
            r#type: String::from("Signer[]"),
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

/// ProofOfAuthority struct representing the Proof-of-Authority parameters.
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfAuthority {
    pub name: String,
    pub from: [u8; 20],
    pub agreement_cid: String,
    pub signers: Vec<Signer>,
    pub timestamp: u64,
    pub metadata: String,
}

impl ProofOfAuthority {
    pub fn to_eip712_message(&self, domain: &EIP712Domain) -> EIP712Message<ProofOfAuthority> {
        EIP712Message {
            types: HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("Signer"), signer_type()),
                (String::from("ProofOfAuthority"), proof_of_authority_type()),
            ]),
            domain: domain.clone(),
            primary_type: String::from("ProofOfAuthority"),
            message: self.clone(),
        }
    }
}

impl Packable for ProofOfAuthority {
    fn pack(&self) -> Vec<u8> {
        let mut signers = Vec::new();
        for signer in self.signers.clone() {
            signers.extend_from_slice(&hash(&signer));
        }
        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&PROOF_OF_AUTHORITY_TYPEHASH.clone());
        encoded.extend_from_slice(&sha3(self.name.as_bytes()));
        encoded.extend_from_slice(<[u8; 12]>::default().as_slice());
        encoded.extend_from_slice(&self.from.clone());
        encoded.extend_from_slice(&sha3(self.agreement_cid.as_bytes()));
        encoded.extend_from_slice(&sha3(&signers));
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
        assert_eq!(
            SIGNER_TYPEHASH,
            sha3(b"Signer(address addr,string metadata)")
        );
        assert_eq!(PROOF_OF_AUTHORITY_TYPEHASH, sha3(b"ProofOfAuthority(string name,address from,string agreementCID,Signer[] signers,uint256 timestamp,string metadata)Signer(address addr,string metadata)"));
    }

    #[test]
    fn check_type() {
        let message = ProofOfAuthority {
            name: String::from("Proof-of-Authority"),
            from: SOME_ADDR.clone(),
            agreement_cid: String::from("agreementCID"),
            signers: vec![Signer {
                addr: SOME_ADDR.clone(),
                metadata: String::from("metadata"),
            }],
            timestamp: 1710330067,
            metadata: String::from("metadata"),
        };

        let expected_hash = <[u8; 32]>::from_hex(
            "63af3c65b875f09665a05dc751138b663dd63cf631a07143e19ba54ff8987358",
        )
        .unwrap();
        assert_eq!(expected_hash, hash(&message));

        let signature = <[u8; 65]>::from_hex("b2e9a6c6ab877ce682c03d584fa8cae1e88d9ab290febee705b211d5033c885b3d83bce8ab90917c540c9f5367592fbeabc8125e7a75866cab4b99e1c030a6a31b").unwrap();
        let recovered = daosign_eip712::recover(&domain(), &message, &signature);
        println!("recovered: {:?}", recovered);
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
