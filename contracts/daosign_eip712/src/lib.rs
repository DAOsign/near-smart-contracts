// use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use secp256k1::{Secp256k1, ecdsa::{RecoverableSignature, RecoveryId}, Message};

use near_sdk::{borsh::{BorshDeserialize, BorshSerialize},log};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, io::Error};
use tiny_keccak::{Hasher, Keccak};

static EIP712DOMAIN_TYPEHASH: [u8; 32] = [
    139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159, 123, 23,
    155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15,
];

pub trait Packable {
    fn pack(&self) -> Vec<u8>;
}

/// EIP712PropertyType struct representing the structure of EIP-712 properties.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EIP712PropertyType {
    pub name: String,
    pub r#type: String,
}

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
pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

impl Packable for EIP712Domain {
    fn pack(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.extend_from_slice(&EIP712DOMAIN_TYPEHASH.clone());
        encoded.extend_from_slice(&sha3(self.name.as_bytes()));
        encoded.extend_from_slice(&sha3(self.version.as_bytes()));
        encoded.extend_from_slice(<[u8; 24]>::default().as_slice());
        encoded.extend_from_slice(&self.chain_id.to_be_bytes());
        encoded.extend_from_slice(<[u8; 12]>::default().as_slice());
        encoded.extend_from_slice(&self.verifying_contract.clone());
        encoded
    }
}

pub fn sha3(input: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(input);
    keccak.finalize(&mut output);
    output
}

pub fn hash(message: &dyn Packable) -> [u8; 32] {
    sha3(&message.pack())
}

pub fn recover(
    domain: &EIP712Domain,
    message: &dyn Packable,
    signature_bytes: &[u8; 65],
) -> Result<[u8; 20], Error> {
    let context = Secp256k1::new();

    // Extract the signature and the recovery ID
    let recovery_id = RecoveryId::from_i32((signature_bytes[64] - 27) as i32);
    let recoverable_sig = RecoverableSignature::from_compact(
        &signature_bytes[0..64],
        recovery_id.unwrap()
    ).unwrap();

    // Create a message hash (this is just a placeholder, use the correct hash function!)
    let mut msg = Vec::new();
    msg.extend_from_slice(b"\x19\x01");
    msg.extend_from_slice(&hash(domain));
    msg.extend_from_slice(&hash(message));

    let mut hasher = Keccak256::new();
    hasher.update(&msg);
    let message_hash = hasher.finalize();
    
    let secp_message = Message::from_slice(&message_hash).unwrap();

    // Recover the public key
    let public_key = context.recover_ecdsa(&secp_message, &recoverable_sig).unwrap();
    log!("public_key: {:?}", public_key);

    // Serialize the public key and compute the Ethereum-style address
    let serialized_pubkey = public_key.serialize_uncompressed(); // or serialize_compressed()
    log!("serialized_pubkey: {:?}", serialized_pubkey);
    
    let eth_address = keccak_hash_bytes(&serialized_pubkey[1..]); // skip the prefix byte

    // Return the last 20 bytes as the address
    Ok(eth_address[12..32].try_into().unwrap())
}

/// # Helper function to get Keccak-256 hash of any given array of bytes.
///
/// This function takes an array of bytes as input and calculates its Keccak-256 hash.
///
/// # Arguments
///
/// * `input` - Array of bytes to be hashed.
///
/// # Returns
///
/// A 32-byte array representing the Keccak-256 hash of the input array of bytes.
fn keccak_hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(input);
    keccak.finalize(&mut output);
    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EIP712Message<T: Packable> {
    pub types: HashMap<String, Vec<EIP712PropertyType>>,
    pub domain: EIP712Domain,
    pub primary_type: String,
    pub message: T,
}

pub fn eip712_domain_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("name"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("version"),
            r#type: String::from("string"),
        },
        EIP712PropertyType {
            name: String::from("chainId"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("verifyingContract"),
            r#type: String::from("address"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

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
        assert_eq!(EIP712DOMAIN_TYPEHASH, sha3(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
    }

    #[test]
    fn check_hash() {
        let struct_hash = hash(&domain());
        let expected: [u8; 32] = <[u8; 32]>::from_hex(
            "539b8d1a49d3e1df5cd1ec2de6d228ec3761b476af73124fc376d18b195b1f27",
        )
        .expect("bad hash value");
        assert_eq!(expected, struct_hash);
    }

    #[test]
    fn check_recover() {
        let message = domain();
        const SOME_ADDR: [u8; 20] = [
            173, 197, 148, 191, 124, 136, 93, 22, 39, 80, 161, 16, 56, 34, 234, 242, 15, 46, 8, 25,
        ];
        let expected_hash = [
            83, 155, 141, 26, 73, 211, 225, 223, 92, 209, 236, 45, 230, 210, 40, 236, 55, 97, 180,
            118, 175, 115, 18, 79, 195, 118, 209, 139, 25, 91, 31, 39,
        ];
        assert_eq!(expected_hash, hash(&message));

        let signature = <[u8; 65]>::from_hex("b2e9a6c6ab877ce682c03d584fa8cae1e88d9ab290febee705b211d5033c885b3d83bce8ab90917c540c9f5367592fbeabc8125e7a75866cab4b99e1c030a6a31b").unwrap();
        let recovered = recover(&domain(), &message, &signature);
        println!("recovered: {:?}", recovered);

        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
