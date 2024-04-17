use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{near_bindgen};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sp_io::crypto::secp256k1_ecdsa_recover_compressed;
use std::collections::HashMap;
use std::io::Error;
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

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
    signature: &[u8; 65],
) -> Result<[u8; 20], Error> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"\x19\x01");
    msg.extend_from_slice(&hash(domain));
    msg.extend_from_slice(&hash(message));

    let output: [u8; 20];

    if let Ok(compressed_public_key) = secp256k1_ecdsa_recover_compressed(&signature, &sha3(&msg)) {
        // Recover the public key from the signature
        let pk = PublicKey::from_slice(compressed_public_key.as_ref()).unwrap();
        let uncompressed = pk.serialize_uncompressed();

        // Convert public key to Ethereum address
        let hash = keccak_hash_bytes(&uncompressed[1..]);
        output = (&hash[12..]).try_into().unwrap();
    } else {
        panic!("Recovery failed!");
    }

    Ok(output)
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
}
