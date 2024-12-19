use daosign_eip712::{
    eip712_domain_type, sha3, EIP712Domain, EIP712Message, EIP712PropertyType, Packable,
};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
// use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use schemars::JsonSchema;

// SCHEMA_TYPE_HASH
// 0x246d7483646a0af29a3543d81d6e3415998d2fc4730181e50b5e54435eec13b3
static SCHEMA_TYPEHASH: [u8; 32] = [
    36, 109, 116, 131, 100, 106, 10, 242, 154, 53, 67, 216, 29, 110, 52, 21, 153, 141, 47, 196,
    115, 1, 129, 229, 11, 94, 84, 67, 94, 236, 19, 179,
];
// METADATA_TYPE_HASH
// 0xf322b28a32f45cd600c6de818556d46b338cebb49fab4256b105e6fc7e0f2a90
static SCHEMA_METADATA_TYPEHASH: [u8; 32] = [
    243, 34, 178, 138, 50, 244, 92, 214, 0, 198, 222, 129, 133, 56, 212, 107, 51, 140, 235, 180,
    159, 171, 66, 86, 177, 5, 230, 252, 126, 15, 42, 144,
];

//SIGNATORY_POLICY_TYPE_HASH
// 0x44b197c8a24fd4923a3bd97f70b80a99bbbc8f6757c07b64538faf1a10bff034
static SIGNATORY_POLICY_TYPEHASH: [u8; 32] = [
    68, 177, 151, 200, 162, 79, 212, 146, 58, 59, 217, 127, 112, 184, 10, 153, 187, 188, 143, 103,
    87, 192, 123, 100, 83, 143, 175, 26, 16, 191, 240, 52,
];

// SCHEMA_DEFINITION_TYPE_HASH
// 0xec2a4530bfd385f89deee17fbbcba392190651792abf5d76b39fdeedfb0be528
static SCHEMA_DEFINITION_TYPEHASH: [u8; 32] = [
    236, 42, 69, 48, 191, 211, 133, 248, 157, 238, 225, 127, 187, 203, 163, 146, 25, 6, 81, 121,
    42, 191, 93, 118, 179, 159, 222, 237, 251, 11, 229, 40,
];

fn schema_type() -> Vec<EIP712PropertyType> {
    vec![
        EIP712PropertyType {
            name: String::from("schema_id"),
            r#type: String::from("uint256"),
        },
        EIP712PropertyType {
            name: String::from("metadata"),
            r#type: String::from("SchemaMetadata"),
        },
        EIP712PropertyType {
            name: String::from("signatory_policy"),
            r#type: String::from("SignatoryPolicy[]"),
        },
        EIP712PropertyType {
            name: String::from("schema_definition"),
            r#type: String::from("SchemaDefinition[]"),
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
pub struct SchemaMetadata {
    name: String,
    description: String,
    attestation_type: String,
    nft_name: String,
    nft_symbol: String,
    creator: String, // Use String to represent address
    created_at: u32,
    is_nft: bool,
    is_public: bool,
    is_revokable: bool,
    expire_in: u32,
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
pub struct SignatoryPolicy {
    operator: u8, // bytes1 in Solidity can be represented as u8
    signatory_description: String,
    required_schema_id: Vec<u128>, // uint256 is a large number, best suited to `u128` or `u256` library
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
pub struct SchemaDefinition {
    definition_type: String,
    definition_name: String,
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
pub struct Schema {
    schema_id: u128, // Assuming large ids
    metadata: SchemaMetadata,
    signatory_policy: Vec<SignatoryPolicy>,
    schema_definition: Vec<SchemaDefinition>,
}

impl Schema {
    pub fn to_eip712_message(&self, domain: &EIP712Domain) -> EIP712Message<Schema> {
        EIP712Message {
            types: HashMap::from([
                (String::from("EIP712Domain"), eip712_domain_type()),
                (String::from("Schema"), schema_type()),
            ]),
            domain: domain.clone(),
            primary_type: String::from("Schema"),
            message: self.clone(),
        }
    }
}

impl Packable for Schema {
    fn pack(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        // 1. Add the type hash at the beginning
        encoded.extend_from_slice(&SCHEMA_TYPEHASH.clone());

        // 2. Encode schema_id
        encoded.extend_from_slice(&self.schema_id.to_be_bytes());

        // 3. Encode metadata fields
        encoded.extend_from_slice(&sha3(&pack_metadata(&self.metadata)).as_slice());

        // 4. Encode signatory policies using the new function
        encoded.extend_from_slice(&sha3(&pack_signatory_policy(&self.signatory_policy)));

        // 5. Encode schema definitions using the new function
        encoded.extend_from_slice(&sha3(&pack_schema_definition(&self.schema_definition)));

        // Return the encoded data
        encoded
    }
}

fn pack_metadata(metadata: &SchemaMetadata) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    // 1. Add the type hash at the beginning
    encoded.extend_from_slice(&SCHEMA_METADATA_TYPEHASH); //change METADATA TYPEHASH

    // 2. Encode metadata fields
    encoded.extend_from_slice(&sha3(metadata.name.as_bytes()));
    encoded.extend_from_slice(&sha3(metadata.description.as_bytes()));
    encoded.extend_from_slice(&sha3(metadata.attestation_type.as_bytes()));
    encoded.extend_from_slice(&sha3(metadata.nft_name.as_bytes()));
    encoded.extend_from_slice(&sha3(metadata.nft_symbol.as_bytes()));
    encoded.extend_from_slice(&hex::decode(&metadata.creator).unwrap()); // Decode hex string to bytes
    encoded.extend_from_slice(&metadata.created_at.to_be_bytes());

    // You may want to also encode other boolean values if needed
    encoded.extend_from_slice(&(metadata.is_nft as u8).to_be_bytes());
    encoded.extend_from_slice(&(metadata.is_public as u8).to_be_bytes());
    encoded.extend_from_slice(&(metadata.is_revokable as u8).to_be_bytes());
    encoded.extend_from_slice(&metadata.expire_in.to_be_bytes());

    encoded
}

fn pack_signatory_policy(signatory_policy: &[SignatoryPolicy]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    // Iterate over signatory policies and pack each one
    for policy in signatory_policy {
        // 1. Add the type hash at the beginning (assign type hash if needed)
        encoded.extend_from_slice(&SIGNATORY_POLICY_TYPEHASH); // Assuming SIGNATORY_POLICY_TYPEHASH is defined

        // 2. Pack operator as a byte
        encoded.extend_from_slice(&(policy.operator as u8).to_be_bytes());

        // 3. Hash the signatory description
        encoded.extend_from_slice(&sha3(policy.signatory_description.as_bytes()));

        // 4. Encode the length of the required schema IDs
        let required_schema_count = policy.required_schema_id.len() as u32;
        encoded.extend_from_slice(&required_schema_count.to_be_bytes());

        // 5. Create a separate buffer for required_schema_ids
        let mut packed_schema_ids: Vec<u8> = Vec::new();

        // 6. Collect byte representation of each schema_id
        for schema_id in &policy.required_schema_id {
            packed_schema_ids.extend_from_slice(&schema_id.to_be_bytes()); // Pack each required_schema_id
        }

        // 7. Hash the packed schema IDs
        let schema_id_hash = sha3(&packed_schema_ids);
        encoded.extend_from_slice(&schema_id_hash); // Extend encoded with the hash of schema IDs
    }

    // Return the encoded data
    encoded
}

fn pack_schema_definition(schema_definition: &[SchemaDefinition]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();

    for definition in schema_definition {
        // 1. Add the type hash at the beginning
        encoded.extend_from_slice(&SCHEMA_DEFINITION_TYPEHASH); //change METADATA TYPEHASH

        // 2. Hash and encode definition_type
        encoded.extend_from_slice(&sha3(definition.definition_type.as_bytes()));

        // 3. Hash and encode definition_name
        encoded.extend_from_slice(&sha3(definition.definition_name.as_bytes()));
    }
    encoded
}

#[cfg(test)]
mod test {
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
        assert_eq!(SCHEMA_TYPEHASH, sha3(b"Schema(uint256 schema_id,SchemaMetadata metadata,SignatoryPolicy[] signatory_policy,SchemaDefinition[] schema_definition)SchemaDefinition(string definition_type,string definition_name)SchemaMetadata(string name,string description,string attestation_type,string nft_name,string nft_symbol,address creator,uint32 created_at,bool is_nft,bool is_public,bool is_revokable,uint32 expire_in)SignatoryPolicy(bytes1 operator,string signatory_description,uint256[] required_schema_id)"))
    }

    #[test]
    fn check_type() {
        let message = Schema {
            schema_id: 0,
            metadata: SchemaMetadata {
                name: String::from("daosign_vacancy"),
                description: String::from("Blockchain developer vacancy"),
                attestation_type: String::from("agreement"),
                nft_name: String::from("vacancy collection"),
                nft_symbol: String::from("vcc"),
                creator: hex::encode(SOME_ADDR),
                created_at: 1,
                is_nft: true,
                is_public: false,
                is_revokable: true,
                expire_in: 0,
            },
            signatory_policy: vec![
                // Assuming we create an array or vector of policies
                SignatoryPolicy {
                    operator: 0x01, // For example, "AND" operation
                    signatory_description: String::from("Main Signatory"),
                    required_schema_id: vec![0], // Placeholder IDs
                },
            ],
            schema_definition: vec![SchemaDefinition {
                definition_type: String::from("string"),
                definition_name: String::from("vacancies"),
            }],
        };
        let expected_hash: [u8; 32] = <[u8; 32]>::from_hex(
            "5685b6f522ba0faa64a751773ca3796b5b525a81fe603c7962e88c803cb0e58b",
        )
        .unwrap();
        assert_eq!(expected_hash, daosign_eip712::hash(&message));

        let signature = <[u8; 65]>::from_hex("54534ed61073d0beba225616c8220f02acd3a819d2cd378533778d4f6d3986057b012e4855ba9e7bfba086afad2c927cd416acd9c30e260433ac9dc9b10e82c01c").unwrap();
        let recovered = daosign_eip712::recover(&domain(), &message, &signature);
        assert_eq!(SOME_ADDR, recovered.unwrap())
    }
}
