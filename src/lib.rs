// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{near_bindgen, /*log, env, AccountId*/};
use near_sdk::serde::{Serialize, Deserialize};
use tiny_keccak::{Hasher, Keccak};
use scale::{/*Decode, */Encode};
// use std::collections::HashMap;

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct DAOsignEIP712 {
    pub domain: EIP712Domain,
    pub domain_hash: [u8; 32],
    pub eip712domain_typehash: [u8; 32],
    pub signer_typehash: [u8; 32],
    pub proof_of_authority_typehash: [u8; 32],
    pub proof_of_signature_typehash: [u8; 32],
    pub proof_of_agreement_typehash: [u8; 32],
    pub proof_of_authority_types: EIP712ProofOfAuthorityTypes,
    pub proof_of_signature_types: EIP712ProofOfSignatureTypes,
    pub proof_of_agreement_types: EIP712ProofOfAgreementTypes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    // As max size in Rust is u128 comparing to u256 in Solidity, chain_id is defined as an
    // array of u8 of size 32 rather than u128. This is done to not loose precision
    pub chain_id: [u8; 32],
    // As we're storing Solidity address here (and in other structs), we will use [u8; 32]
    // instead of AccountId
    pub verifying_contract: [u8; 32],
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
 pub struct Signer {
    pub addr: [u8; 32],
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct ProofOfAuthority {
    pub name: String,
    pub from: [u8; 32],
    pub agreement_cid: String,
    pub signers: Vec<Signer>,
    pub app: String,
    // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
    pub timestamp: [u8; 32],
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfSignature {
    pub name: String,
    pub signer: [u8; 32],
    pub agreement_cid: String,
    pub app: String,
    // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
    pub timestamp: [u8; 32],
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct ProofOfAgreement {
    pub agreement_cid: String,
    pub signature_cids: Vec<String>,
    pub app: String,
    // As Rust doesn't have u256 type as in Solidity, we're using [u8; 32] here
    pub timestamp: [u8; 32],
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EIP712PropertyType {
    name: String,
    kind: String,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EIP712ProofOfAuthorityTypes {
    pub eip712_domain: Vec<EIP712PropertyType>,
    pub signer: Vec<EIP712PropertyType>,
    pub proof_of_authority: Vec<EIP712PropertyType>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EIP712ProofOfSignatureTypes {
    pub eip712_domain: Vec<EIP712PropertyType>,
    pub proof_of_signature: Vec<EIP712PropertyType>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EIP712ProofOfAgreementTypes {
    pub eip712_domain: Vec<EIP712PropertyType>,
    pub proof_of_agreement: Vec<EIP712PropertyType>,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct EIP712ProofOfAuthority {
    types: EIP712ProofOfAuthorityTypes,
    domain: EIP712Domain,
    primary_type: String,
    message: ProofOfAuthority,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct EIP712ProofOfSignature {
    types: EIP712ProofOfSignatureTypes,
    domain: EIP712Domain,
    primary_type: String,
    message: ProofOfSignature,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct EIP712ProofOfAgreement {
    types: EIP712ProofOfAgreementTypes,
    domain: EIP712Domain,
    primary_type: String,
    message: ProofOfAgreement,
}

// Implement the contract structure
#[near_bindgen]
impl DAOsignEIP712 {
    #[init]
    pub fn new(domain: EIP712Domain) -> Self {
        let mut instance = Self {
            domain_hash: [0; 32],
            domain: domain.clone(),
            eip712domain_typehash: [0; 32],
            signer_typehash: [0; 32],
            proof_of_authority_typehash: [0; 32],
            proof_of_signature_typehash: [0; 32],
            proof_of_agreement_typehash: [0; 32],
            proof_of_authority_types: EIP712ProofOfAuthorityTypes::default(),
            proof_of_signature_types: EIP712ProofOfSignatureTypes::default(),
            proof_of_agreement_types: EIP712ProofOfAgreementTypes::default(),
        };
        instance.init_typehashes();
        instance.init_domainhash(domain);
        instance.init_eip712_types();
        instance
    }

    /// # Function to get the hash of an EIP712Domain struct.
    ///
    /// This function takes an EIP712Domain struct and calculates its hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - EIP712Domain struct to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the hash of the EIP712Domain.
    pub fn hash_domain(&self, data: EIP712Domain) -> [u8; 32] {
        let mut encoded_data = Vec::new();

        encoded_data.extend_from_slice(self.eip712domain_typehash.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(data.name.as_str()));
        encoded_data.extend_from_slice(&Self::keccak_hash(data.version.as_str()));
        encoded_data.extend_from_slice(data.chain_id.as_slice());
        encoded_data.extend_from_slice(data.verifying_contract.encode().as_slice());

        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Function to get the hash of a Signer struct.
    ///
    /// This function takes a Signer struct and calculates its hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - Signer struct to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the hash of the Signer.
    pub fn hash_signer(&self, data: Signer) -> [u8; 32] {
        let mut encoded_data = Vec::new();

        encoded_data.extend_from_slice(self.signer_typehash.as_slice());
        encoded_data.extend_from_slice(data.addr.encode().as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata.as_str()));

        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Function to get the hash of an array of Signer structs.
    ///
    /// This function takes an array of Signer structs and calculates their collective hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - Array of Signer structs to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the collective hash of the array of Signers.
    pub fn hash_signers(&self, data: Vec<Signer>) -> [u8; 32] {
        let mut encoded_data = Vec::new();
        for signer in data.iter() {
            encoded_data.extend_from_slice(&self.hash_signer(signer.clone()));
        }
        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Function to get the hash of an array of strings.
    ///
    /// This function takes an array of strings and calculates their collective hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - Array of strings to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the collective hash of the array of strings.
    pub fn hash_strings(&self, data: Vec<String>) -> [u8; 32] {
        let mut encoded_data = Vec::new();
        for string in data.iter() {
            encoded_data.extend_from_slice(&Self::keccak_hash(string));
        }
        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Function to get the hash of a ProofOfAuthority struct.
    ///
    /// This function takes a ProofOfAuthority struct and calculates its hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - ProofOfAuthority struct to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the hash of the ProofOfAuthority.
    pub fn hash_proof_of_authority(&self, data: ProofOfAuthority) -> [u8; 32] {
        let mut encoded_data = Vec::new();

        encoded_data.extend_from_slice(self.proof_of_authority_typehash.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.name));
        encoded_data.extend_from_slice(data.from.encode().as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
        encoded_data.extend_from_slice(&self.hash_signers(data.signers));
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.app));
        encoded_data.extend_from_slice(data.timestamp.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Function to get the hash of a ProofOfSignature struct.
    ///
    /// This function takes a ProofOfSignature struct and calculates its hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - ProofOfSignature struct to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the hash of the ProofOfSignature.
    pub fn hash_proof_of_signature(&self, data: ProofOfSignature) -> [u8; 32] {
        let mut encoded_data = Vec::new();

        encoded_data.extend_from_slice(self.proof_of_signature_typehash.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.name));
        encoded_data.extend_from_slice(data.signer.encode().as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.app));
        encoded_data.extend_from_slice(data.timestamp.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Function to get the hash of a ProofOfAgreement struct.
    ///
    /// This function takes a ProofOfAgreement struct and calculates its hash using the specified encoding rules.
    ///
    /// # Arguments
    ///
    /// * `data` - ProofOfAgreement struct to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the hash of the ProofOfAgreement.
    pub fn hash_proof_of_agreement(&self, data: ProofOfAgreement) -> [u8; 32] {
        let mut encoded_data = Vec::new();

        encoded_data.extend_from_slice(self.proof_of_agreement_typehash.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.agreement_cid));
        encoded_data.extend_from_slice(&self.hash_strings(data.signature_cids));
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.app));
        encoded_data.extend_from_slice(data.timestamp.as_slice());
        encoded_data.extend_from_slice(&Self::keccak_hash(&data.metadata));

        Self::keccak_hash_bytes(&encoded_data)
    }

    /// # Recover function for retrieving the Ethereum address from an EIP-712 signature.
    ///
    /// This function takes an EIP-712 message hash and its corresponding signature,
    /// then performs ECDSA recovery to obtain the uncompressed public key.
    /// The recovered public key is then converted to an Ethereum address,
    /// and the 20-byte address is returned.
    ///
    /// # Arguments
    ///
    /// * `message` - A 32-byte hash representing the EIP-712 message.
    /// * `sig` - A 65-byte signature obtained from signing the EIP-712 message.
    ///
    /// # Returns
    ///
    /// A 20-byte array representing the Ethereum address recovered from the signature.
    pub fn recover(&self, message: [u8; 32], sig: String) -> [u8; 20] {
        // let sig_bytes = hex::decode(sig).expect("Invalid hex in signature");
        // // Recover the public key from the signature
        // let mut uncompressed_public_key = [0; 33];
        // let _ = ink::env::ecdsa_recover(&sig_bytes, &message, &mut uncompressed_public_key);

        // // Convert public key to Ethereum address
        // let mut account_id_bytes = [0; 20];
        // let _ = ink::env::ecdsa_to_eth_address(&uncompressed_public_key, &mut account_id_bytes);

        // account_id_bytes
        [0; 20]
    }

    /// # Recover function for Proof of Authority, retrieving the Ethereum address from a signature.
    ///
    /// This function takes a ProofOfAuthority struct, computes its hash, and uses it to create a
    /// compound message for ECDSA recovery. The signature and message are then passed to the recover
    /// function to obtain the Ethereum address.
    ///
    /// # Arguments
    ///
    /// * `data` - ProofOfAuthority struct containing information about the authority proof.
    /// * `signature` - A 65-byte signature obtained from signing the ProofOfAuthority message.
    ///
    /// # Returns
    ///
    /// A 20-byte array representing the Ethereum address recovered from the ProofOfAuthority signature.
    pub fn recover_proof_of_authority(
        &self,
        data: ProofOfAuthority,
        signature: String,
    ) -> [u8; 20] {
        let packet_hash = self.hash_proof_of_authority(data);

        // Encode the packet hash with the domain hash
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"\x19\x01");
        encoded.extend_from_slice(&self.domain_hash);
        encoded.extend_from_slice(&packet_hash);

        let digest = Self::keccak_hash_bytes(&encoded);

        self.recover(digest, signature)
    }

    /// # Recover function for Proof of Signature, retrieving the Ethereum address from a signature.
    ///
    /// Similar to recover_proof_of_authority, this function takes a ProofOfSignature struct,
    /// computes its hash, and uses it to create a compound message for ECDSA recovery. The signature
    /// and message are then passed to the recover function to obtain the Ethereum address.
    ///
    /// # Arguments
    ///
    /// * `data` - ProofOfSignature struct containing information about the signature proof.
    /// * `signature` - A 65-byte signature obtained from signing the ProofOfSignature message.
    ///
    /// # Returns
    ///
    /// A 20-byte array representing the Ethereum address recovered from the ProofOfSignature signature.
    pub fn recover_proof_of_signature(
        &self,
        data: ProofOfSignature,
        signature: String,
    ) -> [u8; 20] {
        let packet_hash = self.hash_proof_of_signature(data);

        // Encode the packet hash with the domain hash
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"\x19\x01");
        encoded.extend_from_slice(&self.domain_hash);
        encoded.extend_from_slice(&packet_hash);

        let digest = Self::keccak_hash_bytes(&encoded);

        self.recover(digest, signature)
    }

    /// # Recover function for Proof of Agreement, retrieving the Ethereum address from a signature.
    ///
    /// Similar to the previous recover functions, this one takes a ProofOfAgreement struct, computes
    /// its hash, and uses it to create a compound message for ECDSA recovery. The signature and message
    /// are then passed to the recover function to obtain the Ethereum address.
    ///
    /// # Arguments
    ///
    /// * `data` - ProofOfAgreement struct containing information about the agreement proof.
    /// * `signature` - A 65-byte signature obtained from signing the ProofOfAgreement message.
    ///
    /// # Returns
    ///
    /// A 20-byte array representing the Ethereum address recovered from the ProofOfAgreement signature.
    pub fn recover_proof_of_agreement(
        &self,
        data: ProofOfAgreement,
        signature: String,
    ) -> [u8; 20] {
        let packet_hash = self.hash_proof_of_agreement(data);

        // Encode the packet hash with the domain hash
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"\x19\x01");
        encoded.extend_from_slice(&self.domain_hash);
        encoded.extend_from_slice(&packet_hash);

        let digest = Self::keccak_hash_bytes(&encoded);

        self.recover(digest, signature)
    }

    /// # Convert ProofOfAuthority struct to EIP-712 formatted message.
    ///
    /// This function takes a ProofOfAuthority struct and creates an EIP-712 formatted message.
    ///
    /// # Arguments
    ///
    /// * `message` - ProofOfAuthority struct to be converted to the EIP-712 message format.
    ///
    /// # Returns
    ///
    /// An EIP712ProofOfAuthority struct representing the EIP-712 formatted message for ProofOfAuthority.
    pub fn to_eip712_message_proof_of_authority(
        &self,
        message: ProofOfAuthority,
    ) -> EIP712ProofOfAuthority {
        EIP712ProofOfAuthority {
            types: self.proof_of_authority_types.clone(),
            domain: self.domain.clone(),
            primary_type: "ProofOfAuthority".to_string(),
            message,
        }
    }

    /// # Convert ProofOfSignature struct to EIP-712 formatted message.
    ///
    /// Similar to the previous function, this one takes a ProofOfSignature struct and creates
    /// an EIP-712 formatted message.
    ///
    /// # Arguments
    ///
    /// * `message` - ProofOfSignature struct to be converted to the EIP-712 message format.
    ///
    /// # Returns
    ///
    /// An EIP712ProofOfSignature struct representing the EIP-712 formatted message for ProofOfSignature.
    pub fn to_eip712_message_proof_of_signature(
        &self,
        message: ProofOfSignature,
    ) -> EIP712ProofOfSignature {
        EIP712ProofOfSignature {
            types: self.proof_of_signature_types.clone(),
            domain: self.domain.clone(),
            primary_type: "ProofOfSignature".to_string(),
            message,
        }
    }

    /// # Convert ProofOfAgreement struct to EIP-712 formatted message.
    ///
    /// Similar to the previous functions, this one takes a ProofOfAgreement struct and creates
    /// an EIP-712 formatted message.
    ///
    /// # Arguments
    ///
    /// * `message` - ProofOfAgreement struct to be converted to the EIP-712 message format.
    ///
    /// # Returns
    ///
    /// An EIP712ProofOfAgreement struct representing the EIP-712 formatted message for ProofOfAgreement.
    pub fn to_eip712_message_proof_of_agreement(
        &self,
        message: ProofOfAgreement,
    ) -> EIP712ProofOfAgreement {
        EIP712ProofOfAgreement {
            types: self.proof_of_agreement_types.clone(),
            domain: self.domain.clone(),
            primary_type: "ProofOfAgreement".to_string(),
            message,
        }
    }

    /// # Helper function to initialize `domain_hash` variable with DAOsign proofs `domain`.
    ///
    /// This function takes the provided EIP712 domain and calculates its hash, which is then stored in the `domain_hash` variable.
    ///
    /// # Arguments
    ///
    /// * `domain` - EIP712Domain struct representing the domain of the contract.
    fn init_domainhash(&mut self, domain: EIP712Domain) -> () {
        self.domain_hash = self.hash_domain(domain);
    }

    /// # Helper function to initialize hashes of all EIP-712-styled structs. This will be needed
    /// # later on to hash proofs.
    ///
    /// This function initializes the type hashes for EIP712Domain, Signer, Proof-of-Authority, Proof-of-Signature, and Proof-of-Agreement.
    fn init_typehashes(&mut self) -> () {
        self.eip712domain_typehash = Self::keccak_hash("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        self.signer_typehash = Self::keccak_hash("Signer(address addr,string metadata)");
        self.proof_of_authority_typehash = Self::keccak_hash("ProofOfAuthority(string name,address from,string agreementCID,Signer[] signers,string app,uint256 timestamp,string metadata)Signer(address addr,string metadata)");
        self.proof_of_signature_typehash = Self::keccak_hash("ProofOfSignature(string name,address signer,string agreementCID,string app,uint256 timestamp,string metadata)");
        self.proof_of_agreement_typehash = Self::keccak_hash("ProofOfAgreement(string agreementCID,string[] signatureCIDs,string app,uint256 timestamp,string metadata)");
    }

    /// # Helper function to initialize EIP-712, Signer, Proof-of-Authority, Proof-of-Signature, and
    /// # Proof-of-Agreement domain types.
    ///
    /// This function sets up the EIP712 types needed for hashing proofs and stores them in the contract's storage.
    fn init_eip712_types(&mut self) -> () {
        // Initialize EIP712Domain types
        let domain_types = Vec::from([
            EIP712PropertyType {
                name: "name".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "version".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "chainId".to_string(),
                kind: "uint256".to_string(),
            },
            EIP712PropertyType {
                name: "verifyingContract".to_string(),
                kind: "address".to_string(),
            },
        ]);

        // Initialize Signer types
        let signer_types = Vec::from([
            EIP712PropertyType {
                name: "addr".to_string(),
                kind: "address".to_string(),
            },
            EIP712PropertyType {
                name: "metadata".to_string(),
                kind: "string".to_string(),
            },
        ]);

        // Initialize ProofOfAuthority types
        let proof_of_authority_types = Vec::from([
            EIP712PropertyType {
                name: "name".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "from".to_string(),
                kind: "address".to_string(),
            },
            EIP712PropertyType {
                name: "agreementCID".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "signers".to_string(),
                kind: "Signer[]".to_string(),
            },
            EIP712PropertyType {
                name: "app".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "timestamp".to_string(),
                kind: "uint256".to_string(),
            },
            EIP712PropertyType {
                name: "metadata".to_string(),
                kind: "string".to_string(),
            },
        ]);

        // Initialize ProofOfSignature types
        let proof_of_signature_types = Vec::from([
            EIP712PropertyType {
                name: "name".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "signer".to_string(),
                kind: "address".to_string(),
            },
            EIP712PropertyType {
                name: "agreementCID".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "app".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "timestamp".to_string(),
                kind: "uint256".to_string(),
            },
            EIP712PropertyType {
                name: "metadata".to_string(),
                kind: "string".to_string(),
            },
        ]);

        // Initialize ProofOfAgreement types
        let proof_of_agreement_types = Vec::from([
            EIP712PropertyType {
                name: "agreementCID".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "signatureCIDs".to_string(),
                kind: "string[]".to_string(),
            },
            EIP712PropertyType {
                name: "app".to_string(),
                kind: "string".to_string(),
            },
            EIP712PropertyType {
                name: "timestamp".to_string(),
                kind: "uint256".to_string(),
            },
            EIP712PropertyType {
                name: "metadata".to_string(),
                kind: "string".to_string(),
            },
        ]);

        // Set the types in the contract's storage
        self.proof_of_authority_types.eip712_domain = domain_types.clone();
        self.proof_of_authority_types.signer = signer_types.clone();
        self.proof_of_authority_types.proof_of_authority = proof_of_authority_types.clone();

        self.proof_of_signature_types.eip712_domain = domain_types.clone();
        self.proof_of_signature_types.proof_of_signature = proof_of_signature_types.clone();

        self.proof_of_agreement_types.eip712_domain = domain_types;
        self.proof_of_agreement_types.proof_of_agreement = proof_of_agreement_types;
    }

    /// # Helper function to get Keccak-256 hash of any given string.
    ///
    /// This function takes a string input and calculates its Keccak-256 hash.
    ///
    /// # Arguments
    ///
    /// * `input` - String to be hashed.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the Keccak-256 hash of the input string.
    fn keccak_hash(input: &str) -> [u8; 32] {
        let mut keccak = Keccak::v256();
        let mut output = [0u8; 32];
        keccak.update(input.as_bytes());
        keccak.finalize(&mut output);
        output
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
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    // use hex::decode;
    // use hex::FromHexError;
    // use near_sdk::{test_utils::{accounts, VMContextBuilder}, testing_env, VMContext};

    // // Helper function to set up the blockchain context for tests
    // fn get_context(is_view: bool) -> VMContext {
    //     VMContextBuilder::new()
    //         .signer_account_id(accounts(0)) // accounts(0) is a default test account
    //         .is_view(is_view)
    //         .build()
    // }

    #[test]
    fn constructor() {
        // let context = get_context(false);
        // testing_env!(context);

        let domain = EIP712Domain {
            name: "daosign".into(),
            version: "0.1.0".into(),
            chain_id: [0; 32],
            verifying_contract: [0; 32].into(),
        };

        let instance = DAOsignEIP712::new(domain.clone());

        // Test domain hash
        assert_eq!(
            instance.domain_hash,
            <[u8; 32]>::from_hex(
                "98670852334fc8f702b23d30e8b0adf9084b364869f775b23e9b89e3c50390c0",
            )
            .unwrap()
        );

        // Test typehashes
        assert_eq!(
            instance.eip712domain_typehash,
            <[u8; 32]>::from_hex(
                "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f",
            )
            .unwrap()
        );
        assert_eq!(
            instance.signer_typehash,
            <[u8; 32]>::from_hex(
                "67aa40d26f889f44ec5fecd21b812b43af0974bbc5e74283b01e36ceb272966f",
            )
            .unwrap()
        );
        assert_eq!(
            instance.proof_of_authority_typehash,
            <[u8; 32]>::from_hex(
                "8f114d1a21f1f0a7cbd7762e89178eff7aebe129bd6e17c5ba78039f051a7fd4",
            )
            .unwrap()
        );
        assert_eq!(
            instance.proof_of_signature_typehash,
            <[u8; 32]>::from_hex(
                "6fef47b94b61b28c42811a67d3c72900a80a641dc7de99d8a9943e5bf6f6a274",
            )
            .unwrap()
        );
        assert_eq!(
            instance.proof_of_agreement_typehash,
            <[u8; 32]>::from_hex(
                "2d150e81098c40977881d8ba98e4cecf43b28d790b59c176028dd6f16f9ee628",
            )
            .unwrap()
        );

        // Test Proof-of-Authority
        assert_eq!(
            instance.proof_of_authority_types.eip712_domain.len() > 0,
            true
        );
        assert_eq!(instance.proof_of_authority_types.signer.len() > 0, true);
        assert_eq!(
            instance.proof_of_authority_types.proof_of_authority.len() > 0,
            true
        );

        // Test Proof-of-Signature
        assert_eq!(
            instance.proof_of_signature_types.eip712_domain.len() > 0,
            true
        );
        assert_eq!(
            instance.proof_of_signature_types.proof_of_signature.len() > 0,
            true
        );

        // Test Proof-of-Agreement
        assert_eq!(
            instance.proof_of_agreement_types.eip712_domain.len() > 0,
            true
        );
        assert_eq!(
            instance.proof_of_agreement_types.proof_of_agreement.len() > 0,
            true
        );
    }

    #[test]
    fn hash_proof_of_authority() {
        let instance = DAOsignEIP712::new(EIP712Domain {
            name: "daosign".into(),
            version: "0.1.0".into(),
            chain_id: [0; 32],
            verifying_contract: [0; 32].into(),
        });

        //
        // Fisrt Proof-of-Authority
        //

        // prepare timestamp
        let timestamp1: u64 = 1701975136;
        let timestamp1_bytes = timestamp1.to_be_bytes();
        let mut timestamp1_arr: [u8; 32] = [0; 32];
        timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

        // prepare signers
        let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let mut signer1_arr: [u8; 32] = [0; 32];
        signer1_arr[12..].copy_from_slice(&signer1);

        let data1 = ProofOfAuthority {
            name: String::from("Proof-of-Authority"),
            from: signer1_arr,
            agreement_cid: String::from("agreement file cid                            "),
            signers: Vec::from([Signer {
                addr: signer1_arr,
                metadata: String::from("{}"),
            }]),
            app: String::from("daosign"),
            timestamp: timestamp1_arr,
            metadata: String::from("proof metadata"),
        };

        let expected_hash1 = <[u8; 32]>::from_hex(
            "982eeb361acc7f0d6402a812683b34e53f1e59f239fb32156e8b0bd2f9dfd039",
        )
        .unwrap();
        assert_eq!(instance.hash_proof_of_authority(data1), expected_hash1);

        //
        // Second Proof-of-Authority
        //
        // prepare timestamp
        let timestamp2: u64 = 1701975136;
        let timestamp2_bytes = timestamp2.to_be_bytes();
        let mut timestamp2_arr: [u8; 32] = [0; 32];
        timestamp2_arr[24..].copy_from_slice(&timestamp2_bytes);

        // prepare signers
        let signer2 = <[u8; 20]>::from_hex("70997970C51812dc3A010C7d01b50e0d17dc79C8").unwrap();
        let mut signer2_arr: [u8; 32] = [0; 32];
        signer2_arr[12..].copy_from_slice(&signer2);

        let data2 = ProofOfAuthority {
            name: String::from("Proof-of-Authority"),
            from: signer1_arr,
            agreement_cid: String::from("QmbuRibrtidhy9rJuFUjafKG7dDhwDEctc2oWr3NGVxKrd"),
            signers: Vec::from([
                Signer {
                    addr: signer1_arr,
                    metadata: String::from("custom metadata #1"),
                },
                Signer {
                    addr: signer2_arr,
                    metadata: String::from("metadata #2"),
                },
            ]),
            app: String::from("daosign"),
            timestamp: timestamp2_arr,
            metadata: String::from("proof metadata"),
        };

        let expected_hash2 = <[u8; 32]>::from_hex(
            "7764e27376e6d1a8e28583b6bda4bdabce356f493348688fe3ec5d0344700935",
        )
        .unwrap();
        assert_eq!(instance.hash_proof_of_authority(data2), expected_hash2);
    }

    #[test]
    fn hash_proof_of_signature() {
        let instance = DAOsignEIP712::new(EIP712Domain {
            name: "daosign".into(),
            version: "0.1.0".into(),
            chain_id: [0; 32],
            verifying_contract: [0; 32].into(),
        });

        // prepare timestamp
        let timestamp1: u64 = 1701984120;
        let timestamp1_bytes = timestamp1.to_be_bytes();
        let mut timestamp1_arr: [u8; 32] = [0; 32];
        timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

        // prepare signers
        let signer1 = <[u8; 20]>::from_hex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let mut signer1_arr: [u8; 32] = [0; 32];
        signer1_arr[12..].copy_from_slice(&signer1);

        let data1 = ProofOfSignature {
            name: String::from("Proof-of-Signature"),
            signer: signer1_arr,
            agreement_cid: String::from("ProofOfAuthority proof cid                    "),
            app: String::from("daosign"),
            timestamp: timestamp1_arr,
            metadata: String::from("proof metadata"),
        };

        let expected_hash1 = <[u8; 32]>::from_hex(
            "73c2ba7034333fee702ce484bdc6c9d0229bc46f5593b557869e497e5045352c",
        )
        .unwrap();
        assert_eq!(instance.hash_proof_of_signature(data1), expected_hash1);
    }

    #[test]
    fn hash_proof_of_agreement() {
        let instance = DAOsignEIP712::new(EIP712Domain {
            name: "daosign".into(),
            version: "0.1.0".into(),
            chain_id: [0; 32],
            verifying_contract: [0; 32].into(),
        });

        //
        // Simple Proof-of-Agreement
        //

        // prepare timestamp
        let timestamp1: u64 = 1701984586;
        let timestamp1_bytes = timestamp1.to_be_bytes();
        let mut timestamp1_arr: [u8; 32] = [0; 32];
        timestamp1_arr[24..].copy_from_slice(&timestamp1_bytes);

        let data1 = ProofOfAgreement {
            agreement_cid: String::from("agreementCID                                  "),
            signature_cids: Vec::from([
                String::from("signatureCID0                                 "),
                String::from("signatureCID1                                 "),
            ]),
            app: String::from("daosign"),
            timestamp: timestamp1_arr,
            metadata: String::from("metadata"),
        };

        let expected_hash1: [u8; 32] = <[u8; 32]>::from_hex(
            "b5f4a49baad54521096e836a8dceefccf8e3d69ae39e0d5ea3860e31d98b6372",
        )
        .unwrap();
        assert_eq!(instance.hash_proof_of_agreement(data1), expected_hash1);

        //
        // Looong metadata test + the same CIDs
        //

        // prepare timestamp
        let timestamp2: u64 = 1701984586;
        let timestamp2_bytes = timestamp2.to_be_bytes();
        let mut timestamp2_arr: [u8; 32] = [0; 32];
        timestamp2_arr[24..].copy_from_slice(&timestamp2_bytes);

        let data2 = ProofOfAgreement {
            agreement_cid: String::from("signatureCID0                                 "),
            signature_cids: Vec::from([
                String::from("signatureCID0                                 "),
                String::from("signatureCID0                                 "),
            ]),
            app: String::from("daosign"),
            timestamp: timestamp2_arr,
            metadata: String::from("[{'constant':true,'inputs':[],'name':'name','outputs':[{'name':'','type':'string'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':false,'inputs':[{'name':'_spender','type':'address'},{'name':'_value','type':'uint256'}],'name':'approve','outputs':[{'name':'','type':'bool'}],'payable':false,'stateMutability':'nonpayable','type':'function'},{'constant':true,'inputs':[],'name':'totalSupply','outputs':[{'name':'','type':'uint256'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':false,'inputs':[{'name':'_from','type':'address'},{'name':'_to','type':'address'},{'name':'_value','type':'uint256'}],'name':'transferFrom','outputs':[{'name':'','type':'bool'}],'payable':false,'stateMutability':'nonpayable','type':'function'},{'constant':true,'inputs':[],'name':'decimals','outputs':[{'name':'','type':'uint8'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':true,'inputs':[{'name':'_owner','type':'address'}],'name':'balanceOf','outputs':[{'name':'balance','type':'uint256'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':true,'inputs':[],'name':'symbol','outputs':[{'name':'','type':'string'}],'payable':false,'stateMutability':'view','type':'function'},{'constant':false,'inputs':[{'name':'_to','type':'address'},{'name':'_value','type':'uint256'}],'name':'transfer','outputs':[{'name':'','type':'bool'}],'payable':false,'stateMutability':'nonpayable','type':'function'},{'constant':true,'inputs':[{'name':'_owner','type':'address'},{'name':'_spender','type':'address'}],'name':'allowance','outputs':[{'name':'','type':'uint256'}],'payable':false,'stateMutability':'view','type':'function'},{'payable':true,'stateMutability':'payable','type':'fallback'},{'anonymous':false,'inputs':[{'indexed':true,'name':'owner','type':'address'},{'indexed':true,'name':'spender','type':'address'},{'indexed':false,'name':'value','type':'uint256'}],'name':'Approval','type':'event'},{'anonymous':false,'inputs':[{'indexed':true,'name':'from','type':'address'},{'indexed':true,'name':'to','type':'address'},{'indexed':false,'name':'value','type':'uint256'}],'name':'Transfer','type':'event'}]"),
        };

        let expected_hash2: [u8; 32] = <[u8; 32]>::from_hex(
            "7732dfecbf18bf462c5c246643b734fa0d31f785f55de7c970e64bf0092f0a46",
        )
        .unwrap();
        assert_eq!(instance.hash_proof_of_agreement(data2), expected_hash2);
    }

    // #[test]
    // fn get_default_greeting() {
    //     let contract = Contract::default();
    //     // this test did not call set_greeting so should return the default "Hello" greeting
    //     assert_eq!(contract.get_greeting(), "Hello");
    // }

    // #[test]
    // fn set_then_get_greeting() {
    //     let mut contract = Contract::default();
    //     contract.set_greeting("howdy".to_string());
    //     assert_eq!(contract.get_greeting(), "howdy");
    // }
}
