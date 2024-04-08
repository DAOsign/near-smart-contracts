// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{log, near_bindgen, env, AccountId};
use near_sdk::serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct DAOsignEIP712 {
    pub domain: EIP712Domain,
    pub domain_hash: Vec<u8>,
    pub eip712domain_typehash: Vec<u8>,
    pub signer_typehash: Vec<u8>,
    pub proof_of_authority_typehash: Vec<u8>,
    pub proof_of_signature_typehash: Vec<u8>,
    pub proof_of_agreement_typehash: Vec<u8>,
    pub proof_of_authority_types: EIP712ProofOfAuthorityTypes,
    pub proof_of_signature_types: EIP712ProofOfSignatureTypes,
    pub proof_of_agreement_types: EIP712ProofOfAgreementTypes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: Vec<u8>, // NEAR doesn't have a direct equivalent to Ethereum's chain ID concept; adjust as needed
    pub verifying_contract: Vec<u8>, // Use AccountId in a production scenario
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub addr: Vec<u8>, // Consider using AccountId for NEAR addresses
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfAuthority {
    pub name: String,
    pub from: Vec<u8>, // Consider changing to AccountId for actual account IDs
    pub agreement_cid: String,
    pub signers: Vec<Signer>,
    pub app: String,
    pub timestamp: Vec<u8>, // Adjust according to the desired precision and storage consideration
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfSignature {
    pub name: String,
    pub signer: Vec<u8>, // Adjust for NEAR's AccountId
    pub agreement_cid: String,
    pub app: String,
    pub timestamp: Vec<u8>, // As above
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofOfAgreement {
    pub agreement_cid: String,
    pub signature_cids: Vec<String>,
    pub app: String,
    pub timestamp: Vec<u8>, // Adjust as necessary
    pub metadata: String,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EIP712PropertyType {
    pub name: String,
    pub kind: String,
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
    pub types: EIP712ProofOfAuthorityTypes,
    pub domain: EIP712Domain,
    pub primary_type: String,
    pub message: ProofOfAuthority,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct EIP712ProofOfSignature {
    pub types: EIP712ProofOfSignatureTypes,
    pub domain: EIP712Domain,
    pub primary_type: String,
    pub message: ProofOfSignature,
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct EIP712ProofOfAgreement {
    pub types: EIP712ProofOfAgreementTypes,
    pub domain: EIP712Domain,
    pub primary_type: String,
    pub message: ProofOfAgreement,
}


// Define the default, which automatically initializes the contract
// impl Default for Contract {
//     fn default() -> Self {
//         Self {
//             greeting: "Hello".to_string(),
//         }
//     }
// }

// Implement the contract structure
#[near_bindgen]
impl DAOsignEIP712 {
    #[init]
    pub fn new(domain: EIP712Domain) -> Self {
        let mut instance = Self {
            domain_hash: vec![],
            domain: domain,
            eip712domain_typehash: vec![],
            signer_typehash: vec![],
            proof_of_authority_typehash: vec![],
            proof_of_signature_typehash: vec![],
            proof_of_agreement_typehash: vec![],
            proof_of_authority_types: EIP712ProofOfAuthorityTypes::default(),
            proof_of_signature_types: EIP712ProofOfSignatureTypes::default(),
            proof_of_agreement_types: EIP712ProofOfAgreementTypes::default(),
        }
        instance.init_typehashes();
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

    // Public method - returns the greeting saved, defaulting to DEFAULT_GREETING
    // pub fn get_greeting(&self) -> String {
    //     self.greeting.clone()
    // }

    // Public method - accepts a greeting, such as "howdy", and records it
    // pub fn set_greeting(&mut self, greeting: String) {
    //     log!("Saving greeting: {greeting}");
    //     self.greeting = greeting;
    // }
    
    // Initialization and helper methods...
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use near_sdk::{test_utils::{accounts, VMContextBuilder}, testing_env, VMContext};

    // Helper function to set up the blockchain context for tests
    fn get_context(is_view: bool) -> VMContext {
        VMContextBuilder::new()
            .signer_account_id(accounts(0)) // accounts(0) is a default test account
            .is_view(is_view)
            .build()
    }

    #[test]
    fn constructor_test() {
        let context = get_context(false);
        testing_env!(context);

        let domain = EIP712Domain {
            name: "daosign".to_string(),
            version: "0.1.0".to_string(),
            chain_id: vec![0; 32],
            verifying_contract: vec![0; 32],
        };

        let instance = DAOsignEIP712::new(domain.clone());

        // // Test domain hash
        // assert_eq!(
        //     instance.domain_hash,
        //     <[u8; 32]>::from_hex(
        //         "98670852334fc8f702b23d30e8b0adf9084b364869f775b23e9b89e3c50390c0",
        //     )
        //     .unwrap()
        // );

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

        // // Assuming your instance has a way to expose or calculate the domain hash for verification
        // let expected_domain_hash = vec![0; 32]; // Placeholder for the actual expected value
        // assert_eq!(instance.domain_hash, expected_domain_hash, "Domain hash does not match expected value.");

        // // Example assertions for typehashes - adapt according to your instance's logic and available methods
        // let expected_eip712domain_typehash = vec![0; 32]; // Placeholder for actual expected value
        // assert_eq!(instance.eip712domain_typehash, expected_eip712domain_typehash, "EIP712 Domain TypeHash mismatch.");

        // let expected_signer_typehash = vec![0; 32]; // Placeholder for actual expected value
        // assert_eq!(instance.signer_typehash, expected_signer_typehash, "Signer TypeHash mismatch.");

        // // Similarly, for proof structures, assuming your instance can validate or expose these for testing
        // // The following are placeholder checks; you need to adapt them based on your instance's implementation
        // assert!(!instance.proof_of_authority_types.eip712_domain.is_empty(), "Proof of Authority EIP712 domain should not be empty.");
        // assert!(!instance.proof_of_authority_types.signer.is_empty(), "Proof of Authority signer types should not be empty.");
        // assert!(!instance.proof_of_authority_types.proof_of_authority.is_empty(), "Proof of Authority types should not be empty.");

        // assert!(!instance.proof_of_signature_types.eip712_domain.is_empty(), "Proof of Signature EIP712 domain should not be empty.");
        // assert!(!instance.proof_of_signature_types.proof_of_signature.is_empty(), "Proof of Signature types should not be empty.");

        // assert!(!instance.proof_of_agreement_types.eip712_domain.is_empty(), "Proof of Agreement EIP712 domain should not be empty.");
        // assert!(!instance.proof_of_agreement_types.proof_of_agreement.is_empty(), "Proof of Agreement types should not be empty.");

        // // Asserting domain properties to ensure they match what we initialized
        // assert_eq!(instance.domain.name, domain.name);
        // assert_eq!(instance.domain.version, domain.version);
        // assert_eq!(instance.domain.chain_id, domain.chain_id);
        // assert_eq!(instance.domain.verifying_contract, domain.verifying_contract);
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
