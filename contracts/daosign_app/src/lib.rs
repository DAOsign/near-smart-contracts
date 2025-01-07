mod daosign_app {
    use ed25519_dalek::PublicKey;
    use near_sdk::{
        borsh::{self, BorshDeserialize, BorshSerialize},
        env, log, near_bindgen,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    use daosign_attestation::Attestation;
    use daosign_proof_of_agreement::ProofOfAgreement;
    use daosign_proof_of_signature::ProofOfSignature;
    use daosign_schema::Schema;

    /// Main storage structure for DAOsignApp contract.
    #[near_bindgen]
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct DAOSignApp {
        // Counters for schemas and attestations
        pub schema_id: u128,
        pub attestation_id: u128,

        // Mappings
        pub schemas: HashMap<u128, Schema>, // schema_id => Schema
        pub attestations: HashMap<u128, Attestation>, // attestation_id => Attestation
        pub poa: HashMap<u128, Vec<ProofOfAgreement>>, // attestation_id => ProofOfSignature
        pub pos: HashMap<u128, Vec<ProofOfSignature>>, // attestation_id => ProofOfAgreement
        pub signed_attestation: HashMap<u128, HashMap<Vec<u8>, bool>>, // attestation_id  => user => signed
        pub user_attestation: HashMap<u128, HashMap<[u8; 32], Vec<Attestation>>>, // schema_id  => user => Attestation[]
    }

    impl Default for DAOSignApp {
        fn default() -> Self {
            Self {
                schema_id: 0,
                attestation_id: 0,
                schemas: HashMap::new(),
                attestations: HashMap::new(),
                poa: HashMap::new(),
                pos: HashMap::new(),
                signed_attestation: HashMap::new(),
                user_attestation: HashMap::new(),
            }
        }
    }

    #[near_bindgen]
    impl DAOSignApp {
        /// # Constructor for creating a new DAOsignApp instance.
        ///
        /// This constructor initializes a new DAOsignApp contract instance.
        ///
        /// # Returns
        ///
        /// A new instance of DAOsignApp.
        #[init]
        pub fn new() -> Self {
            Self {
                schema_id: 0,
                attestation_id: 0,
                schemas: HashMap::new(),
                attestations: HashMap::new(),
                poa: HashMap::new(),
                pos: HashMap::new(),
                signed_attestation: HashMap::new(),
                user_attestation: HashMap::new(),
            }
        }

        /// # Creates a new schema.
        ///   The Schema object containing metadata and definition to be created.
        #[payable]
        pub fn store_schema(&mut self, data: Schema, caller: [u8; 32]) {
            let caller_key = PublicKey::from_bytes(&caller).unwrap();

            // Validate the data
            data.validate(caller_key);

            // Store
            self.schemas.insert(self.schema_id, data.clone());

            //Increment schema id
            self.schema_id += 1;

            //Emit event
            log!("Event: SchemaCreated {{ data: {:?} }}", data);
        }

        /// # Attests to a specified schema with the provided attestation data.
        ///   The Attestation object containing information about the attestation being made.
        #[payable]
        pub fn store_attestation(&mut self, data: Attestation, caller: Vec<u8>) {
            let caller_key = PublicKey::from_bytes(&caller).unwrap();

            const ZERO_ADDRESS: [u8; 32] = [0u8; 32]; // Define zero address

            let s = self.get_schema(data.schema_id);

            // Validate the data
            data.validate(s, caller_key);

            // Store attestation
            self.attestations.insert(self.schema_id, data.clone());

            // Store attestation for user / signatories
            if data.recipient != ZERO_ADDRESS {
                let recipient: Vec<[u8; 32]> = vec![data.recipient]; // Wrap the recipient in a Vec
                self.store_user_attestation(recipient, data.clone());
            }
            self.store_user_attestation(data.signatories.clone(), data.clone());

            //Increment schema id
            self.attestation_id += 1;

            //Emit event
            log!("Event: AttestationCreated {{ data: {:?} }}", data);
        }

        /// # Revokes an existing attestation.
        ///   a_id The ID of the attestation to be revoked.
        #[payable]
        pub fn store_revoke(&mut self, a_id: u128, caller: Vec<u8>) {
            let caller_key = PublicKey::from_bytes(&caller).unwrap();

            const ZERO_ADDRESS: [u8; 32] = [0u8; 32]; // Define zero address

            let mut a = self.get_attestation(a_id);
            let s = self.get_schema(a.schema_id);

            // Validate revoke
            a.validate_revoke(s, caller_key);

            // modify store revoke status
            a.revoked_at = env::block_timestamp().try_into().unwrap();
            a.is_revoked = true;

            // Update the user attestation by removing the previous entry
            if let Some(user_attestations) = self.user_attestation.get_mut(&a.schema_id) {
                // Remove the existing attestation for the caller
                if let Some(attestations) = user_attestations.get_mut(&a.recipient) {
                    attestations.retain(|att| att.attestation_id != a_id); // Remove the specific attestation
                }
            }

            // Add the modified attestation back to the hashmap
            self.user_attestation
                .entry(a.schema_id)
                .or_insert_with(HashMap::new)
                .entry(a.recipient)
                .or_insert_with(Vec::new)
                .push(a.clone()); // Push the updated attestation

            //Emit event
            log!("Event: Revoked {{ attestation: {:?} }}", a);
        }

        // #[payable]
        // pub fn store_pos(&mut self, data: ProofOfSignature, caller: Vec<u8>) {
        //     let caller_key = PublicKey::from_bytes(&caller).unwrap();

        //     assert!(
        //         self.signed_attestation
        //             .get(&data.attestation_id)
        //             .and_then(|map| map.get(&caller))
        //             .map_or(false, |&v| v),
        //         "Attestation already signed by caller."
        //     );

        //     let mut a = self.get_attestation(data.attestation_id);
        //     let s = self.get_schema(a.schema_id);

        //     // Validate the data
        //     data.validate(a, s, caller_key);

        //     // Store the ProofOfSignature
        //     self.pos
        //         .entry(data.attestation_id)
        //         .or_insert_with(Vec::new)
        //         .push(data.clone());

        //     let proofs = self.get_proof_of_signature(a.attestation_id);
        //     if a.signatories.len() == proofs.len() {
        //         self.store_poa(a)
        //     }

        //     // Mark the attestation as signed by the caller
        //     self.signed_attestation
        //         .entry(data.attestation_id)
        //         .or_insert_with(HashMap::new)
        //         .insert(caller, true);

        //     log!(
        //         "Event: ProofOfSignatureStored {{pos: {:?} }} ",
        //         data.attestation_id
        //     );
        // }

        // fn store_poa(&mut self, a: Attestation) {
        //     let proofs = self.get_proof_of_signature(a.attestation_id);
        //     // Store attestation
        //     self.poa.insert(a.attestation_id, proofs.clone());
        // }

        fn store_user_attestation(&mut self, users: Vec<[u8; 32]>, data: Attestation) {
            for user in users {
                // Get or create the outer entry for the attestation ID
                let user_attestations = self
                    .user_attestation
                    .entry(data.schema_id)
                    .or_insert_with(HashMap::new);

                let recipient_attestations = user_attestations
                    .entry(user) // This is now the inner HashMap
                    .or_insert_with(Vec::new); // Create a new Vec if it doesn’t exist

                // Finally, push the attestation data into the Vec
                recipient_attestations.push(data.clone()); // Ensure to clone if you want to retain the original data
            }
        }

        pub fn get_schema(&self, schema_id: u128) -> Schema {
            self.schemas.get(&schema_id).unwrap().clone()
        }

        pub fn get_attestation(&self, attestation_id: u128) -> Attestation {
            self.attestations.get(&attestation_id).unwrap().clone()
        }

        pub fn get_proof_of_signature(&self, attestation_id: u128) -> Vec<ProofOfSignature> {
            self.pos.get(&attestation_id).unwrap().clone()
        }

        pub fn get_user_attestations(&self, schema_id: u128, caller: [u8; 32]) -> Vec<Attestation> {
            self.user_attestation
                .get(&schema_id) // Get the map for schema_id
                .and_then(|caller_map| caller_map.get(&caller)) // Get the attestations for caller
                .cloned() // Clone the vector (Option<Vec<Attestation>>)
                .unwrap_or_else(Vec::new) // If None, return an empty Vec
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use daosign_app::DAOSignApp;
    use daosign_schema::{Schema, SchemaDefinition, SchemaMetadata, SignatoryPolicy};
    use ed25519_dalek::{Keypair, Signature, Signer};
    use rand::rngs::OsRng;

    fn create_signer() -> Keypair {
        let mut csprng = OsRng {};
        Keypair::generate(&mut csprng)
    }

    fn sign_transaction(message: &[u8], signer: &Keypair) -> Signature {
        signer.sign(message)
    }

    // Create DAOSignApp instance for testing
    fn create_daosign_app() -> DAOSignApp {
        DAOSignApp::new()
    }

    fn create_schema(creator: [u8; 32]) -> Schema {
        let schema_data = Schema {
            schema_id: 0,
            metadata: SchemaMetadata {
                name: "DaoSign Vacancy".to_string(),
                description: "Blockchain developer vacancy".to_string(),
                attestation_type: "agreement".to_string(),
                nft_name: "nft_name".to_string(),
                nft_symbol: "nft_symbol".to_string(),
                creator,
                created_at: 1,
                is_nft: true,
                is_public: false,
                is_revokable: true,
                expire_in: 0,
            },
            signatory_policy: vec![
                SignatoryPolicy {
                    operator: 0x01,
                    signatory_description: "role".to_string(),
                    required_schema_id: vec![0],
                },
                SignatoryPolicy {
                    operator: 0x01,
                    signatory_description: "role1".to_string(),
                    required_schema_id: vec![0],
                },
            ],
            schema_definition: vec![
                SchemaDefinition {
                    definition_type: "string".to_string(),
                    definition_name: "vacancies".to_string(),
                },
                SchemaDefinition {
                    definition_type: "uint256".to_string(),
                    definition_name: "salary".to_string(),
                },
            ],
            signature: vec![0; 65],
        };
        schema_data
    }

    #[test]
    fn test_store_schema() {
        let mut app = create_daosign_app();
        let caller = create_signer().public.to_bytes();
        let schema = create_schema(caller);

        // Store schema
        app.store_schema(schema.clone(), caller);

        // Verify schema is stored
        assert_eq!(app.schemas.len(), 1);
        assert_eq!(app.schemas.get(&0), Some(&schema));
    }

    #[test]
    fn test_schema_unauthorized_schema_creator() {}

    #[test]
    fn test_schema_empty_schema_definition() {}

    #[test]
    fn test_store_attestation() {}

    #[test]
    fn test_attestation_schema_does_not_exist() {}

    #[test]
    fn test_attestation_unauthorized_attestator() {}

    #[test]
    fn test_attestation_schema_already_expired() {}

    #[test]
    fn test_attestation_length_mismatch() {}

    #[test]
    fn test_attestation_name_mismatch() {}

    #[test]
    fn test_attestation_type_mismatch() {}

    #[test]
    fn test_store_revoke() {}

    #[test]
    fn test_revoke_attestation_does_not_exist() {}

    #[test]
    fn test_revoke_unauthorized_attestator() {}

    #[test]
    fn test_store_pos_and() {}

    #[test]
    fn test_store_pos_or() {}

    #[test]
    fn test_store_pos_not() {}

    #[test]
    fn test_pos_invalid_signatory_address() {}

    #[test]
    fn test_pos_unsupported_operator() {}

    #[test]
    fn test_pos_insufficient_attestations() {}

    #[test]
    fn test_store_poa_identity() {}

    #[test]
    fn test_poa_with_one_signatory() {}

    #[test]
    fn test_pos_with_two_signatories() {}
}
