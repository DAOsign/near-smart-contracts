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
        pub signed_attestation: HashMap<u128, HashMap<[u8; 32], bool>>, // attestation_id  => user => signed
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

        /// # Message to store a Schema.
        ///
        /// This function stores a Schema and validates the message. If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `data` - Schema struct containing the schema data.
        /// * `caller` - Address of user who sign this message.
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
            // log!("Event: SchemaCreated {{ data: {:?} }}", data);
        }

        /// # Message to store a Attestation.
        ///
        /// This function stores a Attestation and validates the message. If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `data` - Attestation struct containing the schema data.
        /// * `caller` - Address of user who sign this message.
        #[payable]
        pub fn store_attestation(&mut self, data: Attestation, caller: [u8; 32]) {
            let caller_key = PublicKey::from_bytes(&caller).unwrap();

            const ZERO_ADDRESS: [u8; 32] = [0u8; 32]; // Define zero address

            let s = self.get_schema(data.schema_id);

            // Validate the data
            data.validate(s, caller_key);

            // Store attestation
            self.attestations.insert(self.attestation_id, data.clone());

            // Store attestation for user / signatories
            if data.recipient != ZERO_ADDRESS {
                let recipient: Vec<[u8; 32]> = vec![data.recipient]; // Wrap the recipient in a Vec
                self.store_user_attestation(recipient, data.clone());
            }
            self.store_user_attestation(data.signatories.clone(), data.clone());

            //Increment schema id
            self.attestation_id += 1;

            //Emit event
            // log!("Event: AttestationCreated {{ data: {:?} }}", data);
        }

        /// # Message to store a Revoke.
        ///
        /// This function modify an Attestation and validates the message. If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `a_id` - Attestation id that will be revoked.
        /// * `sig` - Message signature.
        /// * `caller` - Address of user who sign this message.
        #[payable]
        pub fn store_revoke(&mut self, a_id: u128, sig: Vec<u8>, caller: [u8; 32]) {
            let caller_key = PublicKey::from_bytes(&caller).unwrap();

            let mut a = self.get_attestation(a_id);
            let s = self.get_schema(a.schema_id);

            // Validate revoke
            a.validate_revoke(s, sig.clone(), caller_key);

            // modify store revoke status
            a.revoked_at = env::block_timestamp().try_into().unwrap();
            a.is_revoked = true;
            a.revoke_signature = sig.clone();

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

            // Store
            self.attestations.insert(a.attestation_id, a.clone());

            //Emit event
            // log!("Event: Revoked {{ attestation: {:?} }}", a);
        }

        /// # Message to store a Proof of Signature.
        ///
        /// This function stores a Proof of Signature and validates the message. If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `data` - Proof of Signature struct containing the schema data.
        /// * `caller` - Address of user who sign this message.
        #[payable]
        pub fn store_pos(&mut self, data: ProofOfSignature, caller: [u8; 32]) {
            let caller_key = PublicKey::from_bytes(&caller).unwrap();

            if let Some(true) = self
                .signed_attestation
                .get(&data.attestation_id)
                .and_then(|map| map.get(&caller))
            {
                panic!("Attestation already signed by caller.");
            }

            let a = self.get_attestation(data.attestation_id);
            let s = self.get_schema(a.schema_id);

            // Validate the data
            data.validate(a.clone(), s, &self.user_attestation, caller_key);

            // Store the ProofOfSignature
            self.pos
                .entry(data.attestation_id)
                .or_insert_with(Vec::new)
                .push(data.clone());

            let proofs = self.get_proof_of_signature(a.attestation_id);

            if a.signatories.clone().len() == proofs.len() {
                self.store_poa(a)
            }

            // Mark the attestation as signed by the caller
            self.signed_attestation
                .entry(data.attestation_id)
                .or_insert_with(HashMap::new)
                .insert(caller, true);

            log!(
                "Event: ProofOfSignatureStored {{pos: {:?} }} ",
                data.attestation_id
            );
        }

        /// # Message to store a Proof of Agreement.
        ///
        /// This function stores a Proof of Agreement . If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `a` - Attestation that contains all needed information to get Proof of Signature.
        fn store_poa(&mut self, a: Attestation) {
            let proofs = self.get_proof_of_signature(a.attestation_id);

            // Create a vector to store the extracted signatures
            let mut signatory_proofs: Vec<Vec<u8>> = Vec::new();

            // Loop through the proofs and extract the signatures
            for proof in &proofs {
                signatory_proofs.push(proof.signature.clone());
            }

            // Create the ProofOfAgreement struct
            let proof_of_agreement = ProofOfAgreement {
                attestation_id: self.attestation_id,
                signatures: signatory_proofs, // Store the collected signatures
            };
            self.poa
                .entry(a.attestation_id)
                .or_insert_with(Vec::new)
                .push(proof_of_agreement);
        }

        /// # Util method to store user attestation.
        ///
        /// This function stores an Attestations for user. If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `users` - list of users to store Attestation for them.
        /// * `data` - Attestation data that will be stored.
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

        /// # Message to retrieve a Schema by its schema id.
        ///
        /// This function retrieves a stored Schema by its id.
        ///
        /// # Arguments
        ///
        /// * `schema_id` - String representing the ID of the Schema.
        pub fn get_schema(&self, schema_id: u128) -> Schema {
            self.schemas.get(&schema_id).unwrap().clone()
        }

        /// # Message to retrieve a Attestation by its attestation id id.
        ///
        /// This function retrieves a stored Attestation by its id.
        ///
        /// # Arguments
        ///
        /// * `attestation_id` - String representing the ID of the Attestation.
        pub fn get_attestation(&self, attestation_id: u128) -> Attestation {
            self.attestations.get(&attestation_id).unwrap().clone()
        }

        /// # Message to retrieve a Proof of Signature by attestation id.
        ///
        /// This function retrieves a stored Proof of Signature by  attestation id.
        ///
        /// # Arguments
        ///
        /// * `attestation_id` - String representing the ID of the Attestation.
        pub fn get_proof_of_signature(&self, attestation_id: u128) -> Vec<ProofOfSignature> {
            self.pos.get(&attestation_id).unwrap().clone()
        }

        /// # Message to retrieve an Attestations  for a specific user by schema id & his address.
        ///
        /// This function retrieves a stored Attestation by  by schema id & user address.
        ///
        /// # Arguments
        ///
        /// * `schema_id` - String representing the ID of the Schema.
        /// * `caller` - Address of a specific user.
        pub fn get_user_attestations(&self, schema_id: u128, caller: [u8; 32]) -> Vec<Attestation> {
            self.user_attestation
                .get(&schema_id) // Get the map for schema_id
                .and_then(|caller_map| caller_map.get(&caller)) // Get the attestations for caller
                .cloned() // Clone the vector 
                .unwrap_or_else(Vec::new) // If None, return an empty Vec
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use daosign_app::DAOSignApp;
    use daosign_attestation::{Attestation, AttestationResult};
    use daosign_proof_of_signature::ProofOfSignature;
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

    fn create_attestation(creator: [u8; 32]) -> Attestation {
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
        let attestation = Attestation {
            attestation_id: 0,
            schema_id: 0,
            attestation_result: attestation_results, // Assign the vector of results
            creator,                                 // Encode the creator's address
            recipient: creator,                      // Encode the recipient's address
            created_at: 1,                           // Timestamp
            signatories: vec![
                creator, // First signatory address
            ],
            signature: vec![0; 65],
            is_revoked: false,
            revoked_at: 0,
            revoke_signature: vec![0; 65],
        };
        attestation
    }

    fn create_pos(a_id: u128, creator: [u8; 32]) -> ProofOfSignature {
        let pos = ProofOfSignature {
            attestation_id: a_id,
            creator,
            created_at: 0,
            signature: vec![0],
        };
        pos
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
            signatory_policy: vec![SignatoryPolicy {
                operator: 0x01,
                signatory_description: "role".to_string(),
                required_schema_id: vec![0],
            }],
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

        let caller = create_signer();

        let mut schema = create_schema(caller.public.to_bytes());
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &caller);
        schema.signature = signature.to_bytes().to_vec();
        // Store schema
        app.store_schema(schema.clone(), caller.public.to_bytes());

        // Verify schema is stored
        assert_eq!(app.schemas.len(), 1);
        assert_eq!(app.schemas.get(&0), Some(&schema));
    }

    #[test]
    fn test_schema_unauthorized_schema_creator() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            schema.metadata.creator = [1u8; 32]; // Change to an unauthorized creator
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();

            // Attempt to store the schema (this should trigger an error)
            app.store_schema(schema.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_schema_empty_schema_definition() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            schema.schema_definition.clear();

            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();

            // Attempt to store the schema (this should trigger an error)
            app.store_schema(schema.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_store_attestation() {
        let mut app = create_daosign_app();

        let caller = create_signer();

        let mut schema = create_schema(caller.public.to_bytes());
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &caller);
        schema.signature = signature.to_bytes().to_vec();
        // Store schema
        app.store_schema(schema.clone(), caller.public.to_bytes());

        let mut attestation = create_attestation(caller.public.to_bytes());

        let a_mes = attestation.to_ed25519_message();
        let a_sig = sign_transaction(&a_mes, &caller);
        attestation.signature = a_sig.to_bytes().to_vec();

        app.store_attestation(attestation.clone(), caller.public.to_bytes());

        // Verify schema is stored
        assert_eq!(app.attestations.len(), 1);
        assert_eq!(app.attestations.get(&0), Some(&attestation));
    }

    #[test]
    fn test_attestation_schema_does_not_exist() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut attestation = create_attestation(caller.public.to_bytes());

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_attestation_unauthorized_attestator() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();
            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());
            attestation.creator = [0u8; 32];

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_attestation_schema_already_expired() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();
            schema.metadata.expire_in = 1;

            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_attestation_length_mismatch() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();

            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());
            attestation.attestation_result.clear();

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_attestation_name_mismatch() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();

            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());
            attestation.attestation_result[0].name = String::from("foo");

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_attestation_type_mismatch() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();

            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());
            attestation.attestation_result[0].attestation_result_type = String::from("foo");

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_store_revoke() {
        let mut app = create_daosign_app();

        let caller = create_signer();

        let mut schema = create_schema(caller.public.to_bytes());
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &caller);
        schema.signature = signature.to_bytes().to_vec();

        // Store schema
        app.store_schema(schema.clone(), caller.public.to_bytes());

        let mut attestation = create_attestation(caller.public.to_bytes());
        let a_mes = attestation.to_ed25519_message();
        let a_sig = sign_transaction(&a_mes, &caller);
        attestation.signature = a_sig.to_bytes().to_vec();

        app.store_attestation(attestation.clone(), caller.public.to_bytes());

        let r_mes = attestation.to_ed25519_message_revoke();
        let r_sig = sign_transaction(&r_mes, &caller);

        attestation.revoke_signature = r_sig.to_bytes().to_vec();

        app.store_revoke(
            attestation.attestation_id,
            attestation.revoke_signature,
            caller.public.to_bytes(),
        );
        // Verify schema is stored
        assert_eq!(app.attestations.len(), 1);
        if let Some(a) = app.attestations.get(&0) {
            // Assert that `is_revoked` is `true`
            assert_eq!(a.is_revoked, true, "Attestation should be revoked");
        } else {
            panic!("Expected Some(attestation), but got None");
        }
    }

    #[test]
    fn test_revoke_attestation_does_not_exist() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut attestation = create_attestation(caller.public.to_bytes());

            let r_mes = attestation.to_ed25519_message_revoke();
            let r_sig = sign_transaction(&r_mes, &caller);

            attestation.revoke_signature = r_sig.to_bytes().to_vec();

            app.store_revoke(
                attestation.attestation_id,
                attestation.revoke_signature,
                caller.public.to_bytes(),
            );
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_revoke_unauthorized_attestator() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();

            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());
            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());

            let r_mes = attestation.to_ed25519_message_revoke();

            let sec_caller = create_signer();
            let r_sig = sign_transaction(&r_mes, &sec_caller);

            attestation.revoke_signature = r_sig.to_bytes().to_vec();

            app.store_revoke(
                attestation.attestation_id,
                attestation.revoke_signature,
                caller.public.to_bytes(),
            );
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_store_pos_and() {
        let mut app = create_daosign_app();

        let caller = create_signer();

        let mut schema = create_schema(caller.public.to_bytes());
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &caller);
        schema.signature = signature.to_bytes().to_vec();
        // Store schema
        app.store_schema(schema.clone(), caller.public.to_bytes());

        let mut attestation = create_attestation(caller.public.to_bytes());

        let a_mes = attestation.to_ed25519_message();
        let a_sig = sign_transaction(&a_mes, &caller);
        attestation.signature = a_sig.to_bytes().to_vec();

        app.store_attestation(attestation.clone(), caller.public.to_bytes());

        let mut pos = create_pos(attestation.attestation_id, caller.public.to_bytes());

        let pos_mes = pos.to_ed25519_message();
        let pos_sig = sign_transaction(&pos_mes, &caller);

        pos.signature = pos_sig.to_bytes().to_vec();

        app.store_pos(pos, caller.public.to_bytes());
        // println!("poa {:?}", app.poa.get(&0))
    }

    #[test]
    fn test_store_pos_or() {
        let mut app = create_daosign_app();

        let caller = create_signer();

        let mut schema = create_schema(caller.public.to_bytes());
        schema.signatory_policy[0].operator = 0x02;
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &caller);
        schema.signature = signature.to_bytes().to_vec();
        // Store schema
        app.store_schema(schema.clone(), caller.public.to_bytes());

        let mut attestation = create_attestation(caller.public.to_bytes());

        let a_mes = attestation.to_ed25519_message();
        let a_sig = sign_transaction(&a_mes, &caller);
        attestation.signature = a_sig.to_bytes().to_vec();

        app.store_attestation(attestation.clone(), caller.public.to_bytes());

        let mut pos = create_pos(attestation.attestation_id, caller.public.to_bytes());

        let pos_mes = pos.to_ed25519_message();
        let pos_sig = sign_transaction(&pos_mes, &caller);

        pos.signature = pos_sig.to_bytes().to_vec();

        app.store_pos(pos, caller.public.to_bytes());
    }

    #[test]
    fn test_store_pos_not() {
        let mut app = create_daosign_app();

        let caller = create_signer();

        let mut schema = create_schema(caller.public.to_bytes());
        schema.signatory_policy[0].required_schema_id.clear();
        schema.signatory_policy[0].required_schema_id = [1].to_vec();
        schema.signatory_policy[0].operator = 0x03;
        let message = schema.to_ed25519_message();
        let signature = sign_transaction(&message, &caller);
        schema.signature = signature.to_bytes().to_vec();
        // Store schema
        app.store_schema(schema.clone(), caller.public.to_bytes());

        let mut attestation = create_attestation(caller.public.to_bytes());

        let a_mes = attestation.to_ed25519_message();
        let a_sig = sign_transaction(&a_mes, &caller);
        attestation.signature = a_sig.to_bytes().to_vec();

        app.store_attestation(attestation.clone(), caller.public.to_bytes());

        let mut pos = create_pos(attestation.attestation_id, caller.public.to_bytes());

        let pos_mes = pos.to_ed25519_message();
        let pos_sig = sign_transaction(&pos_mes, &caller);

        pos.signature = pos_sig.to_bytes().to_vec();

        app.store_pos(pos, caller.public.to_bytes());
    }

    #[test]
    fn test_pos_invalid_signatory_address() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();
            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());
            let caller_two = create_signer();

            let mut pos = create_pos(attestation.attestation_id, caller_two.public.to_bytes());

            let pos_mes = pos.to_ed25519_message();
            let pos_sig = sign_transaction(&pos_mes, &caller_two);

            pos.signature = pos_sig.to_bytes().to_vec();

            app.store_pos(pos, caller_two.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_pos_unsupported_operator() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            schema.signatory_policy[0].operator = 0x04;
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();
            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());

            let mut pos = create_pos(attestation.attestation_id, caller.public.to_bytes());

            let pos_mes = pos.to_ed25519_message();
            let pos_sig = sign_transaction(&pos_mes, &caller);

            pos.signature = pos_sig.to_bytes().to_vec();

            app.store_pos(pos, caller.public.to_bytes());
        });

        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }

    #[test]
    fn test_pos_insufficient_attestations() {
        let result = std::panic::catch_unwind(|| {
            let mut app = create_daosign_app();

            let caller = create_signer();

            let mut schema = create_schema(caller.public.to_bytes());
            schema.signatory_policy[0].required_schema_id.push(1);
            let message = schema.to_ed25519_message();
            let signature = sign_transaction(&message, &caller);
            schema.signature = signature.to_bytes().to_vec();
            // Store schema
            app.store_schema(schema.clone(), caller.public.to_bytes());

            let mut attestation = create_attestation(caller.public.to_bytes());

            let a_mes = attestation.to_ed25519_message();
            let a_sig = sign_transaction(&a_mes, &caller);
            attestation.signature = a_sig.to_bytes().to_vec();

            app.store_attestation(attestation.clone(), caller.public.to_bytes());

            let mut pos = create_pos(attestation.attestation_id, caller.public.to_bytes());

            let pos_mes = pos.to_ed25519_message();
            let pos_sig = sign_transaction(&pos_mes, &caller);

            pos.signature = pos_sig.to_bytes().to_vec();

            app.store_pos(pos, caller.public.to_bytes());
        });
        // Check that the error occurred and contains the expected message
        assert!(result.is_err(), "Expected an error, but none occurred");
    }
}
