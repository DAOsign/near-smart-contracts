#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod daosign_app {
    use ink::prelude::{string::String, vec::Vec};
    use ink::storage::Mapping;

    use daosign_eip712::{recover, EIP712Domain, EIP712Message};
    use daosign_proof_of_agreement::ProofOfAgreement;
    use daosign_proof_of_authority::ProofOfAuthority;
    use daosign_proof_of_signature::ProofOfSignature;

    // Length of IPFS Content Identifier (CID)
    const IPFS_CID_LENGTH: usize = 46;
    // Default value for zero address
    const ZERO_ADDR: [u8; 20] = [0u8; 20];

    //
    // structs definition
    //

    /// Represents a signed Proof-of-Authority with the message, signature, and proof CID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
    pub struct SignedProofOfAuthority {
        message: ProofOfAuthority,
        signature: Vec<u8>,
        proof_cid: String,
    }

    /// Represents a signed Proof-of-Signature with the message, signature, and proof CID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
    pub struct SignedProofOfSignature {
        message: ProofOfSignature,
        signature: Vec<u8>,
        proof_cid: String,
    }

    /// Represents a signed Proof-of-Agreement with the message, signature, and proof CID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
    pub struct SignedProofOfAgreement {
        message: ProofOfAgreement,
        signature: Vec<u8>,
        proof_cid: String,
    }

    /// Represents a signed Proof-of-Authority with the EIP712 message, signature, and proof CID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SignedProofOfAuthorityMsg {
        message: EIP712Message<ProofOfAuthority>,
        signature: Vec<u8>,
    }

    /// Represents a signed Proof-of-Signature with the EIP712 message, signature, and proof CID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SignedProofOfSignatureMsg {
        message: EIP712Message<ProofOfSignature>,
        signature: Vec<u8>,
    }

    /// Represents a signed Proof-of-Agreement with the EIP712 message, signature, and proof CID.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SignedProofOfAgreementMsg {
        message: EIP712Message<ProofOfAgreement>,
        signature: Vec<u8>,
    }

    //
    // DAOsignApp contract
    //

    /// Event emitted when a new Proof-of-Authority is added.
    #[ink(event)]
    pub struct NewProofOfAuthority {
        data: SignedProofOfAuthority,
    }

    /// Event emitted when a new Proof-of-Signature is added.
    #[ink(event)]
    pub struct NewProofOfSignature {
        data: SignedProofOfSignature,
    }

    /// Event emitted when a new Proof-of-Agreement is added.
    #[ink(event)]
    pub struct NewProofOfAgreement {
        data: SignedProofOfAgreement,
    }

    /// Main storage structure for DAOsignApp contract.
    #[ink(storage)]
    pub struct DAOSignApp {
        domain: EIP712Domain,
        poaus: Mapping<String, SignedProofOfAuthority>,
        posis: Mapping<String, SignedProofOfSignature>,
        poags: Mapping<String, SignedProofOfAgreement>,
        proof2signer: Mapping<String, [u8; 20]>,
        poau_signers_idx: Mapping<(String, [u8; 20]), u32>,
    }

    impl DAOSignApp {
        /// # Ink! constructor for creating a new DAOsignApp instance.
        ///
        /// This constructor initializes a new DAOsignApp contract instance with the provided EIP712 domain.
        ///
        /// # Arguments
        ///
        /// * `domain` - EIP712Domain struct representing the domain of the contract.
        ///
        /// # Returns
        ///
        /// A new instance of DAOsignApp.
        #[ink(constructor)]
        pub fn new(domain: EIP712Domain) -> Self {
            Self {
                domain,
                poaus: Mapping::new(),
                posis: Mapping::new(),
                poags: Mapping::new(),
                proof2signer: Mapping::new(),
                poau_signers_idx: Mapping::new(),
            }
        }

        /// # Ink! message to store a Proof of Authority.
        ///
        /// This function stores a Proof of Authority along with its signature and validates the signature and message.
        /// If the data is valid, it is stored in the contract, and relevant mappings are updated.
        ///
        /// # Arguments
        ///
        /// * `data` - SignedProofOfAuthority struct containing the proof of authority data and its signature.
        #[ink(message)]
        pub fn store_proof_of_authority(&mut self, data: SignedProofOfAuthority) {
            assert!(
                recover(
                    &self.domain.clone(),
                    &data.message,
                    &data.signature.clone().try_into().expect("bad signature")
                )
                .expect("can't recover signer")
                    == data.message.from,
                "Invalid signature"
            );

            // Validate the data
            assert!(
                self.validate_signed_proof_of_authority(&data),
                "Invalid message"
            );

            // Store
            self.poaus.insert(data.proof_cid.clone(), &data.clone());

            // Update the signer indices and push new signers
            for (i, signer) in data.message.signers.iter().enumerate() {
                self.poau_signers_idx
                    .insert((data.proof_cid.clone(), signer.addr), &(i as u32));
            }

            // Update proof to signer mapping
            self.proof2signer
                .insert(data.proof_cid.clone(), &data.message.from);

            Self::env().emit_event(NewProofOfAuthority { data });
        }

        /// # Ink! message to store a Proof of Signature.
        ///
        /// This function stores a Proof of Signature along with its signature and validates the signature and message.
        /// If the data is valid, it is stored in the contract, and relevant mappings are updated.
        ///
        /// # Arguments
        ///
        /// * `data` - SignedProofOfSignature struct containing the proof of signature data and its signature.
        #[ink(message)]
        pub fn store_proof_of_signature(&mut self, data: SignedProofOfSignature) {
            assert!(
                recover(
                    &self.domain.clone(),
                    &data.message,
                    &data.signature.clone().try_into().expect("bad signature")
                )
                .expect("can't recover signer")
                    == data.message.signer,
                "Invalid signature"
            );

            // Validate the data
            assert!(
                self.validate_signed_proof_of_signature(&data),
                "Invalid message"
            );

            // Store
            self.posis.insert(data.proof_cid.clone(), &data.clone());

            // Update proof to signer mapping
            self.proof2signer
                .insert(data.proof_cid.clone(), &data.message.signer);

            Self::env().emit_event(NewProofOfSignature { data });
        }

        /// # Ink! message to store a Proof of Agreement.
        ///
        /// This function stores a Proof of Agreement and validates the message. If the data is valid, it is stored in the contract.
        ///
        /// # Arguments
        ///
        /// * `data` - SignedProofOfAgreement struct containing the proof of agreement data.
        #[ink(message)]
        pub fn store_proof_of_agreement(&mut self, data: SignedProofOfAgreement) {
            // Validate the data
            assert!(
                self.validate_signed_proof_of_agreement(&data),
                "Invalid message"
            );

            // Store
            self.poags.insert(data.proof_cid.clone(), &data.clone());

            Self::env().emit_event(NewProofOfAgreement { data });
        }

        /// # Ink! message to retrieve a Proof of Authority by its CID.
        ///
        /// This function retrieves a stored Proof of Authority by its CID.
        ///
        /// # Arguments
        ///
        /// * `cid` - String representing the CID of the Proof of Authority.
        #[ink(message)]
        pub fn get_proof_of_authority(&self, cid: String) -> SignedProofOfAuthority {
            self.poaus.get(cid).unwrap()
        }

        /// # Ink! message to retrieve a Proof of Signature by its CID.
        ///
        /// This function retrieves a stored Proof of Signature by its CID.
        ///
        /// # Arguments
        ///
        /// * `cid` - String representing the CID of the Proof of Signature.
        #[ink(message)]
        pub fn get_proof_of_signature(&self, cid: String) -> SignedProofOfSignature {
            self.posis.get(cid).unwrap()
        }

        /// # Ink! message to retrieve a Proof of Agreement by its CID.
        ///
        /// This function retrieves a stored Proof of Agreement by its CID.
        ///
        /// # Arguments
        ///
        /// * `cid` - String representing the CID of the Proof of Agreement.
        #[ink(message)]
        pub fn get_proof_of_agreement(&self, cid: String) -> SignedProofOfAgreement {
            self.poags.get(cid).unwrap()
        }

        /// # Validates a signed Proof-of-Authority message.
        ///
        /// This function performs various checks on the provided `SignedProofOfAuthority` data to ensure its validity.
        ///
        /// # Arguments
        ///
        /// * `data` - SignedProofOfAuthority struct representing the signed proof.
        ///
        /// # Returns
        ///
        /// Returns `true` if the validation passes, otherwise raises assertions.
        pub fn validate_signed_proof_of_authority(&self, data: &SignedProofOfAuthority) -> bool {
            assert!(data.proof_cid.len() == IPFS_CID_LENGTH, "Invalid proof CID");
            assert!(
                data.message.name == "Proof-of-Authority",
                "Invalid proof name"
            );
            assert!(
                data.message.agreement_cid.len() == IPFS_CID_LENGTH,
                "Invalid agreement CID"
            );
            for signer in data.message.signers.iter() {
                assert!(signer.addr != ZERO_ADDR, "Invalid signer");
            }
            true
        }

        /// # Validates a signed Proof-of-Signature message.
        ///
        /// This function performs various checks on the provided `SignedProofOfSignature` data to ensure its validity.
        ///
        /// # Arguments
        ///
        /// * `data` - SignedProofOfSignature struct representing the signed proof.
        ///
        /// # Returns
        ///
        /// Returns `true` if the validation passes, otherwise raises assertions.
        pub fn validate_signed_proof_of_signature(&self, data: &SignedProofOfSignature) -> bool {
            assert!(data.proof_cid.len() == IPFS_CID_LENGTH, "Invalid proof CID");
            assert!(
                data.message.name == "Proof-of-Signature",
                "Invalid proof name"
            );

            let i: usize = self
                .poau_signers_idx
                .get((&data.message.authority_cid, &data.message.signer))
                .unwrap()
                .try_into()
                .unwrap();
            assert!(
                self.poaus
                    .get(&data.message.authority_cid)
                    .unwrap()
                    .message
                    .signers[i]
                    .addr
                    == data.message.signer,
                "Invalid signer"
            );

            true
        }

        /// # Validates a signed Proof-of-Agreement message.
        ///
        /// This function performs various checks on the provided `SignedProofOfAgreement` data to ensure its validity.
        ///
        /// # Arguments
        ///
        /// * `data` - SignedProofOfAgreement struct representing the signed proof.
        ///
        /// # Returns
        ///
        /// Returns `true` if the validation passes, otherwise raises assertions.
        pub fn validate_signed_proof_of_agreement(&self, data: &SignedProofOfAgreement) -> bool {
            assert!(data.proof_cid.len() == IPFS_CID_LENGTH, "Invalid proof CID");
            assert!(
                self.poaus
                    .get(&data.message.authority_cid)
                    .unwrap()
                    .message
                    .name
                    == "Proof-of-Authority",
                "Invalid Proof-of-Authority name"
            );
            assert!(
                self.poaus
                    .get(&data.message.authority_cid)
                    .unwrap()
                    .message
                    .signers
                    .len()
                    == data.message.signature_cids.len(),
                "Invalid Proofs-of-Signatures length"
            );

            for signature_cid in data.message.signature_cids.iter() {
                let idx: usize = self
                    .poau_signers_idx
                    .get((
                        &data.message.authority_cid,
                        &self.posis.get(signature_cid).unwrap().message.signer,
                    ))
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(
                    self.poaus
                        .get(&data.message.authority_cid)
                        .unwrap()
                        .message
                        .signers[idx]
                        .addr
                        == self.posis.get(signature_cid).unwrap().message.signer,
                    "Invalid Proofs-of-Signature signer"
                );
            }

            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hex::FromHex;

        use daosign_eip712::EIP712Domain;
        use daosign_proof_of_agreement::ProofOfAgreement;
        use daosign_proof_of_authority::ProofOfAuthority;
        use daosign_proof_of_authority::Signer;
        use daosign_proof_of_signature::ProofOfSignature;

        fn store_proof_of_authority(instance: &mut DAOSignApp) {
            let timestamp: u64 = 1711498247;
            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let signature = <[u8; 65]>::from_hex("ef1e21a1e3d2c5fc8da61aaf4162dbd7480c7b9651fd564c4d7f2425d487279021ac4016d43ddad887f9951cf47e41003826bf6a9bcffd0824946a88b9158abd1c").unwrap();
            let proof_cid = String::from("ProofOfAuthority proof cid                    ");

            instance.store_proof_of_authority(SignedProofOfAuthority {
                message: ProofOfAuthority {
                    name: String::from("Proof-of-Authority"),
                    from,
                    agreement_cid: String::from("agreement file cid                            "),
                    signers: Vec::from([Signer {
                        addr: from,
                        metadata: String::from("some metadata"),
                    }]),
                    timestamp,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            });
        }

        fn store_proof_of_signature(instance: &mut DAOSignApp) {
            let timestamp: u64 = 1711498247;
            let signer = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let signature = <[u8; 65]>::from_hex("461d21a35edf1a3d926b1f9af11738211c846e450830a205e6d1801288195afd09c45e8bbde61fbf6a8e655df3133d9a8ec6495b1987abb77862d8beaefe12811c").unwrap();
            let proof_cid = String::from("ProofOfSignature proof cid                    ");

            instance.store_proof_of_signature(SignedProofOfSignature {
                message: ProofOfSignature {
                    name: String::from("Proof-of-Signature"),
                    signer,
                    authority_cid: String::from("ProofOfAuthority proof cid                    "),
                    timestamp,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            });
        }

        fn store_proof_of_agreement(instance: &mut DAOSignApp) {
            let timestamp: u64 = 1711498247;
            let signature = <[u8; 65]>::from_hex("b05b5e2c46e33e744d474227755f4e6cf8308d75347f67107e3514a9ff7247d93178e100540a2778693459842fd0fedb99f6d17a8b50988ad0d2a634eb164e691b").unwrap();
            let proof_cid = String::from("ProofOfAgreement proof cid                    ");

            instance.store_proof_of_agreement(SignedProofOfAgreement {
                message: ProofOfAgreement {
                    authority_cid: String::from("ProofOfAuthority proof cid                    "),
                    signature_cids: Vec::from([String::from(
                        "ProofOfSignature proof cid                    ",
                    )]),
                    timestamp,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            });
        }

        #[ink::test]
        fn test_store_proof_of_authority() {
            let mut instance = DAOSignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 1,
                verifying_contract: [0; 20].into(),
            });
            let timestamp: u64 = 1711498247;
            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let signature = <[u8; 65]>::from_hex("ef1e21a1e3d2c5fc8da61aaf4162dbd7480c7b9651fd564c4d7f2425d487279021ac4016d43ddad887f9951cf47e41003826bf6a9bcffd0824946a88b9158abd1c").unwrap();
            let proof_cid = String::from("ProofOfAuthority proof cid                    ");

            store_proof_of_authority(&mut instance);

            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().signature,
                signature
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().proof_cid,
                proof_cid.clone()
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().message.name,
                String::from("Proof-of-Authority")
            );
            assert_eq!(
                instance.poaus.get(proof_cid.clone()).unwrap().message.from,
                from
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .agreement_cid,
                String::from("agreement file cid                            ")
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signers
                    .len(),
                1
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signers[0]
                    .addr,
                from
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signers[0]
                    .metadata,
                String::from("some metadata")
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .timestamp,
                timestamp
            );
            assert_eq!(
                instance
                    .poaus
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .metadata,
                String::from("proof metadata")
            );
        }

        #[ink::test]
        fn test_store_proof_of_signature() {
            let mut instance = DAOSignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 1,
                verifying_contract: [0; 20].into(),
            });
            let timestamp: u64 = 1711498247;
            let signer = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let signature = <[u8; 65]>::from_hex("461d21a35edf1a3d926b1f9af11738211c846e450830a205e6d1801288195afd09c45e8bbde61fbf6a8e655df3133d9a8ec6495b1987abb77862d8beaefe12811c").unwrap();
            let proof_cid = String::from("ProofOfSignature proof cid                    ");

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);

            let data = SignedProofOfSignature {
                message: ProofOfSignature {
                    name: String::from("Proof-of-Signature"),
                    signer,
                    authority_cid: String::from("ProofOfAuthority proof cid                    "),
                    timestamp,
                    metadata: String::from("proof metadata"),
                },
                signature: signature.to_vec(),
                proof_cid: proof_cid.clone(),
            };
            instance.store_proof_of_signature(data.clone());

            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().signature,
                signature
            );
            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().proof_cid,
                proof_cid.clone()
            );

            assert_eq!(
                instance.posis.get(proof_cid.clone()).unwrap().message.name,
                String::from("Proof-of-Signature")
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signer,
                signer
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .authority_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .timestamp,
                timestamp
            );
            assert_eq!(
                instance
                    .posis
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .metadata,
                String::from("proof metadata")
            );
        }

        #[ink::test]
        fn test_store_proof_of_agreement() {
            let mut instance = DAOSignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 1,
                verifying_contract: [0; 20].into(),
            });
            let timestamp: u64 = 1711498247;
            let signature = <[u8; 65]>::from_hex("b05b5e2c46e33e744d474227755f4e6cf8308d75347f67107e3514a9ff7247d93178e100540a2778693459842fd0fedb99f6d17a8b50988ad0d2a634eb164e691b").unwrap();
            let proof_cid = String::from("ProofOfAgreement proof cid                    ");

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);
            store_proof_of_agreement(&mut instance);

            assert_eq!(
                instance.poags.get(proof_cid.clone()).unwrap().signature,
                signature
            );
            assert_eq!(
                instance.poags.get(proof_cid.clone()).unwrap().proof_cid,
                proof_cid.clone()
            );

            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .authority_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signature_cids
                    .len(),
                1
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .signature_cids[0],
                String::from("ProofOfSignature proof cid                    ")
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .timestamp,
                timestamp
            );
            assert_eq!(
                instance
                    .poags
                    .get(proof_cid.clone())
                    .unwrap()
                    .message
                    .metadata,
                String::from("proof metadata")
            );
        }

        #[ink::test]
        fn test_get_proof_of_authority() {
            let mut instance = DAOSignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 1,
                verifying_contract: [0; 20].into(),
            });
            let timestamp: u64 = 1711498247;
            let from = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let signature = <[u8; 65]>::from_hex("ef1e21a1e3d2c5fc8da61aaf4162dbd7480c7b9651fd564c4d7f2425d487279021ac4016d43ddad887f9951cf47e41003826bf6a9bcffd0824946a88b9158abd1c").unwrap();
            let proof_cid = String::from("ProofOfAuthority proof cid                    ");
            store_proof_of_authority(&mut instance);

            let proof = instance.get_proof_of_authority(proof_cid.clone());

            assert_eq!(proof.signature, signature);
            assert_eq!(proof.proof_cid, proof_cid.clone());
            assert_eq!(proof.message.name, String::from("Proof-of-Authority"));
            assert_eq!(proof.message.from, from);
            assert_eq!(
                proof.message.agreement_cid,
                String::from("agreement file cid                            ")
            );
            assert_eq!(proof.message.signers.len(), 1);
            assert_eq!(proof.message.signers[0].addr, from);
            assert_eq!(
                proof.message.signers[0].metadata,
                String::from("some metadata")
            );
            assert_eq!(proof.message.timestamp, timestamp);
            assert_eq!(proof.message.metadata, String::from("proof metadata"));
        }

        #[ink::test]
        fn test_get_proof_of_signature() {
            let mut instance = DAOSignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 1,
                verifying_contract: [0; 20].into(),
            });
            let timestamp: u64 = 1711498247;
            let signer = <[u8; 20]>::from_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
            let signature = <[u8; 65]>::from_hex("461d21a35edf1a3d926b1f9af11738211c846e450830a205e6d1801288195afd09c45e8bbde61fbf6a8e655df3133d9a8ec6495b1987abb77862d8beaefe12811c").unwrap();
            let proof_cid = String::from("ProofOfSignature proof cid                    ");

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);

            let proof = instance.get_proof_of_signature(proof_cid.clone());

            assert_eq!(proof.signature, signature);
            assert_eq!(proof.proof_cid, proof_cid.clone());

            assert_eq!(proof.message.name, String::from("Proof-of-Signature"));
            assert_eq!(proof.message.signer, signer);
            assert_eq!(
                proof.message.authority_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(proof.message.timestamp, timestamp);
            assert_eq!(proof.message.metadata, String::from("proof metadata"));
        }

        #[ink::test]
        fn test_get_proof_of_agreement() {
            let mut instance = DAOSignApp::new(EIP712Domain {
                name: "daosign".into(),
                version: "0.1.0".into(),
                chain_id: 1,
                verifying_contract: [0; 20].into(),
            });
            let timestamp: u64 = 1711498247;
            let signature = <[u8; 65]>::from_hex("b05b5e2c46e33e744d474227755f4e6cf8308d75347f67107e3514a9ff7247d93178e100540a2778693459842fd0fedb99f6d17a8b50988ad0d2a634eb164e691b").unwrap();
            let proof_cid = String::from("ProofOfAgreement proof cid                    ");

            store_proof_of_authority(&mut instance);
            store_proof_of_signature(&mut instance);
            store_proof_of_agreement(&mut instance);

            let proof = instance.get_proof_of_agreement(proof_cid.clone());

            assert_eq!(proof.signature, signature);
            assert_eq!(proof.proof_cid, proof_cid.clone());

            assert_eq!(
                proof.message.authority_cid,
                String::from("ProofOfAuthority proof cid                    ")
            );
            assert_eq!(proof.message.signature_cids.len(), 1);
            assert_eq!(
                proof.message.signature_cids[0],
                String::from("ProofOfSignature proof cid                    ")
            );
            assert_eq!(proof.message.timestamp, timestamp);
            assert_eq!(proof.message.metadata, String::from("proof metadata"));
        }
    }
}
