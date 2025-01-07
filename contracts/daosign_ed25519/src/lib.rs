use ed25519_dalek::{PublicKey, Signature, Verifier};

pub fn recover(public_key: PublicKey, signature: Signature, message: &[u8]) -> bool {
    public_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    // use bs58;
    use ed25519_dalek::{Keypair, Signer};
    use rand::rngs::OsRng;

    fn create_signer() -> Keypair {
        let mut csprng = OsRng {};
        Keypair::generate(&mut csprng)
    }
    fn sign_transaction(message: &[u8], signer: &Keypair) -> Signature {
        println!("message {:?}", message);
        signer.sign(message)
    }

    // #[test]

    // fn test_hardcoded_signer() {
    //     // Example private key (Base58 encoded; you may replace this with your actual private key)
    //     let private_key_str = "ed25519:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    //     let private_key_base58 = private_key_str
    //         .strip_prefix("ed25519:")
    //         .expect("Invalid key format");

    //     let private_key_bytes = bs58::decode(private_key_base58)
    //         .into_vec()
    //         .expect("Failed to decode Base58 private key");

    //     // Ensure the private key is 32 bytes long
    //     assert_eq!(private_key_bytes.len(), 64, "Private key must be 64 bytes");

    //     // Create the keypair from the private key bytes
    //     let keypair = Keypair::from_bytes(&private_key_bytes).expect("Failed to create Keypair");

    //     // Example: Signing a message
    //     let message = b"abcdef123456789";
    //     let signature: Signature = keypair.sign(message);

    //     //recover the transaction
    //     let success = recover(keypair.public, signature, message);

    //     // Assert that the signature is valid
    //     assert!(success, "The signature should be valid.");
    // }

    #[test]
    fn test_signer() {
        // Create a signer (keypair)
        let signer = create_signer();

        // Simulated transaction message
        let message = b"abcdef123456789";

        // Sign the transaction
        let signature = sign_transaction(message, &signer);

        //recover the transaction
        let success = recover(signer.public, signature, message);

        // Assert that the signature is valid
        assert!(success, "The signature should be valid.");
    }
}
