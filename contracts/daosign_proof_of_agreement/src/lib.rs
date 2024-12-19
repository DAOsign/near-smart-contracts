use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
// use near_sdk::near_bindgen;
use serde::{Deserialize, Serialize};

use schemars::JsonSchema;

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
pub struct ProofOfAgreement {
    pub attestation_id: u128,
    pub signatures: Vec<u8>,
}
