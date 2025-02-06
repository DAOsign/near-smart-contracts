require("dotenv").config();
const nearAPI = require("near-api-js");

const { connect, keyStores, utils, transactions } = nearAPI;
// Load environment variables
const ACCOUNT_ID = process.env.NEAR_ACCOUNT_ID;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const CONTRACT_ID = process.env.APP_CONTRACT_ID;

async function CREATE_SCHEMA() {
  try {
    if (!ACCOUNT_ID || !PRIVATE_KEY || !CONTRACT_ID) {
      throw new Error("Missing environment variables. Check your .env file.");
    }

    // Setup NEAR connection
    const keyStore = new keyStores.InMemoryKeyStore();
    const keyPair = nearAPI.utils.KeyPair.fromString(PRIVATE_KEY);
    await keyStore.setKey("testnet", ACCOUNT_ID, keyPair);

    const near = await connect({
      networkId: "testnet",
      keyStore,
      nodeUrl: "https://rpc.testnet.near.org",
      walletUrl: "https://wallet.testnet.near.org",
      helperUrl: "https://helper.testnet.near.org",
      explorerUrl: "https://explorer.testnet.near.org",
    });

    let pk = publicKeyToBytes(keyPair.getPublicKey());
    // Load account
    const account = await near.account(ACCOUNT_ID);

    let message = get_message(); // Pass creator

    signature = signMessage(message, keyPair);

    const data = {
      attestation_id: 0,
      creator: ACCOUNT_ID,
      created_at: 0,
      signature: signature,
    };

    // Convert deposit amount to yoctoNEAR
    const depositYocto = utils.format.parseNearAmount("0.3");

    // Define the function call transaction
    const functionCall = transactions.functionCall(
      "store_pos",
      {
        data: data,
      },
      100000000000000, // Gas (100 Tgas)
      depositYocto // No deposit needed
    );

    // Send transaction
    const response = await account.signAndSendTransaction({
      receiverId: CONTRACT_ID,
      actions: [functionCall],
    });

    console.log("✅ Transaction sent successfully!");
    console.log("📜 Transaction hash:", response.transaction.hash);
    console.log(`🔗 Explorer link: https://explorer.testnet.near.org/transactions/${response.transaction.hash}`);
  } catch (error) {
    console.error("❌ Error sending transaction:", error);
    console.log(error.transaction_outcome);
  }
}

function signMessage(message, keyPair) {
  const messageBytes = Buffer.from(JSON.stringify(message)); // Convert JSON to byte array
  const signature = keyPair.sign(messageBytes).signature; // Extract signature bytes
  return Array.from(signature); // Convert Buffer to an array of numbers
}

function get_message(signatory) {
  // Create the Attestation object
  return {
    attestation_id: 0,
    creator: ACCOUNT_ID,
  };
}

function publicKeyToBytes(publicKey) {
  return Array.from(publicKey.data);
}

// Execute the function
CREATE_SCHEMA();
