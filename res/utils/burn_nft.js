require("dotenv").config();
const nearAPI = require("near-api-js");

const { connect, keyStores, utils, transactions } = nearAPI;

async function burnNFT() {
  try {
    // Load environment variables
    const ACCOUNT_ID = process.env.NEAR_ACCOUNT_ID;
    const PRIVATE_KEY = process.env.PRIVATE_KEY;
    const NFT_ACCOUNT_ID = process.env.NFT_ACCOUNT_ID;

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

    // Load account
    const account = await near.account(ACCOUNT_ID);

    // Convert deposit amount to yoctoNEAR
    const depositYocto = utils.format.parseNearAmount("0.01");

    // Define the function call transaction
    const functionCall = transactions.functionCall(
      "nft_burn", // Method name in contract
      {
        token_id: "0", // Example schema_id (update this)
      },
      100000000000000, // Gas (100 Tgas)
      depositYocto // Attach the required deposit
    );

    // Send transaction
    const response = await account.signAndSendTransaction({
      receiverId: NFT_ACCOUNT_ID,
      actions: [functionCall],
    });

    console.log("✅ Transaction sent successfully!");
    console.log("📜 Transaction hash:", response.transaction.hash);
    console.log(`🔗 Explorer link: https://explorer.testnet.near.org/transactions/${response.transaction.hash}`);
  } catch (error) {
    console.error("❌ Error sending transaction:", error);
  }
}

// Execute the function
burnNFT();
