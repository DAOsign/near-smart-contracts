require("dotenv").config();
const nearAPI = require("near-api-js");

const { connect, keyStores, utils, transactions } = nearAPI;

async function deployNFT() {
  try {
    // Load environment variables
    const ACCOUNT_ID = process.env.NEAR_ACCOUNT_ID;
    const PRIVATE_KEY = process.env.PRIVATE_KEY;
    const CONTRACT_ID = process.env.FACTORY_CONTRACT_ID;
    const NFT_ACCOUNT_ID = process.env.NFT_ACCOUNT_ID;
    const DEPOSIT_AMOUNT = process.env.DEPOSIT_AMOUNT || "10"; // Default 10 NEAR

    if (!ACCOUNT_ID || !PRIVATE_KEY || !CONTRACT_ID || !NFT_ACCOUNT_ID) {
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

    // Load account
    const account = await near.account(ACCOUNT_ID);

    // Convert deposit amount to yoctoNEAR
    const depositYocto = utils.format.parseNearAmount(DEPOSIT_AMOUNT);

    // Define the function call transaction
    const functionCall = transactions.functionCall(
      "deploy_nft", // Method name in contract
      {
        schema_id: 1, // Example schema_id (update this)
        nft_acc: NFT_ACCOUNT_ID, // NFT Account to be created
      },
      100000000000000, // Gas (100 Tgas)
      depositYocto // Attach the required deposit
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
  }
}

// Execute the function
deployNFT();
