require("dotenv").config();
const nearAPI = require("near-api-js");

const { connect, keyStores, utils, transactions } = nearAPI;

async function mintNFT() {
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

    // ✅ Properly formatted Token Metadata
    const tokenMetadata = get_default_metadata();

    // Convert deposit amount to yoctoNEAR
    const depositYocto = utils.format.parseNearAmount("0.01");

    // Define the function call transaction
    const functionCall = transactions.functionCall(
      "nft_mint", // Method name in contract
      {
        token_id: "0", // Example schema_id (update this)
        token_owner_id: ACCOUNT_ID,
        token_metadata: tokenMetadata, // NFT Account to be created
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

// ✅ Ensure metadata fields match Rust contract structure
function get_default_metadata() {
  return {
    title: "Olympus Mons",
    description: "The tallest mountain in the charted solar system.",
    media: "https://example.com/nft-image.png",
    media_hash: null,
    copies: 1,

    issued_at: new Date().toISOString(), // ✅ Timestamp when minted (ISO 8601)
    expires_at: null, // ✅ Expiry date (null if does not expire)
    starts_at: new Date().toISOString(), // ✅ Minting start date
    updated_at: new Date().toISOString(), // ✅ Last updated timestamp

    extra: '{"rarity":"Legendary","category":"Space"}',
    reference: "https://example.com/nft-metadata.json",
    reference_hash: null,
  };
}
// Execute the function
mintNFT();
