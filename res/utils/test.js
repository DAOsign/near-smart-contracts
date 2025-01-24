// nearSender.js

// Ensure that the NEAR API library is loaded and ready
window.onload = async function () {
  const nearAPI = await window.nearApi;
  console.log(window);
  const { connect, WalletConnection, keyStores, KeyPair, utils } = await nearAPI;

  const account_Id = "user.testnet"; // Replace with your account ID
  const privateKey = "ed25519:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // Replace with your private key

  const customKeyStore = new keyStores.InMemoryKeyStore();

  // Function to add a key to the keystore
  async function addKeyToKeystore(accountId, privateKey) {
    const keyPair = KeyPair.fromString(privateKey);

    await customKeyStore.setKey("testnet", accountId, keyPair);
    console.log(`Key for account ${accountId} added to custom keyStore.`);
  }

  const nearConfig = {
    networkId: "testnet",
    keyStore: customKeyStore,
    nodeUrl: "https://rpc.testnet.near.org",
    walletUrl: "https://wallet.testnet.near.org",
    helperUrl: "https://helper.testnet.near.org",
  };

  // Function to initialize the NEAR contract
  async function initContract() {
    await addKeyToKeystore(account_Id, privateKey);

    const near = await connect(nearConfig);
    const wallet = new WalletConnection(near, "my-app");

    console.log("Connected to account:");

    return { wallet };
  }

  // Function to sign a message
  function signMessage(message, keyPair) {
    console.log("message", JSON.stringify(message));

    const messageBytes = new TextEncoder().encode(message);

    console.log("messageBytes", messageBytes);
    return keyPair.sign(messageBytes);
  }

  // Function to send a signed message
  async function signAndSendMessage(message) {
    let wallet = await initContract();

    const keyPair = KeyPair.fromString(privateKey);

    const signature = signMessage(message.text, keyPair);
    console.log("Message signed:", signature);

    // Here you would add logic to send the signed message to
    // Your smart contract. For example:
    // await wallet.account().signAndSendTransaction({
    //     receiverId: "receiver_account.testnet", // Replace with the intended receiver's account
    //     actions: [
    //         {
    //             type: "FunctionCall",
    //             params: {
    //                 methodName: "your_method_name", // Your contract method
    //                 args: { message: message, signature: signature }, // Include message and its signature
    //                 gas: "20000000000000", // Amount of gas to use for the transaction
    //                 deposit: "0", // Amount of near tokens to send with the transaction
    //             },
    //         },
    //     ],
    // });

    console.log(`Message sent: ${JSON.stringify(message.text)}`);
  }

  // Function to initiate message sending
  window.sendMessage = function () {
    const message = {
      text: document.getElementById("messageInput").value,
    };
    signAndSendMessage(message).catch(console.error);
  };

  console.log("NEAR API is ready.");
};
