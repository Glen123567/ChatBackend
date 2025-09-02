import express from "express";
import chatContract from "../server.js";  // the ethers.js contract instance you created in Step 2

const router = express.Router();

// Register user on blockchain
router.post("/register", async (req, res) => {
  try {
    const { username, publicKey } = req.body;
    const tx = await chatContract.registerUser(username, publicKey);
    await tx.wait(); // wait for blockchain confirmation
    res.json({ success: true, txHash: tx.hash });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Send encrypted message on blockchain
router.post("/send", async (req, res) => {
  try {
    const { receiverWallet, encryptedContent } = req.body;
    const fee = await chatContract.messageFee(); // get fee from contract
    const tx = await chatContract.sendMessage(receiverWallet, encryptedContent, { value: fee });
    await tx.wait();
    res.json({ success: true, txHash: tx.hash });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Fetch conversation from blockchain
router.get("/conversation/:otherWallet", async (req, res) => {
  try {
    const { otherWallet } = req.params;
    const conversation = await chatContract.getConversation(otherWallet);
    res.json(conversation);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

export default router;
