import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import { ethers } from "ethers";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from 'express-validator';

dotenv.config();

// -------------------- SETUP --------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// -------------------- MONGO CONNECT --------------------
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

// -------------------- MODELS --------------------
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, trim: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    phone: { type: String, trim: true, default: null },
    dob: { type: String, trim: true, default: null },
    walletAddress: { type: String, required: true, unique: true, lowercase: true, trim: true },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model("User", userSchema);

const messageSchema = new mongoose.Schema(
  {
    sender: { type: String, required: true },
    receiver: { type: String, required: true },
    text: { type: String, required: true },
    txHash: { type: String, default: null },
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);

// -------------------- MIDDLEWARE --------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// -------------------- ROUTES --------------------
app.get("/api", (req, res) => res.send("✅ SecureChat Backend is running!"));

app.post("/api/auth/register",
  [ body('username').isLength({ min: 3 }), body('password').isLength({ min: 8 }), body('email').isEmail(), body('walletAddress').isEthereumAddress() ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    try {
      const { username, password, email, phone, dob, walletAddress } = req.body;
      const existing = await User.findOne({ $or: [{ username }, { email }, { walletAddress: walletAddress.toLowerCase() }] });
      if (existing) return res.status(400).json({ success: false, message: "User already exists with this username, email or wallet address" });
      const user = new User({ username, password, email, phone, dob, walletAddress: walletAddress.toLowerCase() });
      await user.save();
      res.status(201).json({ success: true, user });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  }
);

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ success: false, message: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "2h" });
    res.json({ success: true, token, user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// --- NEW ROUTE TO CHECK IF WALLET EXISTS ---
app.post("/api/auth/check-wallet", 
  [ body('walletAddress').isEthereumAddress().withMessage('Invalid wallet address') ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    try {
      const { walletAddress } = req.body;
      const user = await User.findOne({ walletAddress: walletAddress.toLowerCase() });
      res.json({ success: true, isRegistered: !!user });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

app.get("/api/users", authenticateToken, async (req, res) => {
  try { const users = await User.find({}, 'username walletAddress'); res.json(users); } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.delete("/api/users", authenticateToken, async (req, res) => {
  try { await User.deleteMany({}); await Message.deleteMany({}); res.json({ success: true, message: "All users and messages deleted" }); } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.get("/api/messages/:u1/:u2", authenticateToken, async (req, res) => {
  try {
    const { u1, u2 } = req.params;
    const messages = await Message.find({ $or: [{ sender: u1, receiver: u2 }, { sender: u2, receiver: u1 }] }).sort('createdAt');
    res.json(messages);
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.post("/api/messages", authenticateToken, [ body('receiver').notEmpty(), body('text').notEmpty() ], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
  try {
    const { receiver, text, txHash } = req.body;
    const sender = req.user.username;
    const message = new Message({ sender, receiver, text, txHash });
    await message.save();
    res.status(201).json({ success: true, message });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));