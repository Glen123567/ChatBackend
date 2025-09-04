import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import { ethers } from "ethers"; // Although not directly used in *this* server.js, keeping for context if it were to interact with blockchain.
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from 'express-validator'; // For backend validation

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
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
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
    phone: { type: String, trim: true, default: null }, // Made optional
    dob: { type: String, trim: true, default: null }, // Made optional
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
    sender: { type: String, required: true }, // Username of sender
    receiver: { type: String, required: true }, // Username of receiver
    text: { type: String, required: true },
    txHash: { type: String, default: null }, // Placeholder for potential on-chain hash
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);


// -------------------- MIDDLEWARE --------------------
// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: "Authentication token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT verification error:", err);
      return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }
    req.user = user; // Attach user payload to request
    next();
  });
};


// -------------------- ROUTES --------------------
app.get("/api", (req, res) => {
  res.send("✅ SecureChat Backend is running!");
});

// Register
app.post(
  "/api/auth/register",
  [
    body('username').isLength({ min: 3, max: 20 }).withMessage('Username must be between 3 and 20 characters').matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long').matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/).withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    body('email').isEmail().withMessage('Invalid email address'),
    body('walletAddress').isEthereumAddress().withMessage('Invalid Ethereum wallet address'),
    body('phone').optional().isMobilePhone('any').withMessage('Invalid phone number'),
    body('dob').optional().isISO8601().withMessage('Invalid date of birth format (YYYY-MM-DD)')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: "Validation errors", errors: errors.array() });
    }

    try {
      const { username, password, email, phone, dob, walletAddress } = req.body;

      const existing = await User.findOne({ $or: [{ username }, { email }, { walletAddress }] });
      if (existing) return res.status(400).json({ success: false, message: "User already exists with this username, email or wallet address" });

      const user = new User({
        username,
        password,
        email: email.toLowerCase(),
        phone: phone || null, // Ensure optional fields are null if empty
        dob: dob || null,
        walletAddress: walletAddress.toLowerCase(),
      });

      await user.save();

      res.status(201).json({ success: true, message: "User registered successfully", user });
    } catch (err) {
      console.error("Register error:", err);
      res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
  }
);

// Login
app.post(
  "/api/auth/login",
  [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: "Validation errors", errors: errors.array() });
    }

    try {
      const { username, password } = req.body;

      const user = await User.findOne({ username });
      if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(401).json({ success: false, message: "Invalid credentials" });

      const token = jwt.sign({ id: user._id, username: user.username, walletAddress: user.walletAddress }, process.env.JWT_SECRET, { expiresIn: "2h" });

      res.json({ success: true, token, user });
    } catch (err) {
      console.error("Login error:", err);
      res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
  }
);

// Get All Users (Protected Route)
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}, 'username email walletAddress'); // Only return relevant user info
    res.json(users);
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Delete All Users (Admin-like, Protected Route - use with caution!)
app.delete("/api/users", authenticateToken, async (req, res) => {
  // Potentially add more robust admin-check here if req.user has an 'isAdmin' flag
  try {
    await User.deleteMany({});
    await Message.deleteMany({}); // Also delete all messages
    res.json({ success: true, message: "All users and messages deleted successfully" });
  } catch (err) {
    console.error("Delete all users error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});


// Get Messages between two users (Protected Route)
app.get("/api/messages/:u1/:u2", authenticateToken, async (req, res) => {
  try {
    const { u1, u2 } = req.params;

    // Ensure the requesting user is one of the participants
    if (req.user.username !== u1 && req.user.username !== u2) {
      return res.status(403).json({ success: false, message: "Unauthorized access to messages" });
    }

    const messages = await Message.find({
      $or: [
        { sender: u1, receiver: u2 },
        { sender: u2, receiver: u1 },
      ],
    }).sort('createdAt'); // Sort to get chronological order

    res.json(messages);
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Send Message (Protected Route)
app.post(
  "/api/messages",
  authenticateToken,
  [
    body('receiver').notEmpty().withMessage('Receiver is required'),
    body('text').notEmpty().withMessage('Message content cannot be empty')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: "Validation errors", errors: errors.array() });
    }

    try {
      const { receiver, text, txHash } = req.body;
      const sender = req.user.username; // Get sender from authenticated token

      // Basic check: prevent sending message to self unless explicitly allowed
      if (sender === receiver) {
        return res.status(400).json({ success: false, message: "Cannot send message to yourself" });
      }

      const message = new Message({ sender, receiver, text, txHash });
      await message.save();

      res.status(201).json({ success: true, message: "Message sent successfully", message });
    } catch (err) {
      console.error("Send message error:", err);
      res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
  }
);

// Delete All Messages (Admin-like, Protected Route - use with caution!)
app.delete("/api/messages", authenticateToken, async (req, res) => {
  // Potentially add more robust admin-check here if req.user has an 'isAdmin' flag
  try {
    await Message.deleteMany({});
    res.json({ success: true, message: "All messages deleted successfully" });
  } catch (err) {
    console.error("Delete all messages error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});


// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});