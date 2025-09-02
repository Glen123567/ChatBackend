import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import { ethers } from "ethers";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

// -------------------- SETUP --------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// ... (existing imports and setup)

// -------------------- MONGO CONNECT --------------------
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
    socketTimeoutMS: 45000,        // Close sockets after 45 seconds of inactivity
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

// -------------------- MODELS --------------------
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, trim: true, minlength: 3, maxlength: 20 },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    phone: { type: String, trim: true },
    dob: { type: String, trim: true },
    walletAddress: { type: String, required: true, unique: true, lowercase: true, trim: true },
  },
  { timestamps: true }
);

// Pre-save hook to hash password ONLY if it's new or modified
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Method to transform user object for responses (removes password)
userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  return userObject;
};

const User = mongoose.model("User", userSchema);

// ... (Message schema and model)

// -------------------- ETHERS CONTRACT --------------------
// ... (contract setup, ensuring contractData and environment variables are loaded)

// -------------------- ROUTES --------------------

// Health check
app.get("/api/", (req, res) => {
  res.send("✅ SecureChat Backend is running!");
});

// Contract address (for frontend to know which contract to interact with)
app.get("/api/contract/address", (req, res) => {
  res.json({ address: contractData.address });
});

// ------------------- AUTH -------------------

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, email, phone, dob, walletAddress } = req.body;

    // Basic server-side validation (more comprehensive validation can be added)
    if (!username || !password || !email || !walletAddress) {
      return res
        .status(400)
        .json({ success: false, message: "Missing required fields: username, password, email, walletAddress." });
    }

    // Check for unique constraints explicitly to give better error messages
    const existingUserByUsername = await User.findOne({ username });
    if (existingUserByUsername) {
      return res.status(400).json({ success: false, message: "Username already taken." });
    }

    const existingUserByEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingUserByEmail) {
      return res.status(400).json({ success: false, message: "Email address already registered." });
    }

    const existingUserByWallet = await User.findOne({ walletAddress: walletAddress.toLowerCase() });
    if (existingUserByWallet) {
      return res.status(400).json({ success: false, message: "Wallet address already associated with another account." });
    }

    const user = new User({
      username,
      password, // Pre-save hook will hash this
      email: email.toLowerCase(),
      phone,
      dob,
      walletAddress: walletAddress.toLowerCase(),
    });

    await user.save();

    res.status(201).json({ success: true, message: "User registered successfully.", user }); // Use 201 for resource creation
  } catch (err) {
    console.error("Register error:", err);
    // Handle potential duplicate key errors not caught by explicit checks (e.g., race conditions)
    if (err.code === 11000) {
        return res.status(409).json({ success: false, message: "A user with this detail already exists (duplicate key error)." });
    }
    res.status(500).json({ success: false, message: "Server error during registration: " + err.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required." });
    }

    const user = await User.findOne({ username });
    if (!user)
      return res
        .status(401) // 401 Unauthorized for invalid credentials
        .json({ success: false, message: "Invalid username or password." });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res
        .status(401)
        .json({ success: false, message: "Invalid username or password." }); // Keep message generic for security

    const token = jwt.sign({ username: user.username, walletAddress: user.walletAddress }, process.env.JWT_SECRET, {
      expiresIn: "2h",
    });

    res.json({ success: true, token, user }); // `user` will be transformed by toJSON()
  } catch (err) {
    console.error("Login error:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error during login: " + err.message });
  }
});

// ------------------- USERS -------------------
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find({}); // toJSON() will exclude password
    res.json(users);
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ message: "Server error fetching users: " + err.message });
  }
});

// Delete ALL users and their messages (DEVELOPMENT/TESTING ONLY)
app.delete("/api/users", async (req, res) => {
  try {
    await User.deleteMany({});
    await Message.deleteMany({});
    res.json({ success: true, message: "All users and messages deleted." });
  } catch (err) {
    console.error("Delete all users error:", err);
    res.status(500).json({ message: "Server error deleting all users: " + err.message });
  }
});

// ... (MongoDB based messages routes - /api/messages POST and GET, DELETE)
// ... (Blockchain interaction routes, if applicable)

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
});