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
    phone: { type: String, trim: true },
    dob: { type: String, trim: true },
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

// -------------------- ROUTES --------------------
app.get("/api", (req, res) => {
  res.send("✅ SecureChat Backend is running on Render!");
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, email, phone, dob, walletAddress } = req.body;

    if (!username || !password || !email || !walletAddress) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    const existing = await User.findOne({ $or: [{ username }, { email }, { walletAddress }] });
    if (existing) return res.status(400).json({ success: false, message: "User already exists" });

    const user = new User({
      username,
      password,
      email: email.toLowerCase(),
      phone,
      dob,
      walletAddress: walletAddress.toLowerCase(),
    });

    await user.save();

    res.status(201).json({ success: true, message: "User registered successfully", user });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "2h" });

    res.json({ success: true, token, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
});
