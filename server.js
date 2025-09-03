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

// Message Schema
const messageSchema = new mongoose.Schema(
  {
    sender: { type: String, required: true, trim: true },
    receiver: { type: String, required: true, trim: true },
    text: { type: String, required: true },
    txHash: { type: String, trim: true },
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);

// -------------------- MIDDLEWARE --------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// -------------------- ROUTES --------------------
app.get("/api", (req, res) => {
  res.send("✅ SecureChat Backend is running on Render!");
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, email, phone, dob, walletAddress } = req.body;

    console.log("Registration attempt:", { username, email, walletAddress });

    if (!username || !password || !email || !walletAddress) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields: username, password, email, walletAddress" 
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({
      $or: [
        { username: username.trim() },
        { email: email.toLowerCase().trim() },
        { walletAddress: walletAddress.toLowerCase().trim() }
      ]
    });

    if (existingUser) {
      let conflictField = "";
      if (existingUser.username === username.trim()) conflictField = "username";
      else if (existingUser.email === email.toLowerCase().trim()) conflictField = "email";
      else if (existingUser.walletAddress === walletAddress.toLowerCase().trim()) conflictField = "wallet address";
      
      return res.status(400).json({ 
        success: false, 
        message: `User with this ${conflictField} already exists` 
      });
    }

    // Validate wallet address format
    if (!ethers.isAddress(walletAddress)) {
      return res.status(400).json({
        success: false,
        message: "Invalid wallet address format"
      });
    }

    const user = new User({
      username: username.trim(),
      password,
      email: email.toLowerCase().trim(),
      phone: phone?.trim(),
      dob: dob?.trim(),
      walletAddress: walletAddress.toLowerCase().trim(),
    });

    const savedUser = await user.save();
    console.log("User registered successfully:", savedUser.username);

    res.status(201).json({ 
      success: true, 
      message: "User registered successfully", 
      user: savedUser 
    });
  } catch (err) {
    console.error("Register error:", err);
    
    // Handle MongoDB duplicate key errors
    if (err.code === 11000) {
      const field = Object.keys(err.keyValue)[0];
      return res.status(400).json({
        success: false,
        message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "Registration failed: " + err.message 
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log("Login attempt for username:", username);

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const user = await User.findOne({ username: username.trim() });
    if (!user) {
      console.log("User not found:", username);
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      console.log("Password mismatch for user:", username);
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username }, 
      process.env.JWT_SECRET, 
      { expiresIn: "24h" }
    );

    console.log("Login successful for user:", username);

    res.json({ 
      success: true, 
      token, 
      user: user.toJSON()
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Login failed: " + err.message 
    });
  }
});

// Get all users (for contact list)
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ username: 1 });
    console.log(`Fetched ${users.length} users`);
    res.json(users);
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Failed to fetch users: " + err.message 
    });
  }
});

// Delete all users (admin function)
app.delete("/api/users", async (req, res) => {
  try {
    const result = await User.deleteMany({});
    console.log(`Deleted ${result.deletedCount} users`);
    res.json({ 
      success: true, 
      message: `Deleted ${result.deletedCount} users`,
      deletedCount: result.deletedCount
    });
  } catch (err) {
    console.error("Delete users error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Failed to delete users: " + err.message 
    });
  }
});

// Get messages between two users
app.get("/api/messages/:user1/:user2", async (req, res) => {
  try {
    const { user1, user2 } = req.params;
    
    const messages = await Message.find({
      $or: [
        { sender: user1, receiver: user2 },
        { sender: user2, receiver: user1 }
      ]
    }).sort({ createdAt: 1 });

    console.log(`Fetched ${messages.length} messages between ${user1} and ${user2}`);
    res.json(messages);
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Failed to fetch messages: " + err.message 
    });
  }
});

// Send message
app.post("/api/messages", async (req, res) => {
  try {
    const { sender, receiver, text, txHash } = req.body;

    if (!sender || !receiver || !text) {
      return res.status(400).json({
        success: false,
        message: "Sender, receiver, and text are required"
      });
    }

    const message = new Message({
      sender: sender.trim(),
      receiver: receiver.trim(),
      text: text.trim(),
      txHash: txHash || null
    });

    const savedMessage = await message.save();
    console.log(`Message sent from ${sender} to ${receiver}`);

    res.status(201).json({
      success: true,
      message: "Message sent successfully",
      data: savedMessage
    });
  } catch (err) {
    console.error("Send message error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to send message: " + err.message
    });
  }
});

// Delete all messages (admin function)
app.delete("/api/messages", async (req, res) => {
  try {
    const result = await Message.deleteMany({});
    console.log(`Deleted ${result.deletedCount} messages`);
    res.json({
      success: true,
      message: `Deleted ${result.deletedCount} messages`,
      deletedCount: result.deletedCount
    });
  } catch (err) {
    console.error("Delete messages error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to delete messages: " + err.message
    });
  }
});

// Get user profile (protected route)
app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id, '-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }
    res.json({ success: true, user });
  } catch (err) {
    console.error("Get profile error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to fetch profile: " + err.message
    });
  }
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected"
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found"
  });
});

// ------------------- START SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
  console.log(`📡 Health check available at: http://localhost:${PORT}/api/health`);
});