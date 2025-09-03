import fs from "fs";
import path from "path";
import { fileURLToPath } = > from "url";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

// -------------------- SETUP --------------------
// Not strictly needed for a backend-only file, but good practice
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

// User Schema
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, trim: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    phone: { type: String, trim: true, default: "" }, // Made optional
    dob: { type: String, trim: true, default: "" },   // Made optional
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
    sender: { type: String, required: true },
    receiver: { type: String, required: true },
    text: { type: String, required: true },
    txHash: { type: String, default: "" }, // Placeholder for blockchain hash
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);


// -------------------- MIDDLEWARE --------------------

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (token == null) return res.status(401).json({ success: false, message: "Authentication token required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid or expired token" });
    req.user = user; // Attach user payload to request
    next();
  });
};


// -------------------- ROUTES --------------------
app.get("/api", (req, res) => {
  res.send("✅ SecureChat Backend is running on Render!");
});

// --- Auth Endpoints ---

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, email, phone, dob, walletAddress } = req.body;

    if (!username || !password || !email || !walletAddress) {
      return res.status(400).json({ success: false, message: "Missing required fields: username, password, email, walletAddress" });
    }

    const existing = await User.findOne({ $or: [{ username }, { email }, { walletAddress }] });
    if (existing) {
        let message = "User already exists.";
        if (existing.username === username) message = "Username already taken.";
        else if (existing.email === email) message = "Email already registered.";
        else if (existing.walletAddress === walletAddress) message = "Wallet address already registered.";
        return res.status(400).json({ success: false, message });
    }

    const user = new User({
      username,
      password,
      email: email.toLowerCase(),
      phone: phone || "", // Ensure it's not undefined if not provided
      dob: dob || "",     // Ensure it's not undefined if not provided
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

    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: "2h" });

    res.json({ success: true, token, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});


// --- User Endpoints (Protected) ---

// Get all users
app.get("/api/users", authenticateToken, async (req, res) => {
  try {
    const users = await User.find().select("-password"); // Exclude passwords
    res.json(users);
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// Delete all users (for development/testing)
app.delete("/api/users", authenticateToken, async (req, res) => {
  try {
    await User.deleteMany({});
    await Message.deleteMany({}); // Also delete all messages
    res.json({ success: true, message: "All users and messages deleted" });
  } catch (err) {
    console.error("Delete all users error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});


// --- Message Endpoints (Protected) ---

// Get messages between two users
app.get("/api/messages/:u1/:u2", authenticateToken, async (req, res) => {
    try {
        const { u1, u2 } = req.params;
        const messages = await Message.find({
            $or: [
                { sender: u1, receiver: u2 },
                { sender: u2, receiver: u1 },
            ],
        }).sort({ createdAt: 1 }); // Sort by creation time

        res.json(messages);
    } catch (err) {
        console.error("Get messages error:", err);
        res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
});

// Send a message
app.post("/api/messages", authenticateToken, async (req, res) => {
    try {
        const { sender, receiver, text, txHash } = req.body;

        if (!sender || !receiver || !text) {
            return res.status(400).json({ success: false, message: "Missing required fields: sender, receiver, text" });
        }

        // Basic check if sender and receiver exist (optional, but good practice)
        const senderExists = await User.findOne({ username: sender });
        const receiverExists = await User.findOne({ username: receiver });
        if (!senderExists || !receiverExists) {
            return res.status(400).json({ success: false, message: "Sender or receiver does not exist." });
        }

        const message = new Message({
            sender,
            receiver,
            text,
            txHash: txHash || "",
        });

        await message.save();
        res.status(201).json({ success: true, message: "Message sent", message });
    } catch (err) {
        console.error("Send message error:", err);
        res.status(500).json({ success: false, message: "Server error: " + err.message });
    }
});

// Delete all messages (for development/testing)
app.delete("/api/messages", authenticateToken, async (req, res) => {
  try {
    await Message.deleteMany({});
    res.json({ success: true, message: "All messages deleted" });
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