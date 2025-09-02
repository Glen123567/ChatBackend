import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const router = express.Router();

// ------------------- REGISTER -------------------
router.post("/register", async (req, res) => {
  try {
    const { username, password, email, phone, dob, walletAddress } = req.body;

    // Check required fields
    if (!username || !password || !email) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Username already taken" });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      email,
      phone,
      dob,
      walletAddress
    });

    await user.save();

    return res.json({ success: true, message: "User registered successfully", user });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

// ------------------- LOGIN -------------------
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    const token = jwt.sign({ username: user.username }, "supersecretkey", { expiresIn: "2h" });

    return res.json({ success: true, token, user });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});

export default router;
