import express from "express";
import User from "../models/User.js";

const router = express.Router();

// Get all users
router.get("/", async (req, res) => {
  try {
    const users = await User.find({}, "-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Delete all users
router.delete("/", async (req, res) => {
  try {
    await User.deleteMany({});
    res.json({ message: "All users deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

export default router;
