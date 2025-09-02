import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: String,
  phone: String,
  dob: String,
  walletAddress: { type: String, required: true },
}, { timestamps: true });

export default mongoose.model("User", userSchema);
