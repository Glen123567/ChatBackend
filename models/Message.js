import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  text: { type: String, required: true },
  txHash: { type: String, required: true },
}, { timestamps: true });

export default mongoose.model("Message", messageSchema);
