require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();
app.use(cors());
app.use(express.json());
app.use(helmet());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// ── RATE LIMITING ──
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 attempts
  message: { error: "Too many attempts. Try again in 15 minutes." }
});

// ── CONNECT MONGODB ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("DB Error:", err));

// ── USER SCHEMA ──
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

// ── MESSAGE SCHEMA ──
const messageSchema = new mongoose.Schema({
  username: String,
  text: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

// ── INPUT VALIDATION ──
function validateUsername(username) {
  // Only letters, numbers, underscore. 3-20 chars
  const regex = /^[a-zA-Z0-9_]{3,20}$/;
  return regex.test(username);
}

function validatePassword(password) {
  // Min 4 chars, max 50
  return password && password.length >= 4 && password.length <= 50;
}

function validateMessage(text) {
  // Not empty, max 500 chars
  return text && text.trim().length > 0 && text.trim().length <= 500;
}

// ── REGISTER ──
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: "All fields required" });

    if (!validateUsername(username))
      return res.status(400).json({ error: "Username must be 3-20 characters. Only letters, numbers, underscore allowed." });

    if (!validatePassword(password))
      return res.status(400).json({ error: "Password must be 4-50 characters" });

    const exists = await User.findOne({ username });
    if (exists)
      return res.status(400).json({ error: "Username already taken" });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashed });
    await user.save();

    const token = jwt.sign({ username }, process.env.JWT_SECRET);
    res.json({ token, username });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── LOGIN ──
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: "All fields required" });

    if (!validateUsername(username))
      return res.status(400).json({ error: "Invalid username format" });

    const user = await User.findOne({ username });
    if (!user)
      return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ username }, process.env.JWT_SECRET);
    res.json({ token, username });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ── LOAD MESSAGES ──
app.get("/messages", async (req, res) => {
  const messages = await Message.find()
    .sort({ timestamp: 1 }).limit(50);
  res.json(messages);
});

// ── SOCKET.IO ──
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("send_message", async (data) => {
    // Validate message on server side too
    if (!data.username || !validateMessage(data.text)) return;

    // Sanitize — strip HTML tags
    const cleanText = data.text
      .trim()
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    const msg = new Message({
      username: data.username,
      text: cleanText
    });
    await msg.save();

    io.emit("receive_message", {
      username: data.username,
      text: cleanText,
      timestamp: msg.timestamp
    });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log("Server running on port", PORT));