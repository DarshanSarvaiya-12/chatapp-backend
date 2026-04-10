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
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many attempts. Try again in 15 minutes." }
});

// ── MONGODB ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("DB Error:", err));

// ── SCHEMAS ──
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

const messageSchema = new mongoose.Schema({
  roomId: String,
  username: String,
  text: String,
  timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

// ── VALIDATION ──
function validateUsername(u) {
  return /^[a-zA-Z0-9_]{3,20}$/.test(u);
}
function validatePassword(p) {
  return p && p.length >= 4 && p.length <= 50;
}
function validateMessage(t) {
  return t && t.trim().length > 0 && t.trim().length <= 500;
}
function getRoomId(userA, userB) {
  return [userA, userB].sort().join("_");
}

// ── MIDDLEWARE ──
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ── REGISTER ──
app.post("/register", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "All fields required" });
    if (!validateUsername(username))
      return res.status(400).json({ error: "Username: 3-20 chars, letters/numbers/underscore only" });
    if (!validatePassword(password))
      return res.status(400).json({ error: "Password must be 4-50 characters" });
    const exists = await User.findOne({ username });
    if (exists)
      return res.status(400).json({ error: "Username already taken" });
    const hashed = await bcrypt.hash(password, 10);
    await new User({ username, password: hashed }).save();
    const token = jwt.sign({ username }, process.env.JWT_SECRET);
    res.json({ token, username });
  } catch {
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
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ── GET ALL USERS ──
app.get("/users", authMiddleware, async (req, res) => {
  try {
    const users = await User.find(
      { username: { $ne: req.user.username } },
      { username: 1, _id: 0 }
    );
    res.json(users);
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ── GET MESSAGES FOR A ROOM ──
app.get("/messages/:roomId", authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({ roomId: req.params.roomId })
      .sort({ timestamp: 1 }).limit(50);
    res.json(messages);
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ── SOCKET.IO ──
io.on("connection", (socket) => {
  console.log("Connected:", socket.id);

  // Join private room
  socket.on("join_room", ({ userA, userB }) => {
    const roomId = getRoomId(userA, userB);
    socket.join(roomId);
    console.log(`${userA} joined room: ${roomId}`);
  });

  // Send message to room
  socket.on("send_message", async (data) => {
    if (!data.username || !data.roomId || !validateMessage(data.text)) return;
    const cleanText = data.text.trim()
      .replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const msg = new Message({
      roomId: data.roomId,
      username: data.username,
      text: cleanText
    });
    await msg.save();
    io.to(data.roomId).emit("receive_message", {
      username: data.username,
      text: cleanText,
      timestamp: msg.timestamp
    });
  });

  socket.on("disconnect", () => {
    console.log("Disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on port", PORT));