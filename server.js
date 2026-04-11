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
app.use(express.json({ limit: "10kb" }));
app.set("trust proxy", 1);
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
  password: String,
  publicKey: String,
  encryptedPrivateKey: String
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
  return t && t.trim().length > 0 && t.trim().length <= 2000;
}
function getRoomId(a, b) {
  return [a, b].sort().join("_");
}

// ── AUTH MIDDLEWARE ──
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
    const { username, password, publicKey, encryptedPrivateKey } = req.body;

    if (!username || !password || !publicKey || !encryptedPrivateKey)
      return res.status(400).json({ error: "All fields required" });

    if (!validateUsername(username))
      return res.status(400).json({ error: "Username: 3-20 chars, letters/numbers/underscore only" });

    if (!validatePassword(password))
      return res.status(400).json({ error: "Password must be 4-50 characters" });

    const exists = await User.findOne({ username });
    if (exists)
      return res.status(400).json({ error: "Username already taken" });

    const hashed = await bcrypt.hash(password, 10);
    await new User({
      username,
      password: hashed,
      publicKey,
      encryptedPrivateKey
    }).save();

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
    res.json({
      token,
      username,
      publicKey: user.publicKey,
      encryptedPrivateKey: user.encryptedPrivateKey
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ── GET ALL USERS WITH PUBLIC KEYS ──
app.get("/users", authMiddleware, async (req, res) => {
  try {
    const users = await User.find(
      { username: { $ne: req.user.username } },
      { username: 1, publicKey: 1, _id: 0 }
    );
    res.json(users);
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ── GET SINGLE USER PUBLIC KEY ──
app.get("/user/:username", authMiddleware, async (req, res) => {
  try {
    const user = await User.findOne(
      { username: req.params.username },
      { username: 1, publicKey: 1, _id: 0 }
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// ── GET MESSAGES ──
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

  socket.on("join_room", ({ userA, userB }) => {
    const roomId = getRoomId(userA, userB);
    socket.join(roomId);
  });

  socket.on("send_message", async (data) => {
    if (!data.username || !data.roomId || !validateMessage(data.text)) return;

    const msg = new Message({
      roomId: data.roomId,
      username: data.username,
      text: data.text
    });
    await msg.save();

    io.to(data.roomId).emit("receive_message", {
      username: data.username,
      text: data.text,
      timestamp: msg.timestamp
    });
  });

  socket.on("disconnect", () => {
    console.log("Disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on port", PORT));