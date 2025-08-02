const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

const directorySchema = new mongoose.Schema({
  name: { type: String, required: true },
});
const Directory = mongoose.model("Directory", directorySchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
const User = mongoose.model("User", userSchema);

const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  completed: { type: Boolean, default: false },
  important: { type: Boolean, default: false },
  deadline: Date,
  dirId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Directory",
    required: true,
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});
const Task = mongoose.model("Task", taskSchema);

const auth = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).send({ message: "Access denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).send({ message: "Invalid token" });
  }
};

app.post("/api/users", async (req, res) => {
  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).send({ message: "User created successfully", user });
  } catch (err) {
    res.status(400).send({ error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send({ message: "User not found" });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).send({ message: "Invalid password" });
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  res.send({ message: "Login successful", token });
});

app.get("/api/users", async (req, res) => {
  const users = await User.find();
  res.send(users);
});

app.put("/api/users/:id", async (req, res) => {
  const { password, ...rest } = req.body;
  if (password) {
    const salt = await bcrypt.genSalt(10);
    rest.password = await bcrypt.hash(password, salt);
  }
  const user = await User.findByIdAndUpdate(req.params.id, rest, { new: true });
  res.send(user);
});

app.delete("/api/users/:id", async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.send({ message: "User deleted" });
});

app.get("/api/users/:id/tasks", async (req, res) => {
  const tasks = await Task.find({ userId: req.params.id });
  res.send(tasks);
});

app.post("/api/directories", async (req, res) => {
  const directory = new Directory(req.body);
  await directory.save();
  res.status(201).send(directory);
});

app.get("/api/directories", async (req, res) => {
  const directories = await Directory.find();
  res.send(directories);
});

app.put("/api/directories/:id", async (req, res) => {
  const directory = await Directory.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.send(directory);
});

app.delete("/api/directories/:id", async (req, res) => {
  await Directory.findByIdAndDelete(req.params.id);
  res.send({ message: "Directory deleted" });
});

app.post("/api/tasks", auth, async (req, res) => {
  const task = new Task({ ...req.body, userId: req.user.userId });
  await task.save();
  res.status(201).send(task);
});

app.get("/api/tasks", async (req, res) => {
  const tasks = await Task.find().populate("dirId userId");
  res.send(tasks);
});

app.get("/api/directories/:dirId/tasks", async (req, res) => {
  const tasks = await Task.find({ dirId: req.params.dirId });
  res.send(tasks);
});

app.put("/api/tasks/:id", async (req, res) => {
  const task = await Task.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.send(task);
});

app.delete("/api/tasks/:id", async (req, res) => {
  await Task.findByIdAndDelete(req.params.id);
  res.send({ message: "Task deleted" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
