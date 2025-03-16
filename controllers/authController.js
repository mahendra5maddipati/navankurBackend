const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const redisClient = require("../config/redis");
const logger = require("../config/logger");
const { check, validationResult } = require("express-validator");
const { sendResetEmail } = require("../utils/emailServices");

const register = async (req, res) => {
  await check("username", "Username is required").notEmpty().run(req);
  await check("email", "Please include a valid email").isEmail().run(req);
  await check("password", "Password must be 6 or more characters").isLength({ min: 6 }).run(req);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors during registration", { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      logger.warn("User already exists", { email });
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ username, email, password: hashedPassword });

    await user.save();
    logger.info("User registered successfully", { username, email });
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    logger.error("Server error during registration", { error: err.message });
    res.status(500).json({ message: "Server error" });
  }
};

const login = async (req, res) => {
  await check("email", "Please include a valid email").isEmail().run(req);
  await check("password", "Password is required").notEmpty().run(req);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors during login", { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn("Invalid credentials", { email });
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn("Invalid credentials", { email });
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    // Store session in Redis
    await redisClient.setex(user._id.toString(), 3600, token);

    logger.info("User logged in successfully", { email });
    res.json({ token });
  } catch (err) {
    logger.error("Server error during login", { error: err.message });
    res.status(500).json({ message: "Server error" });
  }
};

const logout = async (req, res) => {
  try {
    await redisClient.del(req.user.id);
    logger.info("User logged out successfully", { userId: req.user.id });
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    logger.error("Server error during logout", { error: err.message });
    res.status(500).json({ message: "Server error" });
  }
};

const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      logger.warn("User not found", { userId: req.user.id });
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (err) {
    logger.error("Server error during fetching profile", { error: err.message });
    res.status(500).json({ message: "Server error" });
  }
};

const requestPasswordReset = async (req, res) => {
  await check("email", "Please include a valid email").isEmail().run(req);
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors during password reset request", { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn("User not found", { email });
      return res.status(400).json({ message: "User not found" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    await redisClient.setex(`reset_${user._id}`, 3600, token);

    await sendResetEmail(email, token);
    logger.info("Password reset email sent", { email });
    res.json({ message: "Password reset email sent" });
  } catch (err) {
    logger.error("Server error during password reset request", { error: err.message });
    res.status(500).json({ message: "Server error" });
  }
};

const resetPassword = async (req, res) => {
  await check("token", "Token is required").notEmpty().run(req);
  await check("newPassword", "Password must be 6 or more characters").isLength({ min: 6 }).run(req);
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors during password reset", { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }

  const { token, newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const sessionToken = await redisClient.get(`reset_${decoded.id}`);
    if (!sessionToken) {
      logger.warn("Invalid or expired token", { token });
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });

    await redisClient.del(`reset_${decoded.id}`);
    logger.info("Password reset successful", { userId: decoded.id });
    res.json({ message: "Password reset successful" });
  } catch (err) {
    logger.error("Server error during password reset", { error: err.message });
    res.status(500).json({ message: "Server error" });
  }
};

module.exports = { register, login, logout, getProfile, requestPasswordReset, resetPassword };