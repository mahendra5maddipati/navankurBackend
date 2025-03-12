const express = require("express");
const { register, login, logout, getProfile } = require("../controllers/authController");
const authenticateUser = require("../middlewares/authMiddleware");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", authenticateUser, logout);
router.get("/profile", authenticateUser, getProfile);

module.exports = router;