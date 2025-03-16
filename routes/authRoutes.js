const express = require("express");
const { register, login, logout, getProfile, requestPasswordReset, resetPassword } = require("../controllers/authController");
const authenticateUser = require("../middlewares/authMiddleware");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", authenticateUser, logout);
router.get("/profile", authenticateUser, getProfile);
router.post("/request-password-reset", requestPasswordReset);
router.post("/reset-password", resetPassword);

module.exports = router;