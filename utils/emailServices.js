const nodemailer = require("nodemailer");

const sendResetEmail = async (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset",
    text: `You requested a password reset. Click the link to reset your password: ${process.env.CLIENT_URL}/reset-password/${token}`,
  };

  await transporter.sendMail(mailOptions);
};

const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    await redisClient.setex(`reset_${user._id}`, 3600, token);

    await sendResetEmail(email, token);
    res.json({ message: "Password reset email sent" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const sessionToken = await redisClient.get(`reset_${decoded.id}`);
    if (!sessionToken) return res.status(400).json({ message: "Invalid or expired token" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });

    await redisClient.del(`reset_${decoded.id}`);
    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

module.exports = { register, login, logout, requestPasswordReset, resetPassword };