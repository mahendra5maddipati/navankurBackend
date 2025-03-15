require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const redisClient = require("./config/redis");
const authRoutes = require("./routes/authRoutes");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
connectDB();
redisClient.on('error', (err) => console.error('Redis Error:', err));

app.use(helmet());
app.use(cors());
app.use(express.json());

app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});
app.use(limiter);

app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));