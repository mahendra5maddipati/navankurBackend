const jwt = require("jsonwebtoken");
const redisClient = require("../config/redis");
const logger = require("../config/logger");

const authenticateUser = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    logger.warn("No token, authorization denied");
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check session in Redis
    const sessionToken = await redisClient.get(decoded.id);
    if (!sessionToken) {
      logger.warn("Session expired", { userId: decoded.id });
      return res.status(401).json({ message: "Session expired" });
    }

    req.user = decoded;
    next();
  } catch (err) {
    logger.error("Invalid token", { error: err.message });
    res.status(401).json({ message: "Invalid token" });
  }
};

module.exports = authenticateUser;