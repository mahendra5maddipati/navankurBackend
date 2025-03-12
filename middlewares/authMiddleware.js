const jwt = require("jsonwebtoken");
const redisClient = require("../config/redis");

const authenticateUser = async (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "No token, authorization denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check session in Redis
    const sessionToken = await redisClient.get(decoded.id);
    if (!sessionToken) return res.status(401).json({ message: "Session expired" });

    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

module.exports = authenticateUser;
