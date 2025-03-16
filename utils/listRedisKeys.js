const Redis = require("ioredis");
require("dotenv").config();

const redisClient = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD,
});

const listKeys = async () => {
  try {
    const keys = await redisClient.keys('*');
    for (const key of keys) {
      const value = await redisClient.get(key);
      console.log(`Key: ${key}, Value: ${value}`);
    }
  } catch (err) {
    console.error("Error listing keys:", err);
  } finally {
    redisClient.quit();
  }
};

listKeys();