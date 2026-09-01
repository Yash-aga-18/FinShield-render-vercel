import { createClient } from "redis";

const redisClient = createClient({
  url: process.env.REDIS_URL,
});

redisClient.on("error", (error) => {
  console.error("Redis error:", error);
});

const connectRedis = async () => {
  try {
    if (!redisClient.isOpen) {
      await redisClient.connect();
    }
    console.log("Redis connected");
  } 
  
  catch (error) {
    console.error("Error connecting to Redis:", error);
    process.exit(1);
  }
};

export { redisClient };
export default connectRedis;