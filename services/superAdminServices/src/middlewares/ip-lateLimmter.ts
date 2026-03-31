import { Request, Response, NextFunction } from "express";
import { redisClient } from "../config/redis";

const IP_WINDOW = 60; // 1 min
const IP_MAX = 10;

const EMAIL_WINDOW = 60; // 1 min
const EMAIL_MAX = 5;

export const loginRateLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const ip =
      req.ip ||
      req.headers["x-forwarded-for"] ||
      req.socket.remoteAddress;

    const email = req.body?.email || "unknown";
    const ipKey = `rate_limit:ip:${ip}`;
    const ipCount = await redisClient.incr(ipKey);

    if (ipCount === 1) {
      await redisClient.expire(ipKey, IP_WINDOW);
    }

    if (ipCount > IP_MAX) {
      return res.status(429).json({
        message: "Too many requests from this IP. Try again later.",
      });
    }

    const comboKey = `rate_limit:combo:${ip}:${email}`;
    const comboCount = await redisClient.incr(comboKey);

    if (comboCount === 1) {
      await redisClient.expire(comboKey, EMAIL_WINDOW);
    }

    if (comboCount > EMAIL_MAX) {
      return res.status(429).json({
        message: "Too many login attempts. Try again later.",
      });
    }

    next();
  } catch (err) {
    console.error("Rate limiter error:", err);
    next(); // fail open
  }
};