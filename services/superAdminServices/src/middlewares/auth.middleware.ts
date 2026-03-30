import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { redisClient } from '../config/redis';
import { UserType } from '../entities/superAdmin.enities';

// Public routes (skip auth)
const publicRoutes = new Set([
  '/',
  '/health',
  '/api/v1/superAdmin/login',
  '/api/v1/superAdmin/forgotPassword',
  '/api/v1/superAdmin/resetPassword',
  '/api/v1/superAdmin/refreshToken',
].map(r => r.toLowerCase()));

export const verifyToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Skip public routes
  if (publicRoutes.has(req.path.toLowerCase())) return next();

  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1]; // Bearer <token>
    if (!token) {
      return res.status(401).json({ message: 'Token missing' });
    }

    // Verify JWT
    const decoded = jwt.verify(token, config.JWT_SECRET) as { userId: string, userType: UserType };

    // Optional: Check Redis for blacklisted token
    const isBlacklisted = await redisClient.get(`bl_${decoded.userId}`);
    if (isBlacklisted) {
      return res.status(401).json({ message: 'Token is revoked' });
    }

    // Attach user info to request
    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};
