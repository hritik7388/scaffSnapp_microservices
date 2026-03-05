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
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(403).json({ message: 'Authorization header missing or invalid' });
    }

    const token = authHeader.split(' ')[1];

    // Verify JWT
    const decoded: any = jwt.verify(token, config.JWT_ACCESS_SECRET);

    // Redis check (must exist)
    const redisKey = `auth:${decoded.sub}:${token}`;
    const redisToken = await redisClient.get(redisKey);
    if (!redisToken) {
      return res.status(401).json({ message: 'Session expired or invalid token' });
    }

    // Attach user info
    req.userId = decoded.sub;
    req.userRole = decoded.role;
    req.token = token;

    next();
  } catch (err: unknown) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
};

// SuperAdmin-only routes
export const requireSuperAdmin = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  if (req.userRole !== UserType.SUPER_ADMIN) {
    return res.status(403).json({ message: 'Only SuperAdmin can perform this action' });
  }
  next();
};