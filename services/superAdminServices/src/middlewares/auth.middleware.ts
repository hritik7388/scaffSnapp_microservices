import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { redisClient } from '../config/redis';

// Use a Set for O(1) lookup
const publicRoutes = new Set([
  '/',
  '/health',
  '/api/v1/super-admin/login',
  '/api/v1/super-admin/register',
].map(route => route.toLowerCase()));


export const verifyToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Skip public routes
  if (publicRoutes.has(req.path.toLowerCase())) {
    return next();
  }

  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(403).json({ message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'Token missing' });

    // Verify JWT
    const decoded: any = jwt.verify(token, config.JWT_SECRET);

    // Check Redis token
    const redisKey = `auth:${decoded.id}:${token}`;
    const redisToken = await redisClient.get(redisKey);
    if (!redisToken) return res.status(401).json({ message: 'Unauthorized' });

    // Attach user info
    req.userId = decoded.id;
    req.token = token;

    next();
  } catch (err: unknown) {
    let message = 'Unauthorized';
    if (err instanceof Error) message = err.message;

    return res.status(401).json({ message });
  }
};