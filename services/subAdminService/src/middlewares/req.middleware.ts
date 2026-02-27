import { NextFunction, Request, Response } from 'express';
import logger from '../config/logger';

export const reqLogger = (req: Request, res: Response, next: NextFunction) => {
  // Log incoming request at debug level
  logger.debug(`[REQ START] [${req.method}] ${req.originalUrl}`);

  const startTime = process.hrtime(); // higher precision than Date.now()

  // Listen to finish event to log response details
  res.on('finish', () => {
    const diff = process.hrtime(startTime);
    const durationMs = (diff[0] * 1e3 + diff[1] / 1e6).toFixed(2);

    logger.info(
      `[REQ END] [${req.method}] ${req.originalUrl} - status: ${res.statusCode} - ${durationMs}ms`
    );
  });

  next();
};