import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import logger from '../config/logger';
import { CustomError } from '../types/index';

export const errorHandler = (
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  logger.error(error);
  if (error instanceof z.ZodError) {
    res.status(400).json({
      status: 'error',
      message: 'Invalid input',
      errors: error.issues,
    });
    return;
  }
  const customError = error as CustomError;

  const statusCode = customError.statusCode || 500;
  const status = customError.status || 'error';
  const message = customError.message || 'Internal server error';
  if (process.env.NODE_ENV !== 'production') {
    logger.error({
      message,
      stack: (customError as Error).stack,
      path: req.path,
      method: req.method,
      body: req.body,
      query: req.query,
    });
  }
  res.status(statusCode).json({
    statusCode,
    status,
    message,
  });
};