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
  // Log the raw error first
  logger.error(error);

  // Handle Zod validation errors
  if (error instanceof z.ZodError) {
    res.status(400).json({
      status: 'error',
      message: 'Invalid input',
      errors: error.issues, // detailed validation issues
    });
    return;
  }

  // Ensure error conforms to CustomError interface
  const customError = error as CustomError;

  const statusCode = customError.statusCode || 500;
  const status = customError.status || 'error';
  const message = customError.message || 'Internal server error';

  // Detailed logging for non-production environments
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

  // Send structured response
  res.status(statusCode).json({
    status,
    message,
  });
};