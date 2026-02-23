import winston from 'winston';
import { config } from './config';

const isProduction = process.env.NODE_ENV === 'production';

const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    isProduction
        ? winston.format.json()
        : winston.format.colorize({ all: true }) &&
        winston.format.printf(({ level, message, timestamp, stack }) => {
            return `${timestamp} [${level}] : ${stack || message}`;
        })
);

const logger = winston.createLogger({
    level: config.LOG_LEVEL || 'info',
    defaultMeta: { service: config.SERVICE_NAME },
    transports: [
        new winston.transports.Console(),

        // Error logs file
        new winston.transports.File({
            filename: 'logs/error.log',
            level: 'error',
        }),

        // All logs file
        new winston.transports.File({
            filename: 'logs/combined.log',
        }),
    ],

    // Catch unhandled exceptions
    exceptionHandlers: [
        new winston.transports.File({ filename: 'logs/exceptions.log' }),
    ],

    // Catch unhandled promise rejections
    rejectionHandlers: [
        new winston.transports.File({ filename: 'logs/rejections.log' }),
    ],
});

export const stream = {
    write: (message: string) => {
        logger.info(message.trim());
    },
};

export default logger;