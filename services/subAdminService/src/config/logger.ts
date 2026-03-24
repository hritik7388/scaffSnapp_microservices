import winston from 'winston';
import { config } from './config';
// You might want to install winston-daily-rotate-file for production
// import DailyRotateFile from 'winston-daily-rotate-file'; 

const isProduction = process.env.NODE_ENV === 'production';

const devFormat = winston.format.combine(
    winston.format.colorize({ all: true }),
    winston.format.printf(({ level, message, timestamp, stack }) => {
        return `${timestamp} [${level}] : ${stack || message}`;
    })
);

const prodFormat = winston.format.json();

const logger = winston.createLogger({
    level: config.LOG_LEVEL || (isProduction ? 'info' : 'debug'), // Use 'debug' in development
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.splat(), // Handles string interpolation
        isProduction ? prodFormat : devFormat
    ),
    defaultMeta: { service: config.SERVICE_NAME },
    transports: [
        new winston.transports.Console(),
        // Consider DailyRotateFile for prod to prevent huge log files
        new winston.transports.File({
            filename: 'logs/error.log',
            level: 'error',
        }),
        new winston.transports.File({
            filename: 'logs/combined.log',
        }),
    ],
    exceptionHandlers: [
        new winston.transports.File({ filename: 'logs/exceptions.log' }),
    ],
    rejectionHandlers: [
        new winston.transports.File({ filename: 'logs/rejections.log' }),
    ],
});

export const stream = {
    write: (message: string) => {
        // Use logger.info() correctly by passing the message string
        logger.info(message.trim());
    },
};

export default logger;
