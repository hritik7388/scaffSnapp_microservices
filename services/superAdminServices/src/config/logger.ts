import winston from 'winston';
import { config } from './config';

const isProduction = process.env.NODE_ENV === 'production';

const devFormat = winston.format.combine(
    winston.format.colorize({ all: true }),
    winston.format.printf(({ level, message, timestamp, stack }) => {
        return `${timestamp} [${level}] : ${stack || message}`;
    })
);

const prodFormat = winston.format.json();

const logger = winston.createLogger({
    level: config.LOG_LEVEL || (isProduction ? 'info' : 'debug'),
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
        isProduction ? prodFormat : devFormat
    ),
    defaultMeta: { service: config.SERVICE_NAME },
    transports: [
        new winston.transports.Console(),
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
        logger.info(message.trim());
    },
};

export default logger;
