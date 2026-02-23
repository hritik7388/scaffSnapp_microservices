import Redis from 'ioredis';
import { config } from './config';
import logger from './logger';

export const redisClient = new Redis(config.REDIS_URL, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,

    retryStrategy(times: number) {
        const delay = Math.min(times * 100, 3000);
        logger.warn(`Redis reconnect attempt #${times}, retrying in ${delay}ms`);
        return delay;
    },

    reconnectOnError(err) {
        logger.error('Redis reconnectOnError triggered', { message: err.message });
        return true;
    },

    connectTimeout: 10000,
});

redisClient.on('connect', () => {
    logger.info('Redis connection established');
});

redisClient.on('ready', () => {
    logger.info('Redis ready to use');
});

redisClient.on('error', (error) => {
    logger.error('Redis connection error', { message: error.message });
});

redisClient.on('close', () => {
    logger.warn('Redis connection closed');
});

redisClient.on('end', () => {
    logger.warn('Redis connection ended');
});
process.on('SIGINT', async () => {
    logger.info('Closing Redis connection...');
    await redisClient.quit();
    process.exit(0);
});