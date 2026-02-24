import { Server } from 'node:http';
import { AppDataSource } from '../data-source';
import logger from '../config/logger';
import { redisClient } from '../config/redis';
import { disconnectKafka } from '../events/kafka';

let isShuttingDown = false;

export const setupGracefulShutdown = (server: Server) => {
    const shutdown = async (signal: string) => {
        if (isShuttingDown) return;
        isShuttingDown = true;

        logger.info(`Received ${signal}. Starting graceful shutdown...`);

        // Force exit if shutdown takes too long
        const forceTimeout = setTimeout(() => {
            logger.error('Shutdown timeout reached. Forcing exit.');
            process.exit(1);
        }, 15000);

        try {
            await new Promise<void>((resolve) => {
                server.close(() => {
                    logger.info('HTTP server closed 1');
                    resolve();
                });
            });

            if (AppDataSource.isInitialized) {
                await AppDataSource.destroy();
                logger.info('Database connection closed 1');
            }

            if (redisClient.status === 'ready') {
                await redisClient.quit();
                logger.info('Redis connection closed 1');
            }

            await disconnectKafka();
            logger.info('Kafka disconnected 1');

            clearTimeout(forceTimeout);

            logger.info('Graceful shutdown completed\n--------------------------------',);
            process.exit(0);
        } catch (error: any) {
            logger.error('Error during graceful shutdown', {
                message: error.message,
                stack: error.stack,
            });

            process.exit(1);
        }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    process.on('uncaughtException', (error: Error) => {
        logger.error('Uncaught Exception', {
            message: error.message,
            stack: error.stack,
        });
        shutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason: any) => {
        logger.error('Unhandled Rejection', {
            reason,
        });
        shutdown('unhandledRejection');
    });
};
