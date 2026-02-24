// src/init/index.ts

import { AppDataSource } from '../data-source';
import { redisClient } from '../config/redis';
import { connectKafka } from '../events/kafka';
import { createDefaultSuperAdmin } from './defaultSuperAdmin';
import logger from '../config/logger';

export const init = async (): Promise<void> => {
    try {
        logger.info('Starting infrastructure initialization...');

        // 1️⃣ Database
        if (!AppDataSource.isInitialized) {
            await AppDataSource.initialize();
            logger.info('Database connected successfully');
        }

        // 2️⃣ Redis (ioredis auto-connects)
        const pong = await redisClient.ping();

        if (pong !== 'PONG') {
            throw new Error('Redis ping failed');
        }

        logger.info('Redis connected successfully');

        // 3️⃣ Kafka
        await connectKafka();
        logger.info('Kafka connected successfully');

        // 4️⃣ Default SuperAdmin
        await createDefaultSuperAdmin();

        logger.info('All infrastructure initialized successfully ✅');
    } catch (error: unknown) {
        const message =
            error instanceof Error ? error.message : 'Unknown initialization error';

        logger.error('Infrastructure initialization failed', { message });

        process.exit(1);
    }
};