<<<<<<< HEAD
import { config } from "../../config/config";
import logger from "../../config/logger";
import { startTransactionEventsConsumer } from "./subAdminEvent.consumer";
import { setupKafkaGracefulShutdown } from "../kafka";

export const startConsumers = async (): Promise<void> => {
    try {
        logger.info(`Starting Kafka consumers for ${config.SERVICE_NAME}`);

        const consumer = await startTransactionEventsConsumer();

        await setupKafkaGracefulShutdown([consumer]);

        logger.info(
            `All Kafka consumers started successfully for ${config.SERVICE_NAME}`
        );
    } catch (error) {
        logger.error("Failed to start Kafka consumers", error);
        throw error;
    }
=======
// src/events/consumer/index.ts

import logger from "../../config/logger";
import { startSubAdminConsumer } from "./subAdminEvents.consumer";

export const startConsumers = async () => {
  try {
    logger.info("Starting SubAdmin Consumers...");
    await startSubAdminConsumer();
    logger.info("SubAdmin Consumers Started Successfully");
  } catch (error) {
    logger.error("Failed to start SubAdmin Consumers", error);
    throw error;
  }
>>>>>>> ed543bdde29a9f19caabb86638fdc7d4c8d8e0e3
};