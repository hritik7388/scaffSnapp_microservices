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
};