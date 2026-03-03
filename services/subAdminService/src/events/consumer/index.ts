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
};