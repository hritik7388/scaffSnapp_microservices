import { Kafka, logLevel, Consumer } from "kafkajs";
import logger from "../config/logger";
import { config } from "../config/config";

let isProducerConnected = false;

const kafka = new Kafka({
  clientId: config.SERVICE_NAME,
  brokers: [config.KAFKA_BROKER],
  retry: {
    initialRetryTime: 300,
    retries: 8,
  },
  logLevel: logLevel.NOTHING,
});

//
// ================= PRODUCER =================
//

export const producer = kafka.producer({
  allowAutoTopicCreation: false,
  idempotent: true,
});

export const connectProducer = async () => {
  if (isProducerConnected) return;

  await producer.connect();
  isProducerConnected = true;
  logger.info("Kafka producer connected");
};



export const disconnectProducer = async () => {
  if (!isProducerConnected) return;

  await producer.disconnect();
  isProducerConnected = false;
  logger.info("Kafka producer disconnected");
};

//
// ================= CONSUMER =================
//

export const createConsumer = (groupId: string): Consumer => {
  return kafka.consumer({
    groupId,
    sessionTimeout: 30000,
    heartbeatInterval: 3000,
  });
};

//
// ================= GRACEFUL SHUTDOWN =================
//

export const setupKafkaGracefulShutdown = async (
  consumers: Consumer[]
) => {
  const shutdown = async () => {
    try {
      logger.info("Shutting down Kafka connections...");

      for (const consumer of consumers) {
        await consumer.disconnect();
      }

      await disconnectProducer();

      logger.info("Kafka shutdown complete");
      process.exit(0);
    } catch (error) {
      logger.error("Error during Kafka shutdown", error);
      process.exit(1);
    }
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
};