import { Kafka, logLevel } from 'kafkajs';
import logger from '../config/logger';
import { config } from '../config/config';

let isConnected = false;

const kafka = new Kafka({
  clientId: config.SERVICE_NAME,
  brokers: [config.KAFKA_BROKER],

  retry: {
    initialRetryTime: 300,
    retries: 8,
  },

  logLevel: logLevel.NOTHING,
});

export const producer = kafka.producer({
  allowAutoTopicCreation: false,
  idempotent: true,
});

export const connectKafka = async () => {
  if (isConnected) return;

  try {
    await producer.connect();
    isConnected = true;
    logger.info('Kafka producer connected');
  } catch (error: any) {
    logger.error('Failed to connect Kafka producer', {
      message: error.message,
      stack: error.stack,
    });
    throw error;
  }
};

export const disconnectKafka = async () => {
  if (!isConnected) return;

  try {
    await producer.disconnect();
    isConnected = false;
    logger.info('Kafka producer disconnected');
  } catch (error: any) {
    logger.error('Failed to disconnect Kafka producer', {
      message: error.message,
      stack: error.stack,
    });
  }
};