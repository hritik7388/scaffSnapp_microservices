import { Producer, Kafka, Message } from 'kafkajs';
import logger from '../../config/logger';
import { config } from '../../config/config';

let isConnected = false;

const kafka = new Kafka({
  clientId: config.SERVICE_NAME,
  brokers: [config.KAFKA_BROKER],
  retry: {
    initialRetryTime: 300,
    retries: 8,
  },
});

export const producer: Producer = kafka.producer({
  idempotent: true,
  allowAutoTopicCreation: false,
});

export const TOPICS = {
  SUPERADMIN_CREATED: 'superadmin.created',
};

export interface SuperAdminCreatedEvent {
  id: number;
  email: string;
  createdAt: string;
}

export const connectProducer = async () => {
  if (isConnected) return;

  try {
    await producer.connect();
    isConnected = true;
    logger.info('Kafka SuperAdmin producer connected');
  } catch (error: any) {
    logger.error('Failed to connect Kafka producer', {
      message: error.message,
      stack: error.stack,
    });
    throw error;
  }
};

export const publishSuperAdminCreated = async (
  data: SuperAdminCreatedEvent
) => {
  try {
    const message: Message = {
      key: String(data.id), // ensures partition consistency
      value: JSON.stringify(data),
    };

    await producer.send({
      topic: TOPICS.SUPERADMIN_CREATED,
      acks: -1,
      messages: [message],
    });

    logger.info('SuperAdmin created event published', {
      superAdminId: data.id,
      topic: TOPICS.SUPERADMIN_CREATED,
    });
  } catch (error: any) {
    logger.error('Failed to publish SuperAdmin created event', {
      message: error.message,
      stack: error.stack,
      superAdminId: data.id,
    });
    throw error;
  }
};