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
    SUBADMIN_CREATED: 'subadmin.created',
};

export interface SubAdminCreatedEvent {
    id: number;
    email: string;
    createdAt: string;
}

export const connectProducer = async (): Promise<void> => {
    if (isConnected) return;

    try {
        await producer.connect();
        isConnected = true;
        logger.info('Kafka SubAdmin producer connected');
    } catch (error: any) {
        logger.error('Failed to connect Kafka producer', {
            message: error.message,
            stack: error.stack,
        });
        throw error;
    }
};

export const publishSubAdminCreated = async (
    data: SubAdminCreatedEvent
): Promise<void> => {
    try {
        // Ensure producer is connected
        await connectProducer();

        const message: Message = {
            key: String(data.id), // ensures partition consistency
            value: JSON.stringify(data),
        };

        await producer.send({
            topic: TOPICS.SUBADMIN_CREATED,
            acks: -1,
            messages: [message],
        });

        logger.info('SubAdmin created event published', {
            subAdminId: data.id,
            topic: TOPICS.SUBADMIN_CREATED,
        });
    } catch (error: any) {
        logger.error('Failed to publish SubAdmin created event', {
            message: error.message,
            stack: error.stack,
            subAdminId: data.id,
        });
        throw error;
    }

    process.on("SIGINT", async () => {
        await producer.disconnect();
        process.exit(0);
    });

    process.on("SIGTERM", async () => {
        await producer.disconnect();
        process.exit(0);
    });
};