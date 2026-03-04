import { Message } from "kafkajs";
import logger from "../../config/logger";
import { producer, connectProducer } from "../kafka";

export const TOPICS = {
    SUBADMIN_CREATED: "subadmin.created",
};

export interface SubAdminCreatedEvent {
    id: number;
    email: string;
    createdAt: string;
}

export const publishSubAdminCreated = async (
    data: SubAdminCreatedEvent
): Promise<void> => {
    try {
        await connectProducer();

        const message: Message = {
            key: String(data.id),
            value: JSON.stringify(data),
        };

        await producer.send({
            topic: TOPICS.SUBADMIN_CREATED,
            acks: -1,
            messages: [message],
        });

        logger.info("SubAdmin created event published", {
            subAdminId: data.id,
            topic: TOPICS.SUBADMIN_CREATED,
        });
    } catch (error: any) {
        logger.error("Failed to publish SubAdmin created event", {
            message: error.message,
            stack: error.stack,
            subAdminId: data.id,
        });
        throw error;
    }
};