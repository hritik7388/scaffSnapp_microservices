import { Consumer } from "kafkajs";
import { createConsumer } from "../kafka";
import logger from "../../config/logger";
import SubAdminService  from "../../service/subAdmin.service";  
import { SubAdminApproval } from "../../entities/subAdmin.enities";
import { RegisterSubAdminDTO } from "../../schemas/subAdminSchema";
export const SUBADMIN_TOPICS = {
  SUBADMIN_EVENTS: "subadmin-events",
};

export const SUBADMIN_EVENT_TYPES = {
  SUBADMIN_CREATED: "SUBADMIN_CREATED",
  SUBADMIN_UPDATED: "SUBADMIN_UPDATED",
  SUBADMIN_DELETED: "SUBADMIN_DELETED",
};


export const startSubAdminConsumer = async (): Promise<Consumer> => {
  const consumer = createConsumer("subadmin-events-cg");

  await consumer.connect();

  await consumer.subscribe({
    topic: SUBADMIN_TOPICS.SUBADMIN_EVENTS,
    fromBeginning: false,
  });

  // Consumer me hi handle function define kar do
  const handleSubAdminCreated = async (eventData: RegisterSubAdminDTO) => {
    return SubAdminService.register({
      ...eventData,
      isApproved: SubAdminApproval.APPROVED,
    });
  };

  await consumer.run({
    eachMessage: async ({ topic, partition, message }) => {
      const value = message.value?.toString();

      if (!value) {
        logger.warn(`[${topic}.${partition}] Empty message received`);
        return;
      }

      try {
        const eventData = JSON.parse(value);

        switch (eventData.eventType) {
          case SUBADMIN_EVENT_TYPES.SUBADMIN_CREATED:
            await handleSubAdminCreated(eventData);
            break;

          case SUBADMIN_EVENT_TYPES.SUBADMIN_UPDATED:
            // agar chahe to yaha hi handle function define kar sakte ho
            break;

          case SUBADMIN_EVENT_TYPES.SUBADMIN_DELETED:
            // agar chahe to yaha hi handle function define kar sakte ho
            break;

          default:
            logger.warn(`Unhandled SubAdmin event type: ${eventData.eventType}`);
        }

        logger.info(
          `[${topic}.${partition}] Processed event: ${eventData.eventType}`
        );
      } catch (error) {
        logger.error(
          `[${topic}.${partition}] Error processing SubAdmin event`,
          error
        );
      }
    },
  });

  logger.info("SubAdmin Kafka consumer started successfully");

  return consumer;
};