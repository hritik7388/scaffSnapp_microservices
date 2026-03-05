import { Consumer } from "kafkajs";
import { createConsumer } from "../kafka";
import logger from "../../config/logger";
import SubAdminServiceClass from "../../service/subAdmin.service";
import { SubAdmin, SubAdminApproval, UserType } from "../../entities/subAdmin.enities";
import crypto from "crypto";
import { AppDataSource } from "../../data-source";
import { SubAdminCredential } from "../../entities/subAdmin.credentials";
import bcrypt from "bcryptjs";

export const TOPICS = {
    SUBADMIN_REGISTERED: "subadmin.registered",
};

export const startTransactionEventsConsumer = async (): Promise<Consumer> => {
    const consumer = createConsumer("subadmin-service-group");

    await consumer.connect();

    await consumer.subscribe({
        topic: TOPICS.SUBADMIN_REGISTERED,
        fromBeginning: true,
    });

    await consumer.run({
        autoCommit: true,
        partitionsConsumedConcurrently: 1,

        eachMessage: async ({ topic, partition, message }) => {
            const value = message.value?.toString();
            if (!value) return;

            try {
                const eventData = JSON.parse(value);

                switch (eventData.eventType) {

                    case "SUBADMIN_REGISTERED":
                        await handleSubAdminCreate(eventData);
                        break;

                    case "SUBADMIN_UPDATED":
                        await handleSubAdminUpdate(eventData);
                        break;

                    case "SUBADMIN_DELETED":
                        await handleSubAdminDelete(eventData);
                        break;

                    default:
                        logger.warn(`Unknown event type: ${eventData.eventType}`);
                }

            } catch (error: any) {
                logger.error("Error processing event", {
                    offset: message.offset,
                    message: error.message,
                });
            }
        }
    });

    return consumer;
};
const subAdminRepository = AppDataSource.getRepository(SubAdmin);
const credentialRepository = AppDataSource.getRepository(SubAdminCredential);

export const handleSubAdminCreate = async (eventData: any) => {
    const queryRunner = AppDataSource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
        const email = eventData.email?.toLowerCase().trim();
        if (!email) {
            logger.warn("Email missing in event payload");
            return;
        }

        // ✅ Idempotency Check
        const existing = await credentialRepository.findOne({
            where: { email },
        });

        if (existing) {
            logger.warn(`SubAdmin already exists with email: ${email}`);
            return;
        }



        // ✅ Approval Logic
        const approvalStatus =
            eventData.createdByRole === "SUPER_ADMIN"
                ? SubAdminApproval.APPROVED
                : SubAdminApproval.PENDING;

        // ✅ Generate Temp Password
        const tempPassword = crypto.randomBytes(6).toString("hex");
        const hashedPassword = await bcrypt.hash(tempPassword, 10);

        // ✅ Create Credential Entity
        const credential = credentialRepository.create({
            email,
            passwordHash: hashedPassword,
            mustChangePassword: true,
        });

        // ✅ Create SubAdmin Entity
        const subAdmin = subAdminRepository.create({
            firstName: eventData.firstName,
            lastName: eventData.lastName,
            phoneNumber: eventData.phoneNumber,
            countryCode: eventData.countryCode,
            profileImage: eventData.profileImage,
            address: eventData.address,
            coordinates: eventData.coordinates,
            userType: UserType.SUB_ADMIN,
            isApproved: approvalStatus,
            isVerified: true,
            credential,
        });

        await queryRunner.manager.save(subAdmin);

        await queryRunner.commitTransaction();

        logger.info(
            `SubAdmin created successfully | Email: ${email} | Approval: ${approvalStatus}`
        );

    } catch (error: any) {
        await queryRunner.rollbackTransaction();

        logger.error("Error creating SubAdmin", {
            message: error.message,
            stack: error.stack,
        });
    } finally {
        await queryRunner.release();
    }
};

export const handleSubAdminUpdate = async (eventData: any) => {
    const queryRunner = AppDataSource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
        const subAdmin = await queryRunner.manager.findOne(SubAdmin, {
            where: { id: eventData.id },
            relations: ["credential"],
        });

        if (!subAdmin) {
            logger.warn(`SubAdmin not found with id: ${eventData.id}`);
            return;
        }

        // ✅ Update only allowed fields (never blindly assign)
        subAdmin.firstName = eventData.firstName ?? subAdmin.firstName;
        subAdmin.lastName = eventData.lastName ?? subAdmin.lastName;
        subAdmin.phoneNumber = eventData.phoneNumber ?? subAdmin.phoneNumber;
        subAdmin.countryCode = eventData.countryCode ?? subAdmin.countryCode;
        subAdmin.profileImage = eventData.profileImage ?? subAdmin.profileImage;
        subAdmin.address = eventData.address ?? subAdmin.address;
        subAdmin.coordinates = eventData.coordinates ?? subAdmin.coordinates;

        await queryRunner.manager.save(subAdmin);

        await queryRunner.commitTransaction();

        logger.info(`SubAdmin updated successfully | ID: ${eventData.id}`);

    } catch (error: any) {
        await queryRunner.rollbackTransaction();

        logger.error("Error updating SubAdmin", {
            message: error.message,
            stack: error.stack,
        });
    } finally {
        await queryRunner.release();
    }
};

export const handleSubAdminDelete = async (eventData: any) => {
    const queryRunner = AppDataSource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
        const subAdmin = await queryRunner.manager.findOne(SubAdmin, {
            where: { id: eventData.id },
        });

        if (!subAdmin) {
            logger.warn(`SubAdmin not found with id: ${eventData.id}`);
            return;
        }

        // ✅ Soft Delete
        await queryRunner.manager.softRemove(subAdmin);

        await queryRunner.commitTransaction();

        logger.info(`SubAdmin soft deleted successfully | ID: ${eventData.id}`);

    } catch (error: any) {
        await queryRunner.rollbackTransaction();

        logger.error("Error deleting SubAdmin", {
            message: error.message,
            stack: error.stack,
        });
    } finally {
        await queryRunner.release();
    }
};