import { AppDataSource } from '../data-source';
import {
    SuperAdmin,
    UserType,
    SuperAdminStatus,
} from '../entities/superAdmin.enities';
import { SuperAdminCredential } from '../entities/superAdmin.credentials';
import bcrypt from 'bcryptjs';
import logger from '../config/logger';

export const createDefaultSuperAdmin = async (): Promise<void> => {
    const queryRunner = AppDataSource.createQueryRunner();

    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
        const superAdminRepo = queryRunner.manager.getRepository(SuperAdmin);
        const credentialRepo =
            queryRunner.manager.getRepository(SuperAdminCredential);

        const existingAdmin = await superAdminRepo.findOne({
            where: { userType: UserType.SUPER_ADMIN },
            relations: ['credential'],
        });

        if (existingAdmin) {
            logger.info('Default SuperAdmin already exists. Skipping seeding.');
            await queryRunner.rollbackTransaction();
            return;
        }

        const defaultEmail = process.env.DEFAULT_SUPERADMIN_EMAIL;
        const defaultPassword = process.env.DEFAULT_SUPERADMIN_PASSWORD;

        if (!defaultEmail || !defaultPassword) {
            throw new Error(
                'DEFAULT_SUPERADMIN_EMAIL and DEFAULT_SUPERADMIN_PASSWORD must be defined in environment variables.'
            );
        }

        const passwordHash = await bcrypt.hash(defaultPassword, 12);

        const credential = credentialRepo.create({
            email: defaultEmail,
            passwordHash,
        });

        const superAdmin = superAdminRepo.create({
            credential,
            firstName: 'Default',
            lastName: 'superAdmin',
            userType: UserType.SUPER_ADMIN,
            phoneNumber: '7388503329',
            countryCode: '+91',
            status: SuperAdminStatus.ACTIVE,
            isVerified: true,
            address: {
                street: '123 Admin St',
                city: 'Admin City',
                state: 'Admin State',
                postalCode: '12345',
                country: 'Admin Country',

            },
            coordinates: {
                lat: 40.7128,
                lng: -74.0060,
            },
        });

        await superAdminRepo.save(superAdmin);

        await queryRunner.commitTransaction();

        logger.info('Default SuperAdmin created successfully', {
            email: defaultEmail,
        });
    } catch (error: any) {
        await queryRunner.rollbackTransaction();

        logger.error('Failed to seed Default SuperAdmin', {
            message: error.message,
            stack: error.stack,
        });

        throw error;
    } finally {
        await queryRunner.release();
    }
};