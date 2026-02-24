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
  const superAdminRepo = AppDataSource.getRepository(SuperAdmin);

  // Efficient existence check
  const existingAdmin = await superAdminRepo.findOne({
    where: { userType: UserType.SUPER_ADMIN },
  });

  if (existingAdmin) {
    logger.info('Default SuperAdmin already exists. Skipping seeding.');
    return;
  }

  const defaultEmail = "scaffSnap@mailinator.com";
  const defaultPassword = "Agicent@123";

  

  const passwordHash = await bcrypt.hash(defaultPassword, 12);

  const credential = new SuperAdminCredential();
  credential.email = defaultEmail;
  credential.passwordHash = passwordHash;

  const superAdmin = new SuperAdmin();
  superAdmin.firstName = 'Default';
  superAdmin.lastName = 'SuperAdmin';
  superAdmin.phoneNumber = '9999999999';
  superAdmin.countryCode = '+91';
  superAdmin.userType = UserType.SUPER_ADMIN;
  superAdmin.status = SuperAdminStatus.ACTIVE;
  superAdmin.isVerified = true;
  superAdmin.address = {
    street: 'Head Office',
    city: 'City',
    state: 'State',
    postalCode: '000000',
    country: 'Country',
  };
  superAdmin.coordinates = {
    lat: 0,
    lng: 0,
  };
  superAdmin.credential = credential;

  await superAdminRepo.save(superAdmin);

  logger.info('Default SuperAdmin created successfully', {
    email: defaultEmail,
  });
};