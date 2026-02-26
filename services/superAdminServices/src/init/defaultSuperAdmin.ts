import { AppDataSource } from '../data-source';
import {
  SuperAdmin,
  UserType,
  SuperAdminStatus,
} from '../entities/superAdmin.enities';
import { SuperAdminCredential } from '../entities/superAdmin.credentials';
import logger from '../config/logger';
import Crypto from 'node:crypto'

export const createDefaultSuperAdmin = async (email?: string): Promise<void> => {
  if (!email) {
    return
  }

  const superAdminRepo = AppDataSource.getRepository(SuperAdmin);
  const existingAdmin = await superAdminRepo.findOne({
    where: { userType: UserType.SUPER_ADMIN },
  });

  if (existingAdmin) {
    logger.info('Default SuperAdmin already exists. Skipping seeding.');
    return;
  }
  const tempPassword = Crypto.randomBytes(10).toString("base64url");

  const credential = new SuperAdminCredential();
  credential.email = email;
  credential.passwordHash = tempPassword;

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

  logger.info('Default SuperAdmin created successfully', { email });
};