import { AppDataSource } from '../data-source';
import {
  SuperAdmin,
  UserType,
  SuperAdminStatus,
} from '../entities/superAdmin.enities';
import { SuperAdminCredential } from '../entities/superAdmin.credentials';
import bcrypt from 'bcryptjs';
import logger from '../config/logger';
import Crypto from 'node:crypto'

export const createDefaultSuperAdmin = async (email: string): Promise<void> => {

  const superAdminRepo = AppDataSource.getRepository(SuperAdmin);
  const existingAdmin = await superAdminRepo.findOne({
    where: { userType: UserType.SUPER_ADMIN },
  });

  if (existingAdmin) {
    logger.info('Default SuperAdmin already exists. Skipping seeding.');
    return;
  }


  if (!email) {
    throw new Error('SuperAdmin email must be provided.');
  }
  const tempPass = await Crypto.randomBytes(6).toString('hex')

  const passwordHash = await bcrypt.hash(tempPass, 12);

  const credential = new SuperAdminCredential();
  credential.email = email;
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
    email, tempPass
  });
};