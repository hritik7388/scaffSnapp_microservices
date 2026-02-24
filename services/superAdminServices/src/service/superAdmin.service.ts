import jwt from 'jsonwebtoken';
import ms from 'ms';
import bcrypt from 'bcryptjs';
import { config } from '../config/config'
import crypto from 'crypto';

import { AppDataSource } from '../data-source';
import { redisClient } from '../config/redis'
import { Repository } from 'typeorm';
import { SuperAdminCredential } from '../entities/superAdmin.credentials';
import { SuperAdmin, UserType } from '../entities/superAdmin.enities';
import { createError } from '../utils';
import { SuperAdminDTO } from '../schemas/superAdminSchema';



class AuthService {
  credentialRepository: Repository<SuperAdminCredential>;
  userRepository: Repository<SuperAdmin>;

  constructor() {
    this.credentialRepository = AppDataSource.getRepository(SuperAdminCredential);
    this.userRepository = AppDataSource.getRepository(SuperAdmin);
  }



  async login(data: SuperAdminDTO) {
    
  }



  async logout(userId: number, token: string) {
    
  }
}

export default AuthService;