import dotenv from "dotenv";
dotenv.config();
import jwt, { SignOptions } from 'jsonwebtoken'; 
import bcrypt from 'bcryptjs';  
import crypto from "node:crypto";
import { AppDataSource } from '../data-source';
import { redisClient } from '../config/redis'
import { Repository } from 'typeorm';
import { SuperAdminCredential } from '../entities/superAdmin.credentials';
import { SuperAdmin, UserType } from '../entities/superAdmin.enities';
import { createError } from '../utils';
import { SuperAdminDTO } from '../schemas/superAdminSchema';
import { DeviceSession } from '../entities/device-session.entity'; 
import { config } from '../config/config';
import logger from '../config/logger';


const FAIL_TTL = 900; // 15 minutes
const MAX_FAILS = 3;
const PWD_CACHE_TTL = 86400; // 1 day
const REFRESH_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days

  

class AuthService {
  credentialRepository: Repository<SuperAdminCredential>;
  userRepository: Repository<SuperAdmin>;
  deviceRepository: Repository<DeviceSession> 

  constructor() {
    this.credentialRepository = AppDataSource.getRepository(SuperAdminCredential);
    this.userRepository = AppDataSource.getRepository(SuperAdmin);
    this.deviceRepository=AppDataSource.getRepository(DeviceSession)
  }



  async login(data: SuperAdminDTO, ip: string) {


    await this.checkBlock(data.email);
    const credential = await this.getCredentialWithUser(data.email);
    logger.info("credential===================>>>>",credential)
    this.validateUserStatus(credential.user);
    await this.verifyPassword(data.password, credential);
    await this.clearFailCounter(data.email);
    const tokens = this.generateTokens(credential.user.id);

    await this.saveLoginIp(credential.user.id, ip);
 await this.createDeviceSession(
    credential.user.id,
    tokens.refreshToken,
    ip,
    data.deviceType,      
    data.deviceName,      
    data.deviceToken      
  );


    return { message: "Login successful" ,
      tokens:tokens
    };


  }

  



  private async checkBlock(email: string) {
    const blocked = await redisClient.get(`block:${email}`);
    if (blocked) {
      throw new Error("Account blocked for 15 minutes");
    }
  }



  private async getCredentialWithUser(email: string) {
    const credential = await this.credentialRepository
      .createQueryBuilder("cred")
      .addSelect("cred.passwordHash")
      .leftJoinAndSelect("cred.user", "user")
      .where("cred.email = :email", { email })
      .getOne();

    if (!credential) {
      throw new Error("Invalid credentials");
    }

    return credential;
  }
  private validateUserStatus(user: SuperAdmin) {
    if (!user.isVerified) {
      throw createError("User not verified", 403);
    }

    if (user.status !== "ACTIVE") {
      throw createError("User not active", 403);
    }

    if (user.userType !== UserType.SUPER_ADMIN) {
      throw createError("Not authorized", 403);
    }
  }
  private async verifyPassword(password: string, credential: SuperAdminCredential) {
    const pwdCacheKey = `pwd:${credential.id}:${credential.passwordHash}`;
  const cached = await redisClient.exists(pwdCacheKey);

  if (cached === 1) return true;
 const isValid = await bcrypt.compare(password, credential.passwordHash);
    if (!isValid) {
      await this.increaseFailCount(credential.email);
      throw createError("Invalid credentials", 401);
    } 
  redisClient.setex(pwdCacheKey, PWD_CACHE_TTL, "1").catch(() => {});
  return true;
  }

  private async increaseFailCount(email: string) {
 const attempts = await redisClient.incr(`fail:${email}`);
  if (attempts === 1) await redisClient.expire(`fail:${email}`, FAIL_TTL);
  if (attempts >= MAX_FAILS) {
    await redisClient.set(`block:${email}`, "1", "EX", FAIL_TTL);
    throw createError("Account blocked due to multiple failed attempts", 429);
  }
  }

  private async clearFailCounter(email: string) {
    await redisClient.del(`fail:${email}`);
    await redisClient.del(`block:${email}`);
  }
  private async saveLoginIp(userId: number, ip: string) {
    await this.deviceRepository.save({
     userId,
  ipAddress: ip,
  deviceType: "web",
  expiresAt: new Date(Date.now() + 15 * 60 * 1000)
    });
  }

  private generateTokens(userId: number) {
  const accessToken = jwt.sign(
    { sub: userId, type: "access" }, 
    config.JWT_SECRET as jwt.Secret,   // ✅ cast to Secret
    { expiresIn:  process.env.JWT_EXPIRES_IN || "24h" }as SignOptions
  );

  const refreshToken = jwt.sign(
    { sub: userId, type: "refresh" }, 
     
    config.JWT_SECRET as jwt.Secret, 
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d" }as SignOptions
  );

  return { accessToken, refreshToken };
}

  private hashToken(token: string) {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

private async createDeviceSession(
  userId: number,
  refreshToken: string,
  ip: string,
  deviceType?: string,
  deviceName?: string,
  deviceToken?: string
) {
  const refreshTokenHash = this.hashToken(refreshToken);

  const session = this.deviceRepository.create({
    userId,
    refreshTokenHash,
    ipAddress: ip,
    deviceType,
    deviceToken,
    deviceName,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    isRevoked: false,
  });

  return await this.deviceRepository.save(session);
}
}

export default AuthService;


