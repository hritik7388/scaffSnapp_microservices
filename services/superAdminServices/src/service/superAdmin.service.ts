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


const FAIL_TTL = 180;
const MAX_FAILS = 3;
const PWD_CACHE_TTL = 300;
const REFRESH_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days



class AuthService {
  credentialRepository: Repository<SuperAdminCredential>;
  userRepository: Repository<SuperAdmin>;
  deviceRepository: Repository<DeviceSession>

  constructor() {
    this.credentialRepository = AppDataSource.getRepository(SuperAdminCredential);
    this.userRepository = AppDataSource.getRepository(SuperAdmin);
    this.deviceRepository = AppDataSource.getRepository(DeviceSession)
  }



  async login(data: SuperAdminDTO, ip: string) {


    await this.checkBlock(data.email);
    const credential = await this.getCredentialWithUser(data.email);
    this.validateUserStatus(credential.user);
    await this.verifyPassword(data.password, credential);
    await this.clearFailCounter(data.email, credential);
    const tokens = this.generateTokens(credential.user.id);
    await this.createDeviceSession(
      credential.user.id,
      tokens.refreshToken,
      ip,
      data.deviceType,
      data.deviceName,
      data.deviceToken
    );


    return {
      message: "Login successful",
      tokens: tokens
    };


  }





  private async checkBlock(email: string) {
    const ttl = await redisClient.ttl(`block:${email}`); // time left in seconds
    if (ttl > 0) {
      throw createError(
        `Account blocked. Try again in ${Math.ceil(ttl / 60)} minutes.`,
        429
      );
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
      await this.increaseFailCount(email);
      throw new Error("Invalid credentials");
    }

    if (credential.accountLockedUntil && credential.accountLockedUntil > new Date()) {
      throw createError(
        `Account locked until ${credential.accountLockedUntil.toISOString()}`,
        429
      );
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
    }

    redisClient.setex(pwdCacheKey, PWD_CACHE_TTL, "1") 
  }

  private async increaseFailCount(email: string) {
    const credential = await this.credentialRepository.findOne({
      where: { email },
      relations: ["user"]
    });

    const redisFailKey = `fail:${email}`;
    const redisBlockKey = `block:${email}`;

    // Increase Redis counter
    const attempts = await redisClient.incr(redisFailKey);
    if (attempts === 1) {
      await redisClient.expire(redisFailKey, FAIL_TTL);
    }

    // If credential doesn't exist
    if (!credential) {
      if (attempts >= MAX_FAILS) {
        await redisClient.setex(redisBlockKey, FAIL_TTL, "1");
        throw createError(
          `Account blocked due to multiple failed attempts. Try again later.`,
          429
        );
      }

      throw createError(
        `Invalid credentials. ${MAX_FAILS - attempts} attempts remaining.`,
        401
      );
    }

    // Update DB counter
    credential.failedLoginAttempts = attempts;

    if (credential.failedLoginAttempts >= MAX_FAILS) {
      const lockUntil = new Date(Date.now() + FAIL_TTL * 1000);
      credential.accountLockedUntil = lockUntil;

      await redisClient.setex(redisBlockKey, FAIL_TTL, "1");
    }

    await this.credentialRepository.save(credential);

    if (credential.failedLoginAttempts >= MAX_FAILS) {
      throw createError(
        `Account blocked due to multiple failed attempts. Try again at ${credential.accountLockedUntil?.toISOString()}`,
        429
      );
    }

    throw createError(
      `Invalid credentials. ${MAX_FAILS - credential.failedLoginAttempts} attempts remaining.`,
      401
    );
  }
  private async clearFailCounter(email: string, credential: SuperAdminCredential) {
    await redisClient.del(`fail:${email}`);
    await redisClient.del(`block:${email}`);
    if (credential) {
      credential.failedLoginAttempts = 0;
      credential.accountLockedUntil = null;
      await this.credentialRepository.save(credential);
    }
  }


  private generateTokens(userId: number) {
    const accessToken = jwt.sign(
      { sub: userId, type: "access" },
      config.JWT_ACCESS_SECRET as jwt.Secret,   // ✅ cast to Secret
      { expiresIn: process.env.JWT_EXPIRES_IN || "24h" } as SignOptions
    );

    const refreshToken = jwt.sign(
      { sub: userId, type: "refresh" },

      config.JWT_REFRESH_SECRET as jwt.Secret,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d" } as SignOptions
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
    if (!deviceToken) {
      throw createError("Device token is required", 400);
    }

    const refreshTokenHash = this.hashToken(refreshToken);

    // Find existing session by userId + deviceToken
    let session = await this.deviceRepository.findOne({
      where: { userId, deviceToken }
    });

    const expiresAt = new Date(Date.now() + REFRESH_TTL);

    if (session) {
      session.refreshTokenHash = refreshTokenHash;
      session.ipAddress = ip;
      session.deviceType = deviceType;
      session.deviceName = deviceName;
      session.expiresAt = expiresAt;
      session.isRevoked = false;

      return await this.deviceRepository.save(session);
    }
    const newSession = this.deviceRepository.create({
      userId,
      refreshTokenHash,
      ipAddress: ip,
      deviceType,
      deviceToken,
      deviceName,
      expiresAt,
      isRevoked: false,
    });

    return await this.deviceRepository.save(newSession);
  }
}

export default AuthService;


