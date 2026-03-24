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
import { ForgetPasswordDTO, RefreshTokenDTO, ResetPasswordDTO, SuperAdminDTO } from '../schemas/superAdminSchema';
import { DeviceSession } from '../entities/device-session.entity';
import { config } from '../config/config';
import { producer } from "../events/kafka";
import logger from "../config/logger";


const FAIL_TTL = 180;
const MAX_FAILS = 3;
const REFRESH_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days


const FP_TOKEN_TTL = 180; // 3 minutes
const FP_RATE_TTL = 120; // 2 minutes
const FP_MAX_REQUESTS = 3;
export const TOPICS = {
  SUBADMIN_REGISTERED: "subadmin.registered",
};


class SuperAdminService {
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
    const tokens = this.generateTokens(credential.user.id, credential.user.userType);
    await redisClient.setex(
      `auth:${credential.user.id}:${tokens.accessToken}`, // key
      60 * 60 * 24,                           // 24h in seconds
      tokens.accessToken                       // value
    );
    await this.createDeviceSession(
      credential.user.id,
      tokens.refreshToken,
      ip,
      data.deviceType,
      data.deviceName,
      data.deviceToken
    );
    await this.auditLogin(credential.id, ip, true)

    return {
      message: "Login successful",
      tokens: tokens
    };


  }

  async forgotPassword(data: ForgetPasswordDTO) {
    await this.checkResetRate(data.email);
    const credential = await this.credentialRepository.findOne({
      where: { email: data.email },
    });

    if (!credential) {
      return {
        message: "If the email exists, a reset link has been sent.",
      };
    }
    const token = await this.createResetToken(data.email);
    return {
      message: "If the email exists, a reset link has been sent.",
      resetToken: token,
    };
  }

  async resetPassword(data: ResetPasswordDTO) {
    const { email, resetToken, newPassword } = data;
    const tokenKey = `reset:token:${email}`;
    const storedHash = await redisClient.get(tokenKey);
    if (!storedHash || storedHash !== this.hashToken(resetToken)) {
      throw createError("Invalid or expired reset token", 400);
    }
    const credential = await this.getCredentialWithUser(email);
    this.validateUserStatus(credential.user);
    await this.updatePasswordAndRevokeSessions(credential, newPassword);
    await redisClient.del(tokenKey);
    await redisClient.del(`fail:${email}`);
    await redisClient.del(`block:${email}`);
    return {
      message: "Password reset successful",
    };
  }

  async createSubAdmin(superAdminId: number, payload: any) {
    const eventPayload = {
      eventType: "SUBADMIN_REGISTERED",
      firstName: payload.firstName,
      lastName: payload.lastName,
      email: payload.email,
      phoneNumber: payload.phoneNumber,
      countryCode: payload.countryCode,
      profileImage: payload.profileImage,
      address: payload.address,
      coordinates: payload.coordinates,
      createdById: superAdminId,
      createdByRole: "SUPER_ADMIN",
      timestamp: new Date(),
    };

    await producer.send({
      topic: TOPICS.SUBADMIN_REGISTERED,
      messages: [
        {
          key: payload.email,
          value: JSON.stringify(eventPayload),
        },
      ],
    });

    logger.info(
      `SubAdmin creation event published by SuperAdmin ID: ${superAdminId}`
    );
  }

  async refreshToken(data: RefreshTokenDTO) {
    const tokens = await this.refresh(
      data.refreshToken,
      data.deviceToken
    );
    return {
      message: "Token refreshed successfully",
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }



  private async updatePasswordAndRevokeSessions(
    credential: SuperAdminCredential,
    newPassword: string
  ) {
    credential.passwordHash = await bcrypt.hash(newPassword, 12);
    credential.failedLoginAttempts = 0;
    credential.accountLockedUntil = null;
    await this.credentialRepository.save(credential);
    await this.deviceRepository.update(
      { userId: credential.user.id },
      { isRevoked: true }
    );
  }

  private async checkResetRate(email: string) {
    const rateKey = `reset:rate:${email}`;
    const attempts = await redisClient.incr(rateKey);
    if (attempts === 1) {
      await redisClient.expire(rateKey, FP_RATE_TTL);
    }
    if (attempts > FP_MAX_REQUESTS) {
      throw createError("Too many requests. Try again later.", 429);
    }
  }

  private async createResetToken(email: string) {
    const rawToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = this.hashToken(rawToken);
    await redisClient.setex(
      `reset:token:${email}`,
      FP_TOKEN_TTL,
      hashedToken
    );
    return rawToken; // send this in email
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
      throw createError("Not authorized or Not SuperAdmin", 403);
    }
  }

  private async verifyPassword(password: string, credential: SuperAdminCredential) {
    const cacheKey = `login-ok:${credential.email}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) {
      return true;
    }
    const isValid = await bcrypt.compare(password, credential.passwordHash);

    if (!isValid) {
      await this.increaseFailCount(credential.email);
      throw createError("Invalid credentials", 401);
    }
    await redisClient.setex(cacheKey, 10, "ok");
  }

  private async increaseFailCount(email: string) {
    const credential = await this.credentialRepository.findOne({
      where: { email },
      relations: ["user"]
    });
    const redisFailKey = `fail:${email}`;
    const redisBlockKey = `block:${email}`;
    const attempts = await redisClient.incr(redisFailKey);
    if (attempts === 1) {
      await redisClient.expire(redisFailKey, FAIL_TTL);
    }
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

  private generateTokens(userId: number, role: UserType) {
    const accessToken = jwt.sign(
      { sub: userId, role: role, type: "access" },
      config.JWT_ACCESS_SECRET as jwt.Secret,   // ✅ cast to Secret
      { expiresIn: process.env.JWT_EXPIRES_IN || "24h" } as SignOptions
    );
    const refreshToken = jwt.sign(
      { sub: userId, role: role, type: "refresh" },
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

  private async auditLogin(
    userId: number,
    ip: string,
    success: boolean
  ) {

    await this.credentialRepository.save({
      id: userId,
      ipAddress: ip,
      success,
      loginAt: new Date()
    })
  }

  private async refresh(refreshToken: string, deviceToken: string) {
    if (!refreshToken || !deviceToken) {
      throw createError("Refresh token and device token required", 400);
    }
    let payload: any;
    try {
      payload = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET, {
        algorithms: ["HS256"], // 🔐 Restrict algorithm
      }) as { sub: string; type: string };
    } catch {
      throw createError("Invalid or expired refresh token", 401);
    }
    if (!payload?.sub || payload.type !== "refresh") {
      throw createError("Invalid token payload", 401);
    }
    const userId = payload.sub;
    const session = await this.deviceRepository.findOne({
      where: { userId, deviceToken },
    });
    if (!session) {
      throw createError("Session not found", 401);
    }
    if (session.isRevoked) {
      throw createError("Session revoked. Please login again.", 401);
    }
    if (!session.expiresAt || session.expiresAt < new Date()) {
      throw createError("Session expired. Please login again.", 401);
    }
    const incomingHash = this.hashToken(refreshToken);
    if (
      !session.refreshTokenHash ||
      !crypto.timingSafeEqual(
        Buffer.from(incomingHash),
        Buffer.from(session.refreshTokenHash)
      )
    ) {
      throw createError("Invalid refresh token", 401);
    }

    const userRole = payload.role as UserType;
    const tokens = this.generateTokens(userId, userRole);
    session.refreshTokenHash = this.hashToken(tokens.refreshToken);
    session.expiresAt = new Date(Date.now() + REFRESH_TTL);
    session.isRevoked = false;
    await this.deviceRepository.save(session);
    return tokens;
  }
}

export default SuperAdminService;


