import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  Index,
  JoinColumn
} from "typeorm";

import { SuperAdmin } from "../entities/superAdmin.enities";

@Entity({ name: "device_sessions" })
@Index(["userId"])
@Index(["refreshTokenHash"])
@Index(["isRevoked"])
@Index(["userId", "deviceToken"])
export class DeviceSession {

  @PrimaryGeneratedColumn("increment")
  id: number;

  @Column({ name: "user_id" })
  userId: number;

  @Column({ nullable: true })
  refreshTokenHash: string;

  @Column({ name: "device_name", nullable: true })
  deviceName?: string;

  @Column({ name: "device_type", nullable: true })
  deviceType?: string;

  @Column({ name: "device_token", nullable: true })
  deviceToken?: string;

  @Column({ name: "ip_address", nullable: true })
  ipAddress?: string;

  @Column({ name: "user_agent", nullable: true })
  userAgent?: string;

  @Column({ name: "expires_at", type: "timestamp" })
  expiresAt: Date;

  @Column({ name: "last_used_at", type: "timestamp", nullable: true })
  lastUsedAt?: Date;

    @Column({ default: false })
  success: boolean;

  @CreateDateColumn({ name: "login_at" })
  loginAt: Date;

  @Column({ name: "is_revoked", default: false })
  isRevoked: boolean;

  @ManyToOne(() => SuperAdmin, { onDelete: "CASCADE" })
  @JoinColumn({ name: "user_id" })
  user: SuperAdmin;

  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;
}