
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  Index,
} from "typeorm";
import { SubAdmin } from "./subAdmin.enities";

@Entity({ name: "sub_admin_credentials" })
@Index(["accountLockedUntil"])
@Index(["email"])
export class SubAdminCredential {

  @PrimaryGeneratedColumn("increment")
  id: number;

  @Column({ length: 255, unique: true })
  email: string;

  @Column({
    name: "password_hash",
    length: 255,
    select: false,
  })
  passwordHash: string;

  @Column({
    name: "must_change_password",
    default: true,
  })
  mustChangePassword: boolean;

  @Column({
    name: "failed_login_attempts",
    default: 0,
  })
  failedLoginAttempts: number;

  @Column({
    name: "account_locked_until",
    type: "timestamp",
    nullable: true,
  })
  accountLockedUntil?: Date | null;

  @Column({
    name: "password_changed_at",
    type: "timestamp",
    nullable: true,
  })
  passwordChangedAt?: Date;

  @Column({
    name: "last_login_at",
    type: "timestamp",
    nullable: true,
  })
  lastLoginAt?: Date;

  @Column({
    name: "two_factor_enabled",
    default: false,
  })
  twoFactorEnabled: boolean;

  @Column({
    name: "two_factor_secret",
    nullable: true,
  })
  twoFactorSecret?: string;

  @Column({
    name: "password_reset_token",
    nullable: true,
  })
  passwordResetToken?: string;

  @Column({
    name: "password_reset_expires",
    type: "timestamp",
    nullable: true,
  })
  passwordResetExpires?: Date;

  @OneToOne(() => SubAdmin, (subAdmin) => subAdmin.credential, {
    onDelete: "CASCADE",
  })
  user: SubAdmin;

  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;

  @UpdateDateColumn({ name: "updated_at" })
  updatedAt: Date;

  @DeleteDateColumn({ name: "deleted_at" })
  deletedAt?: Date;
}

