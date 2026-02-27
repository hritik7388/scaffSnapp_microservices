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
export class SubAdminCredential {
  @PrimaryGeneratedColumn("increment")
  id: number;

  @Column({ length: 255, unique: true }) // UNIQUE handled here
  email: string;

  @Column({
    name: "password_hash",
    length: 255,
    select: false, // 🔐 password never returned by default
  })
  passwordHash: string;

  @Column({
    name: "must_change_password",
    default: true, // 🔥 by default true for new accounts
  })
  mustChangePassword: boolean;
  // 🔐 Login security fields
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

  // 🔗 Relation
  @OneToOne(() => SubAdmin, (subAdmin) => subAdmin.credential, {
    onDelete: "CASCADE",
  })
  user: SubAdmin;

  // 📅 Timestamps
  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;

  @UpdateDateColumn({ name: "updated_at" })
  updatedAt: Date;

  @DeleteDateColumn({ name: "deleted_at" })
  deletedAt?: Date;
}