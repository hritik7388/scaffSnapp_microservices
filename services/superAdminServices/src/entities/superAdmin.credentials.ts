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
import { SuperAdmin } from "./superAdmin.enities";

@Entity({ name: "super_admin_credentials" })
@Index(["accountLockedUntil"])
export class SuperAdminCredential {
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

 
  @OneToOne(() => SuperAdmin, (superAdmin) => superAdmin.credential, {
    onDelete: "CASCADE",
  })
  user: SuperAdmin;

 
  @CreateDateColumn({ name: "created_at" })
  createdAt: Date;

  @UpdateDateColumn({ name: "updated_at" })
  updatedAt: Date;

  @DeleteDateColumn({ name: "deleted_at" })
  deletedAt?: Date;
}