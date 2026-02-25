import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    OneToOne,
    CreateDateColumn,
    UpdateDateColumn,
    DeleteDateColumn,
    Index,
    JoinColumn,
} from "typeorm";
import { SuperAdminCredential } from "./superAdmin.credentials";

export enum SuperAdminStatus {
    ACTIVE = "ACTIVE",
    INACTIVE = "BLOCKED",
    SUSPENDED = "DELETED",
}

export enum UserType {
    SUPER_ADMIN = "SUPER ADMIN",
}

@Entity({ name: "super_admins" })
@Index(["phoneNumber"], { unique: true })
@Index(["status"])
@Index(["createdAt"])
export class SuperAdmin {
    @PrimaryGeneratedColumn("increment")
    id: number;

    @Column({ name: "first_name", length: 100 })
    firstName: string;

    @Column({ name: "last_name", length: 100 })
    lastName: string;

    @Column({ name: "phone_number", length: 20, nullable: true })
    phoneNumber?: string;

    @Column({ name: "country_code", length: 10, nullable: true })
    countryCode?: string;

    @Column({
        type: "enum",
        enum: UserType,
        default: UserType.SUPER_ADMIN,
    })
    userType: UserType;

    @Column({
        type: "enum",
        enum: SuperAdminStatus,
        default: SuperAdminStatus.ACTIVE,
    })
    status: SuperAdminStatus;

    @Column({ default: false })
    isVerified: boolean;

    @Column({ type: "json", nullable: true })
    address?: Record<string, any>;

    @Column({ type: "json", nullable: true })
    coordinates?: { lat: number; lng: number };

    @Column({ nullable: true, select: false })
    otp?: string; // select: false for security

    @Column({ type: "timestamp", nullable: true })
    otpExpireTime?: Date;

    @OneToOne(() => SuperAdminCredential, (credential) => credential.user, {
        cascade: true,
        onDelete: "CASCADE",
    })
    @JoinColumn({ name: "credential_id" })
    credential: SuperAdminCredential;

    @CreateDateColumn({ name: "created_at" })
    createdAt: Date;

    @UpdateDateColumn({ name: "updated_at" })
    updatedAt: Date;

    @DeleteDateColumn({ name: "deleted_at" })
    deletedAt?: Date;
}