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
import { SubAdminCredential } from "./subAdmin.credentials";

export enum SubAdminStatus {
    ACTIVE = "ACTIVE",
    BLOCKED = "BLOCKED",
    SUSPENDED = "SUSPENDED",
    DELETED = "DELETED",
}

export enum UserType {
    SUB_ADMIN = "SUB_ADMIN",
}

@Entity({ name: "sub_admins" })
@Index(["phoneNumber"], { unique: true })
@Index(["status"])
@Index(["createdAt"])
export class SubAdmin {
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
        default: UserType.SUB_ADMIN,
    })
    userType: UserType;

    @Column({
        type: "enum",
        enum: SubAdminStatus,
        default: SubAdminStatus.ACTIVE,
    })
    status: SubAdminStatus;

    @Column({ default: false })
    isVerified: boolean;

    @Column({ type: "json", nullable: true })
    address?: Record<string, any>;

    @Column({ type: "json", nullable: true })
    coordinates?: { lat: number; lng: number };

    @Column({ nullable: true, select: false })
    otp?: string; // select: false for security

    @Column({ name: "profile_image", nullable: true })
    profileImage?: string;

    @Column({ type: "timestamp", nullable: true })
    otpExpireTime?: Date;

    @OneToOne(() => SubAdminCredential, (credential) => credential.user, {
        cascade: true,
        onDelete: "CASCADE",
    })
    @JoinColumn({ name: "credential_id" })
    credential: SubAdminCredential;

    @CreateDateColumn({ name: "created_at" })
    createdAt: Date;

    @UpdateDateColumn({ name: "updated_at" })
    updatedAt: Date;

    @DeleteDateColumn({ name: "deleted_at" })
    deletedAt?: Date;
}