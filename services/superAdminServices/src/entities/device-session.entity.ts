// src/modules/auth/entities/device-session.entity.ts

import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    ManyToOne,
    CreateDateColumn,
    Index,
} from 'typeorm';
import { SuperAdmin } from '../entities/superAdmin.enities';

@Entity({ name: 'device_sessions' })
@Index(['userId'])
@Index(['refreshTokenHash'])
@Index(['isRevoked'])
export class DeviceSession {
    @PrimaryGeneratedColumn('increment')
    id: number;

    @Column({ name: 'user_id' })
    userId: number;

    @Column({ nullable: true })
    refreshTokenHash: string;

    @Column({ name: 'device_name', nullable: true })
    deviceName?: string;

    @Column({ name: 'device_type', nullable: true })
    deviceType?: string; // ios | android | web

    @Column({ name: 'device_token', nullable: true })
    deviceToken?: string; // FCM token

    @Column({ name: 'ip_address', nullable: true })
    ipAddress?: string;

    @Column({ name: 'expires_at', type: 'timestamp' })
    expiresAt: Date;

    @Column({ name: 'is_revoked', default: false })
    isRevoked: boolean;

    @ManyToOne(() => SuperAdmin, { onDelete: 'CASCADE' })
    user: SuperAdmin;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;
}