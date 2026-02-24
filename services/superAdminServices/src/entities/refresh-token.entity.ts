// src/modules/auth/entities/refresh-token.entity.ts

import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    ManyToOne,
    CreateDateColumn,
    Index,
} from 'typeorm';
import { SuperAdmin } from '../entities/superAdmin.enities';

@Entity({ name: 'refresh_tokens' })
@Index(['userId'])
@Index(['expiresAt'])
@Index(['isRevoked'])
export class RefreshToken {
    @PrimaryGeneratedColumn('increment')
    id: number;

    @Column({ name: 'user_id' })
    userId: number;

    @Column({ name: 'token_hash', length: 255 })
    tokenHash: string; // hashed refresh token

    @Column({ name: 'expires_at', type: 'timestamp' })
    expiresAt: Date;

    @Column({ name: 'is_revoked', default: false })
    isRevoked: boolean;

    @Column({ name: 'device_info', nullable: true })
    deviceInfo?: string;

    @Column({ name: 'ip_address', nullable: true })
    ipAddress?: string;

    @ManyToOne(() => SuperAdmin, { onDelete: 'CASCADE' })
    user: SuperAdmin;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;
}