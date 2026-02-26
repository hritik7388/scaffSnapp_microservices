import 'dotenv/config';
import { DataSource } from "typeorm";
import { SuperAdmin } from "./entities/superAdmin.enities";
import { SuperAdminCredential } from "./entities/superAdmin.credentials";
import { DeviceSession } from "./entities/device-session.entity";

const isProduction = process.env.NODE_ENV === "production";

export const AppDataSource = new DataSource({
    type: "mysql",
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT) || 3306,
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,

    synchronize: true, // ❌ never true in production
    logging: !isProduction,

    entities: [SuperAdmin, SuperAdminCredential, DeviceSession],
    migrations: ["dist/migrations/*.js"],

    extra: {
        connectionLimit: Number(process.env.DB_CONNECTION_LIMIT) || 20,
        waitForConnections: true,
        queueLimit: 0,
        connectTimeout: Number(process.env.DB_CONNECT_TIMEOUT) || 10000,
        acquireTimeout: Number(process.env.DB_ACQUIRE_TIMEOUT) || 10000,
    },
});