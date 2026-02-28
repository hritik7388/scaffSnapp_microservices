import 'dotenv/config';
import { DataSource } from "typeorm";
import { SubAdmin } from "./entities/subAdmin.enities";
import { SubAdminCredential } from "./entities/subAdmin.credentials";
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

    entities: [SubAdmin, SubAdminCredential, DeviceSession],
    migrations: ["dist/migrations/*.js"],

    extra: {
        connectionLimit: Number(process.env.DB_CONNECTION_LIMIT) || 20,
        waitForConnections: true,
        queueLimit: 0,
        connectTimeout: Number(process.env.DB_CONNECT_TIMEOUT) || 10000,
        acquireTimeout: Number(process.env.DB_ACQUIRE_TIMEOUT) || 10000,
    },
});