import dotenv from "dotenv";

dotenv.config();

const superAdminRequiredEnv = (key: string): string => {
    const value = process.env[key];
    if (!value) {
        throw new Error(`❌ Missing required environment variable: ${key}`);
    }
    return value;
};

interface SuperAdminConfig {
    NODE_ENV: string;
    SERVICE_NAME: string;
    PORT: number;
    DATABASE_URL: string;
    REDIS_URL: string;
    KAFKA_BROKER: string;
    JWT_ACCESS_SECRET: string;
    JWT_REFRESH_SECRET: string,
    JWT_EXPIRES_IN: string;
    LOG_LEVEL: string;
    ALLOWED_ORIGINS: string;
}

export const config: SuperAdminConfig = {
    NODE_ENV: process.env.NODE_ENV || "development",

    SERVICE_NAME: process.env.SERVICE_NAME || require("../../package.json").name,

    PORT: Number(process.env.PORT) || 3001,

    DATABASE_URL: superAdminRequiredEnv("DATABASE_URL"),

    REDIS_URL: superAdminRequiredEnv("REDIS_URL"),

    KAFKA_BROKER: superAdminRequiredEnv("KAFKA_BROKER"),

    JWT_ACCESS_SECRET: superAdminRequiredEnv("JWT_ACCESS_SECRET"),

    JWT_REFRESH_SECRET: superAdminRequiredEnv("JWT_REFRESH_SECRET"),

    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "24h",

    LOG_LEVEL: process.env.LOG_LEVEL || "info",

    ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || "http://localhost:3000")
};