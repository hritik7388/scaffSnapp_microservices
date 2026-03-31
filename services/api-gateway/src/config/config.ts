import dotenv from "dotenv";

dotenv.config();

const apiGatewayRequiredEnv = (key: string): string => {
    const value = process.env[key];
    if (!value) {
        throw new Error(`❌ Missing required environment variable: ${key}`);
    }
    return value;
};

interface ApiGatewayConfig {
    NODE_ENV: string;
    SERVICE_NAME: string;
    PORT: number;
    DEFAULT_TIMEOUT: string;
    REDIS_URL: string;
    JWT_ACCESS_SECRET: string;
    JWT_REFRESH_SECRET: string,
    JWT_EXPIRES_IN: string;
    GATEWAY_JWT_SECRET: string;
    GATEWAY_JWT_EXPIRES_IN: string;
    LOG_LEVEL: string;
    SUPERADMIN_SERVICE_URL: string;
    SUBADMIN_SERVICE_URL: string;
    ALLOWED_ORIGINS: string;
}

export const config: ApiGatewayConfig = {
    NODE_ENV: process.env.NODE_ENV || "development",

    SERVICE_NAME: process.env.SERVICE_NAME || require("../../package.json").name,

    PORT: Number(process.env.PORT) || 3000,
    DEFAULT_TIMEOUT: process.env.DEFAULT_TIMEOUT || "60s",

    REDIS_URL: apiGatewayRequiredEnv("REDIS_URL"),

    JWT_ACCESS_SECRET: apiGatewayRequiredEnv("JWT_ACCESS_SECRET"),

    JWT_REFRESH_SECRET: apiGatewayRequiredEnv("JWT_REFRESH_SECRET"),

    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "24h",

    GATEWAY_JWT_SECRET: apiGatewayRequiredEnv("GATEWAY_JWT_SECRET"),

    GATEWAY_JWT_EXPIRES_IN: process.env.GATEWAY_JWT_EXPIRES_IN || "1m",

    LOG_LEVEL: process.env.LOG_LEVEL || "info",
    SUPERADMIN_SERVICE_URL: apiGatewayRequiredEnv("SUPERADMIN_SERVICE_URL"),
    SUBADMIN_SERVICE_URL: apiGatewayRequiredEnv("SUBADMIN_SERVICE_URL"),

    ALLOWED_ORIGINS: (process.env.ALLOWED_ORIGINS || "http://localhost:3000")
};