import * as express from 'express';

declare global {
    namespace Express {
        export interface Request {
            userId?: number; // optional to handle public routes where userId might not exist
            token?: string;  // optional for the same reason
        }
    }
}