import cors, { CorsOptions } from 'cors';
import { config } from '../config/config'; 
const allowedOrigins = new Set(
  config.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
);

const corsOptions: CorsOptions = {
  origin: (origin, callback) => { 
    if (!origin) return callback(null, true);

    // Check existence in the Set
    if (allowedOrigins.has(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
  ],
};

export const corsMiddleware = cors(corsOptions);