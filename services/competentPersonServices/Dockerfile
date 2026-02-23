# ------------------------------------------------------------
# Builder Stage
# ------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy only package.json & tsconfig
COPY services/superadmin-service/package*.json ./ 
COPY services/superadmin-service/tsconfig.json ./

# Install dependencies
RUN npm install

# Copy source files
COPY services/superadmin-service/src ./src

# Build TypeScript
RUN npm run build

# Verify dist folder exists
RUN ls -la ./dist

# ------------------------------------------------------------
# Production Stage
# ------------------------------------------------------------
FROM node:22-alpine

WORKDIR /app

# Copy dist and package.json from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

# Set environment
ENV NODE_ENV=production

# Install only production dependencies
RUN npm ci --omit=dev

# Expose port
EXPOSE 3001

# Start the service
CMD ["node", "dist/app.js"]
