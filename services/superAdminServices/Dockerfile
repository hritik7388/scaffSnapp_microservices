# ------------------------------------------------------------
# Builder Stage
# ------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy only package.json & tsconfig for caching
COPY services/superadminService/package*.json ./ 
COPY services/superadminService/tsconfig.json ./

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

# Create non-root user and group in a single layer
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy build output and package.json from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

# Set environment
ENV NODE_ENV=production

# Install production dependencies and fix permissions in one layer
RUN npm ci --omit=dev \
    && chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3001

# Start the service
CMD ["node", "dist/app.js"]
