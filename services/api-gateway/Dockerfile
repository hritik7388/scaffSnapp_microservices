# ------------------------------------------------------------
# Builder Stage
# ------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files
COPY services/api-gateway/package*.json ./
COPY services/api-gateway/tsconfig.json ./

# Install dependencies
RUN npm install

# Copy source code
COPY services/api-gateway/src ./src

# Build TypeScript
RUN npm run build

# Debug (optional)
RUN ls -la ./dist


# ------------------------------------------------------------
# Production Stage
# ------------------------------------------------------------
FROM node:22-alpine

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy build output
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

# Set environment
ENV NODE_ENV=production

# Install only production deps
RUN npm ci --omit=dev

# Fix permissions
RUN chown -R appuser:appgroup /app

# Switch to non-root
USER appuser

# Expose port
EXPOSE 3000

# Start app
CMD ["node", "dist/app.js"]