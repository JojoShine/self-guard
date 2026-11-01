FROM golang:1.27.3-alpine AS rule-test
WORKDIR /src
COPY services/agent/go.mod services/agent/*.go ./
RUN CGO_ENABLED=0 go build -o /agent .
FROM golang:1.27.3-alpine AS intelligence-reader
WORKDIR /src
COPY services/intelligence/go.mod services/intelligence/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /intelligence-unzip .
FROM node:22-bookworm-slim
RUN --mount=type=tmpfs,target=/tmp --mount=type=tmpfs,target=/var/lib/apt/lists --mount=type=tmpfs,target=/var/cache/apt apt-get update && apt-get install -y --no-install-recommends openssl openssh-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY apps/api/package*.json ./
RUN npm ci --no-audit --no-fund
COPY apps/api/prisma ./prisma
RUN npx prisma generate
COPY apps/api/tsconfig.json ./
COPY apps/api/src ./src
COPY apps/api/scripts ./scripts
RUN npm run build
COPY --from=rule-test /agent /usr/local/bin/selfguard-agent
COPY --from=intelligence-reader /intelligence-unzip /usr/local/bin/intelligence-unzip
ENV INTELLIGENCE_ARCHIVE_READER=/usr/local/bin/intelligence-unzip
ENV AGENT_RULE_TEST_BINARY=/usr/local/bin/selfguard-agent
RUN mkdir -p /var/lib/selfguard/intelligence /var/lib/selfguard/agent-artifacts && chown -R node:node /var/lib/selfguard && chmod 700 /var/lib/selfguard/agent-artifacts
ENV INTELLIGENCE_ARTIFACT_DIR=/var/lib/selfguard/intelligence
ENV AGENT_ARTIFACT_DIR=/var/lib/selfguard/agent-artifacts
USER node
EXPOSE 4000
CMD ["sh", "-c", "npx prisma migrate deploy && npx tsx prisma/seed.ts && node dist/main.js"]
