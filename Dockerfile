FROM golang:1.27.3-alpine AS helpers
WORKDIR /agent
COPY services/agent/go.mod services/agent/*.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /agent-helper .
WORKDIR /intelligence
COPY services/intelligence/go.mod services/intelligence/*.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /intelligence-unzip .
FROM node:22.22.0-bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY apps/api/package*.json ./
RUN npm ci --no-audit --no-fund
COPY apps/api/prisma ./prisma
RUN npx --no-install prisma generate
COPY apps/api/tsconfig.json ./
COPY apps/api/src ./src
RUN npm run build
FROM node:22.22.0-bookworm-slim AS runtime
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/JojoShine/self-guard" org.opencontainers.image.revision=$SOURCE_REVISION org.opencontainers.image.licenses="LicenseRef-SelfGuard-Internal"
RUN apt-get update && apt-get install -y --no-install-recommends openssl openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY apps/api/scripts ./scripts
COPY bin ./bin
COPY --from=helpers /agent-helper /usr/local/bin/selfguard-agent
COPY --from=helpers /intelligence-unzip /usr/local/bin/intelligence-unzip
RUN mkdir -p /var/lib/selfguard/intelligence /var/lib/selfguard/agent-artifacts && chown -R node:node /var/lib/selfguard && chmod 700 /var/lib/selfguard/agent-artifacts && chmod +x /app/bin/*
ENV NODE_ENV=production PORT=8080 INTELLIGENCE_ARCHIVE_READER=/usr/local/bin/intelligence-unzip AGENT_RULE_TEST_BINARY=/usr/local/bin/selfguard-agent INTELLIGENCE_ARTIFACT_DIR=/var/lib/selfguard/intelligence AGENT_ARTIFACT_DIR=/var/lib/selfguard/agent-artifacts
USER node
EXPOSE 8080
CMD ["node","dist/main.js"]
