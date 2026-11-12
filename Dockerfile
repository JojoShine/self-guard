ARG GO_BUILD_IMAGE=golang:1.27.3-alpine
ARG NODE_BUILD_IMAGE=node:22.22.0-bookworm-slim
ARG NUCLEI_IMAGE=projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb
FROM ${NUCLEI_IMAGE} AS native-engine
FROM ${GO_BUILD_IMAGE} AS helpers
ENV GOTOOLCHAIN=local
WORKDIR /agent
COPY services/agent/go.mod services/agent/*.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /agent-helper .
RUN mkdir -p /probe-artifacts && for arch in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o /probe-artifacts/selfguard-database-probe-linux-$arch .; done
WORKDIR /intelligence
COPY services/intelligence/go.mod services/intelligence/*.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /intelligence-unzip .
WORKDIR /scanner
COPY services/scanner/ ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /selfguard-scanner ./cmd/scanner
WORKDIR /access-probe
COPY services/access-probe/ ./
RUN go test ./... && mkdir -p /probe-artifacts && for arch in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o /probe-artifacts/selfguard-access-probe-linux-$arch .; done
WORKDIR /suricata-bridge
COPY services/suricata-bridge/ ./
RUN go test ./... && for arch in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o /probe-artifacts/selfguard-suricata-bridge-linux-$arch .; done
FROM ${NODE_BUILD_IMAGE} AS build
COPY --from=helpers /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY apps/api/package*.json ./
RUN npm ci --no-audit --no-fund
COPY apps/api/prisma ./prisma
RUN npx --no-install prisma generate
COPY apps/api/tsconfig.json ./
COPY apps/api/src ./src
RUN npm run build
FROM ${NODE_BUILD_IMAGE} AS runtime
COPY --from=helpers /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/JojoShine/self-guard" org.opencontainers.image.revision=$SOURCE_REVISION org.opencontainers.image.licenses="LicenseRef-SelfGuard-Internal"
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && apt-get -o Acquire::Retries=3 update && apt-get install -y --no-install-recommends openssl openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/prisma ./prisma
COPY apps/api/scripts ./scripts
COPY apps/api/rule-sources ./rule-sources
COPY bin ./bin
COPY --from=helpers /probe-artifacts /opt/selfguard-probes
COPY --from=helpers /agent-helper /usr/local/bin/selfguard-agent
COPY --from=helpers /intelligence-unzip /usr/local/bin/intelligence-unzip
COPY --from=helpers /selfguard-scanner /usr/local/bin/selfguard-scanner
COPY --from=native-engine /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY scripts/sync-probe-library.cjs ./scripts/sync-probe-library.cjs
RUN mkdir -p /var/lib/selfguard/access-evidence /var/lib/selfguard/intelligence /var/lib/selfguard/agent-artifacts && chown -R node:node /var/lib/selfguard && chmod 700 /var/lib/selfguard/access-evidence /var/lib/selfguard/agent-artifacts && chmod +x /app/bin/*
ENV NODE_ENV=production PORT=8080 INTELLIGENCE_ARCHIVE_READER=/usr/local/bin/intelligence-unzip AGENT_RULE_TEST_BINARY=/usr/local/bin/selfguard-agent INTELLIGENCE_ARTIFACT_DIR=/var/lib/selfguard/intelligence AGENT_ARTIFACT_DIR=/var/lib/selfguard/agent-artifacts
ENV SCAN_WORKER_BINARY=/usr/local/bin/selfguard-scanner NUCLEI_BINARY=/usr/local/bin/nuclei
ENV PROBE_RULE_LIBRARY_DIR=/var/lib/selfguard/intelligence/probe-rule-library PROBE_RULE_LIBRARY_SOURCE=/var/lib/selfguard/intelligence/probe-rule-library-source.json PROBE_RULE_DOWNLOAD_DIR=/var/lib/selfguard/intelligence/probe-rule-downloads
USER node
EXPOSE 8080
CMD ["node","dist/main.js"]

ENV ACCESS_EVIDENCE_DIR=/var/lib/selfguard/access-evidence
