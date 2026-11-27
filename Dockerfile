# Multi-stage Dockerfile building both Go vectoll-gate and Node 24 Facilitator/Console
FROM golang:1.23-alpine AS gate-builder
WORKDIR /src/services/gate
COPY services/gate/ ./
RUN CGO_ENABLED=0 go build -o /out/vectoll-gate ./cmd/vectoll-gate

FROM node:24-bookworm-slim AS node-runtime
RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /app
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/ ./packages/
COPY apps/ ./apps/
COPY examples/ ./examples/
COPY --from=gate-builder /out/vectoll-gate /usr/local/bin/vectoll-gate
RUN pnpm install --no-frozen-lockfile && pnpm build

EXPOSE 4020 4021 4022
CMD ["node", "packages/cli/dist/bin.js", "dev", "--config", "examples/global-cloud-ai/vectoll.yaml"]
