# syntax=docker/dockerfile:1.7

FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS dependencies
WORKDIR /workspace

COPY package.json package-lock.json ./
COPY apps/slack-companion/package.json ./apps/slack-companion/package.json
COPY apps/web/package.json ./apps/web/package.json
COPY sdk/typescript/package.json ./sdk/typescript/package.json

RUN --mount=type=cache,target=/root/.npm,sharing=locked \
    npm ci --workspace @writer/cerebro-web --include-workspace-root

FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS builder
WORKDIR /workspace

ARG NEXT_PUBLIC_CEREBRO_WEB_VERSION
ENV NEXT_PUBLIC_CEREBRO_WEB_VERSION=${NEXT_PUBLIC_CEREBRO_WEB_VERSION}
ENV NEXT_TELEMETRY_DISABLED=1

COPY --from=dependencies /workspace/node_modules ./node_modules
COPY --from=dependencies /workspace/apps/web/node_modules ./apps/web/node_modules
COPY package.json package-lock.json ./
COPY apps/web ./apps/web

RUN npm run build --workspace @writer/cerebro-web

FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS runner
WORKDIR /app/apps/web

ARG SOURCE_REVISION=unknown

ENV HOSTNAME=0.0.0.0
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
ENV PORT=3000

LABEL org.opencontainers.image.revision=${SOURCE_REVISION}
LABEL org.opencontainers.image.source="https://github.com/writer/cerebro"

RUN addgroup -S nodejs && adduser -S nextjs -G nodejs -u 10001

COPY --from=builder --chown=nextjs:nodejs /workspace/apps/web/.next/standalone /app

RUN test -f server.js \
    && test -d .next/static/chunks \
    && find .next/static/chunks -maxdepth 1 -type f -name '*.js' -print -quit | grep -q .

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then((response)=>{if(!response.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
