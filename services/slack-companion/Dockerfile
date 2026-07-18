# syntax=docker/dockerfile:1.25

FROM --platform=$BUILDPLATFORM node:22.23.1-slim AS deps
WORKDIR /workspace
COPY package.json package-lock.json ./
COPY apps ./apps
COPY services ./services
COPY sdk ./sdk
RUN --mount=type=cache,target=/root/.npm npm ci

FROM deps AS build
RUN npm run build --workspace @writer/cerebro-slack-host

FROM deps AS prod-deps
ENV NODE_ENV=production
RUN npm prune --omit=dev

FROM --platform=$TARGETPLATFORM node:22.23.1-slim AS runtime
WORKDIR /workspace
ARG CEREBRO_COMPANION_VERSION=local
ARG CEREBRO_COMPANION_COMMIT_SUBJECT
ARG CEREBRO_PRODUCT_RELEASE_REQUIRED=false
ARG CEREBRO_PRODUCT_RELEASE_VERSION
ARG CEREBRO_PRODUCT_RELEASE_COMMIT
ENV NODE_ENV=production \
    CEREBRO_COMPANION_VERSION="${CEREBRO_COMPANION_VERSION}" \
    CEREBRO_COMPANION_COMMIT_SUBJECT="${CEREBRO_COMPANION_COMMIT_SUBJECT}" \
    CEREBRO_PRODUCT_RELEASE_REQUIRED="${CEREBRO_PRODUCT_RELEASE_REQUIRED}" \
    CEREBRO_PRODUCT_RELEASE_VERSION="${CEREBRO_PRODUCT_RELEASE_VERSION}" \
    CEREBRO_PRODUCT_RELEASE_COMMIT="${CEREBRO_PRODUCT_RELEASE_COMMIT}"
LABEL org.opencontainers.image.source="https://github.com/writer/cerebro"
COPY --from=prod-deps /workspace/node_modules ./node_modules
COPY --from=prod-deps /workspace/sdk/typescript ./sdk/typescript
COPY --from=prod-deps /workspace/services/slack-companion/package.json ./services/slack-companion/package.json
COPY --from=prod-deps /workspace/services/slack-companion/node_modules ./services/slack-companion/node_modules
COPY --from=build /workspace/services/slack-companion/dist ./services/slack-companion/dist
CMD ["node", "services/slack-companion/dist/src/index.js"]
