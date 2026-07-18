# syntax=docker/dockerfile:1.25

FROM --platform=$BUILDPLATFORM node:22.23.1-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN --mount=type=cache,target=/root/.npm npm ci
RUN --mount=type=cache,target=/root/.npm \
    if [ -f vendor/product-release/cerebro-slack-companion.tgz ] && [ -f vendor/product-release/cerebro-sdk.tgz ]; then \
      npm install --no-save --package-lock=false --ignore-scripts \
        ./vendor/product-release/cerebro-sdk.tgz \
        ./vendor/product-release/cerebro-slack-companion.tgz; \
    fi

FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM --platform=$BUILDPLATFORM node:22.23.1-slim AS prod-deps
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev
RUN --mount=type=cache,target=/root/.npm \
    if [ -f vendor/product-release/cerebro-slack-companion.tgz ] && [ -f vendor/product-release/cerebro-sdk.tgz ]; then \
      npm install --omit=dev --no-save --package-lock=false --ignore-scripts \
        ./vendor/product-release/cerebro-sdk.tgz \
        ./vendor/product-release/cerebro-slack-companion.tgz; \
    fi

FROM --platform=$TARGETPLATFORM node:22.23.1-slim AS runtime
WORKDIR /app
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
COPY --from=prod-deps /app/package.json ./package.json
COPY --from=prod-deps /app/package-lock.json ./package-lock.json
COPY --from=prod-deps /app/vendor ./vendor
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
CMD ["node", "dist/src/index.js"]
