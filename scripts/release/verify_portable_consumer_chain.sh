#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

commit="${PORTABLE_CHAIN_COMMIT:-$(git rev-parse HEAD)}"
if ! [[ "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "portable consumer chain: commit must be a 40-character lowercase Git object ID" >&2
  exit 1
fi

bundle_root="$(mktemp -d "${TMPDIR:-/tmp}/cerebro-portable-consumer-chain.XXXXXX")"
cleanup() {
  rm -rf "${bundle_root}"
}
trap cleanup EXIT

make agent-service-lifecycle-check openapi-check openapi-ts-check

npm ci
npm run check --workspace @writer/cerebro-sdk
npm run check --workspace @writer/cerebro-web
npm run build --workspace @writer/cerebro-web
npm run check --workspace @writer/cerebro-slack-companion
npm run build --workspace @writer/cerebro-slack-companion

npm pack --workspace @writer/cerebro-sdk --pack-destination "${bundle_root}"
npm pack --workspace @writer/cerebro-slack-companion --pack-destination "${bundle_root}"
cp api/openapi.yaml "${bundle_root}/cerebro-openapi.yaml"
cp schemas/agent-service-lifecycle.schema.json "${bundle_root}/agent-service-lifecycle.schema.json"

sdk_archive_count="$(find "${bundle_root}" -maxdepth 1 -type f -name 'writer-cerebro-sdk-*.tgz' -print | wc -l | tr -d '[:space:]')"
slack_archive_count="$(find "${bundle_root}" -maxdepth 1 -type f -name 'writer-cerebro-slack-companion-*.tgz' -print | wc -l | tr -d '[:space:]')"
if [ "${sdk_archive_count}" -ne 1 ] || [ "${slack_archive_count}" -ne 1 ]; then
  echo "portable consumer chain: expected exactly one SDK archive and one Slack companion archive" >&2
  exit 1
fi
sdk_archive="$(find "${bundle_root}" -maxdepth 1 -type f -name 'writer-cerebro-sdk-*.tgz' -print -quit)"
slack_archive="$(find "${bundle_root}" -maxdepth 1 -type f -name 'writer-cerebro-slack-companion-*.tgz' -print -quit)"

version="candidate-${commit}"
runtime_digest="sha256:$(printf '0%.0s' {1..64})"
web_digest="sha256:$(printf '1%.0s' {1..64})"
manifest="${bundle_root}/cerebro-product-release.json"

python3 scripts/release/product_release.py build \
  --channel candidate \
  --version "${version}" \
  --commit "${commit}" \
  --runtime-image "ghcr.io/example/cerebro:${version}" \
  --runtime-digest "${runtime_digest}" \
  --web-image "ghcr.io/example/cerebro-web:${version}" \
  --web-digest "${web_digest}" \
  --slack-archive "${slack_archive}" \
  --slack-version "$(jq -r .version apps/slack-companion/package.json)" \
  --sdk-archive "${sdk_archive}" \
  --sdk-version "$(jq -r .version sdk/typescript/package.json)" \
  --openapi "${bundle_root}/cerebro-openapi.yaml" \
  --lifecycle-schema "${bundle_root}/agent-service-lifecycle.schema.json" \
  --bundle-root "${bundle_root}" \
  --out "${manifest}"

python3 scripts/release/product_release.py validate "${manifest}" --bundle-root "${bundle_root}"
