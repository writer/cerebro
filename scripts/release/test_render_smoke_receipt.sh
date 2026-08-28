#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
renderer="${root}/scripts/release/render_smoke_receipt.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

candidate_sha="0123456789abcdef0123456789abcdef01234567"
runtime_digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
jq -n --arg commit "${candidate_sha}" '{
  schema_version:"cerebro.pr-rust-graph/v1",
  status:"passed",
  commit:$commit,
  checks:[range(0;17) | {name:("check-" + tostring), status:"passed", evidence:"bounded"}]
}' > "${tmp}/source.json"

render() {
  CEREBRO_SMOKE_SOURCE_RECEIPT="${tmp}/source.json" \
  CEREBRO_SMOKE_OUTPUT="${tmp}/smoke.json" \
  CEREBRO_SMOKE_CANDIDATE_COMMIT="${candidate_sha}" \
  CEREBRO_SMOKE_RUNTIME_IMAGE="${CEREBRO_SMOKE_RUNTIME_IMAGE:-ghcr.io/writer/cerebro:candidate-${candidate_sha}@${runtime_digest}}" \
  CEREBRO_SMOKE_ENVIRONMENT_CLASS="${CEREBRO_SMOKE_ENVIRONMENT_CLASS:-ephemeral}" \
  CEREBRO_SMOKE_SOAK_SECONDS="${CEREBRO_SMOKE_SOAK_SECONDS:-60}" \
  CEREBRO_SMOKE_PRODUCER_WORKFLOW=.github/workflows/ephemeral-cerebro.yml \
  CEREBRO_SMOKE_RUN_URL="${CEREBRO_SMOKE_RUN_URL:-https://github.com/writer/cerebro/actions/runs/12345}" \
  CEREBRO_SMOKE_COMPLETED_AT=2026-08-28T00:00:00Z \
    "${renderer}"
}

expect_failure() {
  expected="$1"
  shift
  if "$@" 2> "${tmp}/error"; then
    echo "ERROR: renderer accepted an invalid portable smoke receipt" >&2
    exit 1
  fi
  grep -Fq "${expected}" "${tmp}/error"
}

render
jq -e '
  .schema_version == "cerebro.smoke-receipt/v1" and
  .candidate_commit == $commit and
  .runtime_image == $image and
  .runtime_image_digest == $digest and
  .web_image == null and
  .web_image_digest == null and
  .environment_class == "ephemeral" and
  .soak_seconds == 60 and
  (.checks | length) == 17 and
  .completed_at == "2026-08-28T00:00:00Z"
' \
  --arg commit "${candidate_sha}" \
  --arg image "ghcr.io/writer/cerebro:candidate-${candidate_sha}" \
  --arg digest "${runtime_digest}" \
  "${tmp}/smoke.json" >/dev/null

CEREBRO_SMOKE_RUNTIME_IMAGE="ghcr.io/writer/cerebro:candidate-${candidate_sha}" \
  expect_failure "must pin the candidate manifest digest" render
CEREBRO_SMOKE_ENVIRONMENT_CLASS=private-production \
  expect_failure "must be ephemeral, canary, or production" render
CEREBRO_SMOKE_SOAK_SECONDS=59 \
  expect_failure "between 60 and 1800" render
CEREBRO_SMOKE_RUN_URL="https://example.test/private/run" \
  expect_failure "must be a bounded GitHub Actions run" render

jq '.checks[0].status = "failed"' "${tmp}/source.json" > "${tmp}/failed-source.json"
mv "${tmp}/failed-source.json" "${tmp}/source.json"
expect_failure "does not contain 17 passed checks" render

echo "portable smoke receipt renderer tests passed"
