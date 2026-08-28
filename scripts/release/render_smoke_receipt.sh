#!/usr/bin/env bash
set -euo pipefail

source_receipt="${CEREBRO_SMOKE_SOURCE_RECEIPT:-}"
out="${CEREBRO_SMOKE_OUTPUT:-}"
candidate_commit="${CEREBRO_SMOKE_CANDIDATE_COMMIT:-}"
runtime_ref="${CEREBRO_SMOKE_RUNTIME_IMAGE:-}"
environment_class="${CEREBRO_SMOKE_ENVIRONMENT_CLASS:-ephemeral}"
soak_seconds="${CEREBRO_SMOKE_SOAK_SECONDS:-}"
producer_workflow="${CEREBRO_SMOKE_PRODUCER_WORKFLOW:-}"
producer_run_url="${CEREBRO_SMOKE_RUN_URL:-}"
completed_at="${CEREBRO_SMOKE_COMPLETED_AT:-$(date -u +'%Y-%m-%dT%H:%M:%SZ')}"

fail() {
  echo "ERROR: portable smoke receipt: $*" >&2
  exit 1
}

[ -f "${source_receipt}" ] || fail "CEREBRO_SMOKE_SOURCE_RECEIPT must name a qualification receipt"
[ -n "${out}" ] || fail "CEREBRO_SMOKE_OUTPUT is required"
[[ "${candidate_commit}" =~ ^[0-9a-f]{40}$ ]] || fail "candidate commit must be full lowercase hex"
[[ "${runtime_ref}" =~ ^ghcr\.io/[A-Za-z0-9_.-]+/cerebro:candidate-${candidate_commit}@sha256:[0-9a-f]{64}$ ]] || \
  fail "runtime image must pin the candidate manifest digest"
[[ "${environment_class}" =~ ^(ephemeral|canary|production)$ ]] || \
  fail "environment class must be ephemeral, canary, or production"
if ! [[ "${soak_seconds}" =~ ^[0-9]+$ ]] || \
  ((soak_seconds < 60 || soak_seconds > 1800)); then
  fail "soak duration must be between 60 and 1800 seconds"
fi
[ "${producer_workflow}" = .github/workflows/ephemeral-cerebro.yml ] || \
  fail "producer workflow must be Ephemeral Cerebro"
[[ "${producer_run_url}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$ ]] || \
  fail "producer run URL must be a bounded GitHub Actions run"
[ "$(jq -r .schema_version "${source_receipt}")" = cerebro.pr-rust-graph/v1 ] || \
  fail "source receipt has an unsupported schema"
[ "$(jq -r .status "${source_receipt}")" = passed ] || fail "source receipt did not pass"
[ "$(jq -r .commit "${source_receipt}")" = "${candidate_commit}" ] || \
  fail "source receipt is not bound to the candidate"
[ "$(jq '(.checks | length) == 17 and all(.checks[]; .status == "passed")' \
  "${source_receipt}")" = true ] || fail "source receipt does not contain 17 passed checks"

runtime_image="${runtime_ref%@*}"
runtime_digest="${runtime_ref##*@}"
jq -n \
  --arg candidate_commit "${candidate_commit}" \
  --arg runtime_image "${runtime_image}" \
  --arg runtime_image_digest "${runtime_digest}" \
  --arg environment_class "${environment_class}" \
  --argjson soak_seconds "${soak_seconds}" \
  --arg completed_at "${completed_at}" \
  --arg producer_workflow "${producer_workflow}" \
  --arg producer_run_url "${producer_run_url}" \
  --slurpfile qualification "${source_receipt}" \
  '{
    schema_version: "cerebro.smoke-receipt/v1",
    status: "passed",
    candidate_commit: $candidate_commit,
    runtime_image: $runtime_image,
    runtime_image_digest: $runtime_image_digest,
    web_image: null,
    web_image_digest: null,
    environment_class: $environment_class,
    soak_seconds: $soak_seconds,
    checks: ($qualification[0].checks | map({name, status, evidence})),
    completed_at: $completed_at,
    producer: {
      kind: "github_actions",
      workflow: $producer_workflow,
      run_url: $producer_run_url
    }
  }' > "${out}"
