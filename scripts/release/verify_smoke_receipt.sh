#!/usr/bin/env bash
set -euo pipefail

smoke_url="${SMOKE_RECEIPT_URL:-}"
candidate_sha="${CANDIDATE_SHA:-}"
repository="${GITHUB_REPOSITORY:-}"
allowed_origins="${SMOKE_RECEIPT_ALLOWED_ORIGINS:-}"
notes_bound="${SMOKE_NOTES_BOUND:-false}"
out="${SMOKE_EVIDENCE_OUT:-${RUNNER_TEMP:-.}/smoke-evidence.json}"

fail() {
  echo "ERROR: smoke receipt: $*" >&2
  exit 1
}

if [ -z "${smoke_url}" ] || [ -z "${candidate_sha}" ] || [ -z "${repository}" ]; then
  fail "SMOKE_RECEIPT_URL, CANDIDATE_SHA, and GITHUB_REPOSITORY are required"
fi
if ! [[ "${candidate_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  fail "CANDIDATE_SHA must be a full lowercase commit"
fi
if [ "${notes_bound}" != true ]; then
  fail "release notes must bind the supplied receipt URL before verification"
fi

actions_prefix="https://github.com/${repository}/actions/runs/"
if [[ "${smoke_url}" == "${actions_prefix}"* ]]; then
  run_id="${smoke_url#"${actions_prefix}"}"
  [[ "${run_id}" =~ ^[0-9]+$ ]] || fail "same-repository Actions URL must end in a numeric run id"

  run="$(gh api "repos/${repository}/actions/runs/${run_id}")"
  [ "$(jq -r .status <<< "${run}")" = completed ] || fail "run ${run_id} is not terminal"
  [ "$(jq -r .conclusion <<< "${run}")" = success ] || fail "run ${run_id} did not conclude successfully"
  [ "$(jq -r .path <<< "${run}")" = .github/workflows/ephemeral-cerebro.yml ] || \
    fail "run ${run_id} is not Ephemeral Cerebro"
  [ "$(jq -r .event <<< "${run}")" = workflow_dispatch ] || \
    fail "run ${run_id} was not manually dispatched against a published candidate"
  [ "$(jq -r .head_branch <<< "${run}")" = main ] || \
    fail "run ${run_id} did not execute the Ephemeral Cerebro workflow from main"

  artifact_name="pr-rust-graph-${candidate_sha}"
  signed_artifact_name="signed-${artifact_name}"
  artifacts="$(gh api "repos/${repository}/actions/runs/${run_id}/artifacts?per_page=100")"
  artifact_count="$(jq --arg name "${artifact_name}" \
    '[.artifacts[] | select(.expired == false and .name == $name)] | length' <<< "${artifacts}")"
  signed_artifact_count="$(jq --arg name "${signed_artifact_name}" \
    '[.artifacts[] | select(.expired == false and .name == $name)] | length' <<< "${artifacts}")"
  [ "${signed_artifact_count}" -le 1 ] || \
    fail "run ${run_id} contains multiple signed smoke artifacts"
  portable=false
  if [ "${signed_artifact_count}" -eq 1 ]; then
    artifact_name="${signed_artifact_name}"
    portable=true
  elif [ "${artifact_count}" -ne 1 ]; then
    fail "run ${run_id} must contain one unexpired candidate smoke artifact; re-run the published-image smoke"
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  gh run download "${run_id}" --repo "${repository}" --name "${artifact_name}" --dir "${tmp}"
  receipt="${tmp}/receipt.json"
  [ -f "${receipt}" ] || fail "artifact ${artifact_name} does not contain receipt.json"
  [ "$(jq -r .schema_version "${receipt}")" = cerebro.pr-rust-graph/v1 ] || \
    fail "artifact ${artifact_name} has an unsupported schema"
  [ "$(jq -r .status "${receipt}")" = passed ] || fail "artifact ${artifact_name} did not pass"
  [ "$(jq -r .commit "${receipt}")" = "${candidate_sha}" ] || \
    fail "artifact ${artifact_name} is not bound to candidate ${candidate_sha}"

  owner="${repository%%/*}"
  image="$(jq -r .image "${receipt}")"
  image_prefix="ghcr.io/${owner}/cerebro-rust:candidate-${candidate_sha}@sha256:"
  image_digest="${image#"${image_prefix}"}"
  [[ "${image}" == "${image_prefix}"* && "${image_digest}" =~ ^[0-9a-f]{64}$ ]] || \
    fail "artifact ${artifact_name} did not exercise the attested published Rust candidate image"

  if [ "${portable}" = true ]; then
    portable_receipt="${tmp}/smoke-receipt.json"
    portable_signature="${portable_receipt}.sig"
    portable_certificate="${portable_receipt}.pem"
    [ -f "${portable_receipt}" ] && [ -f "${portable_signature}" ] && \
      [ -f "${portable_certificate}" ] || \
      fail "signed artifact ${artifact_name} is missing its portable receipt, signature, or certificate"
    expected_runtime_digest="${CANDIDATE_RUNTIME_DIGEST:-}"
    [[ "${expected_runtime_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
      fail "CANDIDATE_RUNTIME_DIGEST is required for a portable smoke receipt"
    [ "$(jq -r .schema_version "${portable_receipt}")" = cerebro.smoke-receipt/v1 ] || \
      fail "portable receipt has an unsupported schema"
    [ "$(jq -r .status "${portable_receipt}")" = passed ] || \
      fail "portable receipt did not pass"
    [ "$(jq -r .candidate_commit "${portable_receipt}")" = "${candidate_sha}" ] || \
      fail "portable receipt is not bound to candidate ${candidate_sha}"
    [ "$(jq -r .runtime_image "${portable_receipt}")" = \
      "ghcr.io/${repository}:candidate-${candidate_sha}" ] || \
      fail "portable receipt names the wrong candidate runtime image"
    [ "$(jq -r .runtime_image_digest "${portable_receipt}")" = \
      "${expected_runtime_digest}" ] || \
      fail "portable receipt runtime digest does not match the release candidate"
    [ "$(jq -r .environment_class "${portable_receipt}")" = ephemeral ] || \
      fail "same-repository Ephemeral Cerebro receipt must use environment_class ephemeral"
    [ "$(jq -r '.web_image == null and .web_image_digest == null' "${portable_receipt}")" = true ] || \
      fail "portable receipt must not claim an unexercised web image"
    [ "$(jq '(.checks | length) == 17 and all(.checks[]; .status == "passed")' \
      "${portable_receipt}")" = true ] || \
      fail "portable receipt does not contain the complete passed smoke check set"
    [ "$(jq -r .producer.workflow "${portable_receipt}")" = \
      .github/workflows/ephemeral-cerebro.yml ] || \
      fail "portable receipt has the wrong producer workflow"
    [ "$(jq -r .producer.run_url "${portable_receipt}")" = "${smoke_url}" ] || \
      fail "portable receipt producer run does not match the supplied receipt URL"
    cosign verify-blob \
      --signature "${portable_signature}" \
      --certificate "${portable_certificate}" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp \
      "^https://github.com/${repository}/.github/workflows/ephemeral-cerebro.yml@refs/heads/main$" \
      "${portable_receipt}" >/dev/null

    jq -n \
      --arg url "${smoke_url}" \
      --arg commit "${candidate_sha}" \
      --arg run_id "${run_id}" \
      --arg image "${image}" \
      --arg runtime_digest "${expected_runtime_digest}" \
      '{
        schema_version: "cerebro.smoke-evidence/v1",
        evidence_mode: "machine_verified_portable",
        smoke_receipt_url: $url,
        candidate_commit: $commit,
        verified: {
          notes_binding: true,
          run_terminal_success: true,
          workflow_identity: true,
          workflow_dispatch: true,
          workflow_main_branch: true,
          artifact_candidate_binding: true,
          receipt_signature: true,
          published_rust_candidate_image: $image,
          candidate_runtime_digest_binding: $runtime_digest,
          candidate_web_digest_binding: "not_machine_proven"
        },
        producer: {kind: "github_actions", run_id: $run_id}
      }' > "${out}"

    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      {
        echo "## Smoke evidence"
        echo
        echo "MACHINE-VERIFIED portable evidence: Ephemeral Cerebro run ${run_id} produced a signed receipt bound to candidate ${candidate_sha} and runtime digest ${expected_runtime_digest}."
        echo
        echo "The web image is not exercised by this smoke and remains explicitly unproven."
      } >> "${GITHUB_STEP_SUMMARY}"
    fi
    exit 0
  fi

  jq -n \
    --arg url "${smoke_url}" \
    --arg commit "${candidate_sha}" \
    --arg run_id "${run_id}" \
    --arg image "${image}" \
    '{
      schema_version: "cerebro.smoke-evidence/v1",
      evidence_mode: "machine_verified_github_actions",
      smoke_receipt_url: $url,
      candidate_commit: $commit,
      verified: {
        notes_binding: true,
        run_terminal_success: true,
        workflow_identity: true,
        workflow_dispatch: true,
        workflow_main_branch: true,
        artifact_candidate_binding: true,
        published_rust_candidate_image: $image,
        candidate_runtime_digest_binding: "not_machine_proven",
        candidate_web_digest_binding: "not_machine_proven"
      },
      producer: {kind: "github_actions", run_id: $run_id}
    }' > "${out}"

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "## Smoke evidence"
      echo
      echo "MACHINE-VERIFIED GitHub Actions evidence: Ephemeral Cerebro run ${run_id} completed successfully and its published Rust-image artifact is bound to candidate ${candidate_sha}."
      echo
      echo "The candidate runtime and web image digests are not machine-bound by this receipt version."
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
  exit 0
fi

origin="$(python3 - "${smoke_url}" <<'PY'
import sys
from urllib.parse import urlsplit

value = urlsplit(sys.argv[1])
if (
    value.scheme != "https"
    or not value.hostname
    or value.username is not None
    or value.password is not None
    or value.query
    or value.fragment
):
    raise SystemExit(2)
port = f":{value.port}" if value.port is not None else ""
print(f"https://{value.hostname.lower()}{port}")
PY
)" || fail "external receipt must be an HTTPS URL without credentials, query, or fragment"
[ "${origin}" != https://github.com ] || \
  fail "GitHub receipts must be same-repository Actions run URLs"

allowed=false
while IFS= read -r configured; do
  configured="${configured//[[:space:]]/}"
  if [ -n "${configured}" ] && [ "${configured}" = "${origin}" ]; then
    allowed=true
    break
  fi
done < <(printf '%s\n' "${allowed_origins}" | tr ',' '\n')
[ "${allowed}" = true ] || fail "external receipt origin is not allowlisted"

jq -n \
  --arg url "${smoke_url}" \
  --arg commit "${candidate_sha}" \
  --arg origin "${origin}" \
  '{
    schema_version: "cerebro.smoke-evidence/v1",
    evidence_mode: "operator_attested_external",
    smoke_receipt_url: $url,
    candidate_commit: $commit,
    verified: {
      notes_binding: true,
      origin_allowlisted: true,
      receipt_existence: "not_machine_proven",
      receipt_success: "not_machine_proven",
      candidate_binding: "not_machine_proven",
      immutability: "not_machine_proven"
    },
    producer: {kind: "external", origin: $origin}
  }' > "${out}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Smoke evidence"
    echo
    echo "OPERATOR ATTESTATION: the external receipt origin is allowlisted. Receipt existence, success, candidate binding, digest binding, and immutability are NOT machine-proven."
    echo
    echo "Approve the stable-release environment only after personally reviewing the receipt."
  } >> "${GITHUB_STEP_SUMMARY}"
fi
