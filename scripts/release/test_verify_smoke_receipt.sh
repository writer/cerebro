#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
verifier="${root}/scripts/release/verify_smoke_receipt.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/bin"

candidate_sha="0123456789abcdef0123456789abcdef01234567"
run_id="12345"
receipt_url="https://github.com/writer/cerebro/actions/runs/${run_id}"

cat > "${tmp}/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = api ]; then
  case "$2" in
    */artifacts?per_page=100) cat "${GH_STUB_ARTIFACTS_JSON}" ;;
    *) cat "${GH_STUB_RUN_JSON}" ;;
  esac
  exit 0
fi
if [ "$1" = run ] && [ "$2" = download ]; then
  shift 2
  destination=""
  artifact_name=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dir) destination="$2"; shift 2 ;;
      --name) artifact_name="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  mkdir -p "${destination}"
  if [[ "${artifact_name}" == signed-* ]]; then
    cp "${GH_STUB_SIGNED_DIR}"/* "${destination}/"
  else
    cp "${GH_STUB_RECEIPT_JSON}" "${destination}/receipt.json"
  fi
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 2
SH
chmod +x "${tmp}/bin/gh"
cat > "${tmp}/bin/cosign" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${COSIGN_STUB_FAIL:-false}" = true ]; then
  echo "signature invalid" >&2
  exit 1
fi
printf '%s\n' "$*" > "${COSIGN_STUB_LOG}"
SH
chmod +x "${tmp}/bin/cosign"

jq -n \
  --arg path ".github/workflows/ephemeral-cerebro.yml" \
  '{status:"completed", conclusion:"success", path:$path, event:"workflow_dispatch", head_branch:"main"}' \
  > "${tmp}/run.json"
jq -n --arg name "pr-rust-graph-${candidate_sha}" \
  '{artifacts:[{name:$name, expired:false}]}' > "${tmp}/artifacts.json"
mkdir -p "${tmp}/signed"
jq -n \
  --arg raw "pr-rust-graph-${candidate_sha}" \
  --arg signed "signed-pr-rust-graph-${candidate_sha}" \
  '{artifacts:[{name:$raw, expired:false}, {name:$signed, expired:false}]}' \
  > "${tmp}/signed-artifacts.json"
jq -n \
  --arg commit "${candidate_sha}" \
  --arg image "ghcr.io/writer/cerebro-rust:candidate-${candidate_sha}@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  '{schema_version:"cerebro.pr-rust-graph/v1", status:"passed", commit:$commit, image:$image}' \
  > "${tmp}/receipt.json"
cp "${tmp}/receipt.json" "${tmp}/signed/receipt.json"
runtime_digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
jq -n \
  --arg commit "${candidate_sha}" \
  --arg runtime_image "ghcr.io/writer/cerebro:candidate-${candidate_sha}" \
  --arg runtime_digest "${runtime_digest}" \
  --arg run_url "${receipt_url}" \
  '{
    schema_version:"cerebro.smoke-receipt/v1",
    status:"passed",
    candidate_commit:$commit,
    runtime_image:$runtime_image,
    runtime_image_digest:$runtime_digest,
    web_image:null,
    web_image_digest:null,
    environment_class:"ephemeral",
    soak_seconds:60,
    checks:[range(0;17) | {name:("check-" + tostring), status:"passed", evidence:"bounded"}],
    completed_at:"2026-08-28T00:00:00Z",
    producer:{kind:"github_actions", workflow:".github/workflows/ephemeral-cerebro.yml", run_url:$run_url}
  }' > "${tmp}/signed/smoke-receipt.json"
printf '%s\n' signature > "${tmp}/signed/smoke-receipt.json.sig"
printf '%s\n' certificate > "${tmp}/signed/smoke-receipt.json.pem"

verify() {
  PATH="${tmp}/bin:${PATH}" \
  GH_STUB_RUN_JSON="${GH_STUB_RUN_JSON:-${tmp}/run.json}" \
  GH_STUB_ARTIFACTS_JSON="${GH_STUB_ARTIFACTS_JSON:-${tmp}/artifacts.json}" \
  GH_STUB_RECEIPT_JSON="${GH_STUB_RECEIPT_JSON:-${tmp}/receipt.json}" \
  GH_STUB_SIGNED_DIR="${GH_STUB_SIGNED_DIR:-${tmp}/signed}" \
  COSIGN_STUB_FAIL="${COSIGN_STUB_FAIL:-false}" \
  COSIGN_STUB_LOG="${tmp}/cosign.log" \
  GITHUB_REPOSITORY=writer/cerebro \
  CANDIDATE_SHA="${candidate_sha}" \
  CANDIDATE_RUNTIME_DIGEST="${CANDIDATE_RUNTIME_DIGEST:-}" \
  SMOKE_NOTES_BOUND=true \
  SMOKE_EVIDENCE_OUT="${tmp}/evidence.json" \
  "${verifier}"
}

expect_failure() {
  expected="$1"
  shift
  if "$@" 2> "${tmp}/error"; then
    echo "ERROR: verifier accepted invalid smoke evidence" >&2
    exit 1
  fi
  if ! grep -Fq "${expected}" "${tmp}/error"; then
    echo "ERROR: expected failure containing: ${expected}" >&2
    cat "${tmp}/error" >&2
    exit 1
  fi
}

SMOKE_RECEIPT_URL="${receipt_url}" verify
jq -e '
  .schema_version == "cerebro.smoke-evidence/v1" and
  .evidence_mode == "machine_verified_github_actions" and
  .candidate_commit == $commit and
  .verified.workflow_main_branch == true and
  .verified.artifact_candidate_binding == true and
  .verified.candidate_runtime_digest_binding == "not_machine_proven"
' --arg commit "${candidate_sha}" "${tmp}/evidence.json" >/dev/null

GH_STUB_ARTIFACTS_JSON="${tmp}/signed-artifacts.json" \
CANDIDATE_RUNTIME_DIGEST="${runtime_digest}" \
SMOKE_RECEIPT_URL="${receipt_url}" verify
jq -e '
  .evidence_mode == "machine_verified_portable" and
  .verified.receipt_signature == true and
  .verified.candidate_runtime_digest_binding == $digest and
  .verified.candidate_web_digest_binding == "not_machine_proven"
' --arg digest "${runtime_digest}" "${tmp}/evidence.json" >/dev/null
grep -Fq -- '--certificate-identity-regexp' "${tmp}/cosign.log"
grep -Fq 'ephemeral-cerebro.yml@refs/heads/main' "${tmp}/cosign.log"

GH_STUB_ARTIFACTS_JSON="${tmp}/signed-artifacts.json" \
CANDIDATE_RUNTIME_DIGEST="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "runtime digest does not match the release candidate" verify

GH_STUB_ARTIFACTS_JSON="${tmp}/signed-artifacts.json" \
CANDIDATE_RUNTIME_DIGEST="${runtime_digest}" \
COSIGN_STUB_FAIL=true \
SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "signature invalid" verify

jq '.conclusion = "failure"' "${tmp}/run.json" > "${tmp}/failed-run.json"
GH_STUB_RUN_JSON="${tmp}/failed-run.json" SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "did not conclude successfully" verify

jq '.path = ".github/workflows/ci.yml"' "${tmp}/run.json" > "${tmp}/wrong-workflow.json"
GH_STUB_RUN_JSON="${tmp}/wrong-workflow.json" SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "is not Ephemeral Cerebro" verify

jq '.event = "pull_request"' "${tmp}/run.json" > "${tmp}/wrong-event.json"
GH_STUB_RUN_JSON="${tmp}/wrong-event.json" SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "was not manually dispatched" verify

jq '.head_branch = "feature/untrusted-workflow"' "${tmp}/run.json" > "${tmp}/wrong-branch.json"
GH_STUB_RUN_JSON="${tmp}/wrong-branch.json" SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "did not execute the Ephemeral Cerebro workflow from main" verify

jq -n '{artifacts:[]}' > "${tmp}/missing-artifact.json"
GH_STUB_ARTIFACTS_JSON="${tmp}/missing-artifact.json" SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "must contain one unexpired" verify

jq --arg image "cerebro-rust-source:${candidate_sha}" '.image = $image' \
  "${tmp}/receipt.json" > "${tmp}/source-receipt.json"
GH_STUB_RECEIPT_JSON="${tmp}/source-receipt.json" SMOKE_RECEIPT_URL="${receipt_url}" \
  expect_failure "did not exercise the attested published Rust candidate image" verify

SMOKE_RECEIPT_URL="https://receipts.example.test/releases/123" \
SMOKE_RECEIPT_ALLOWED_ORIGINS="https://receipts.example.test" verify
jq -e '
  .evidence_mode == "operator_attested_external" and
  .verified.origin_allowlisted == true and
  .verified.candidate_binding == "not_machine_proven"
' "${tmp}/evidence.json" >/dev/null

SMOKE_RECEIPT_URL="https://untrusted.example.test/releases/123" \
SMOKE_RECEIPT_ALLOWED_ORIGINS="https://receipts.example.test" \
  expect_failure "external receipt origin is not allowlisted" verify

SMOKE_RECEIPT_URL="https://receipts.example.test/releases/123?token=secret" \
SMOKE_RECEIPT_ALLOWED_ORIGINS="https://receipts.example.test" \
  expect_failure "without credentials, query, or fragment" verify

SMOKE_RECEIPT_URL="https://github.com/other/repository/actions/runs/${run_id}" \
  expect_failure "GitHub receipts must be same-repository Actions run URLs" verify

echo "smoke receipt verifier tests passed"
