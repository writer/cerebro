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
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dir) destination="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  mkdir -p "${destination}"
  cp "${GH_STUB_RECEIPT_JSON}" "${destination}/receipt.json"
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 2
SH
chmod +x "${tmp}/bin/gh"

jq -n \
  --arg path ".github/workflows/ephemeral-cerebro.yml" \
  '{status:"completed", conclusion:"success", path:$path, event:"workflow_dispatch", head_branch:"main"}' \
  > "${tmp}/run.json"
jq -n --arg name "pr-rust-graph-${candidate_sha}" \
  '{artifacts:[{name:$name, expired:false}]}' > "${tmp}/artifacts.json"
jq -n \
  --arg commit "${candidate_sha}" \
  --arg image "ghcr.io/writer/cerebro-rust:candidate-${candidate_sha}@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  '{schema_version:"cerebro.pr-rust-graph/v1", status:"passed", commit:$commit, image:$image}' \
  > "${tmp}/receipt.json"

verify() {
  PATH="${tmp}/bin:${PATH}" \
  GH_STUB_RUN_JSON="${GH_STUB_RUN_JSON:-${tmp}/run.json}" \
  GH_STUB_ARTIFACTS_JSON="${GH_STUB_ARTIFACTS_JSON:-${tmp}/artifacts.json}" \
  GH_STUB_RECEIPT_JSON="${GH_STUB_RECEIPT_JSON:-${tmp}/receipt.json}" \
  GITHUB_REPOSITORY=writer/cerebro \
  CANDIDATE_SHA="${candidate_sha}" \
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
