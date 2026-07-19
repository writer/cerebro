#!/usr/bin/env bash

set -euo pipefail

test_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly test_directory
repository_root="$(cd "${test_directory}/../.." && pwd)"
readonly repository_root
readonly fixture_source="${test_directory}/fixtures/final-archive-contract"
readonly validator="${repository_root}/infra/scripts/validate_final_archive_contract.sh"
readonly source_main="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly source_tree="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly public_target="cccccccccccccccccccccccccccccccccccccccc"
readonly private_target="dddddddddddddddddddddddddddddddddddddddd"

test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

last_status=0
last_stdout=""
last_stderr=""

new_case() {
  local name="$1"
  local case_directory="${test_root}/${name}"
  mkdir -p "${case_directory}"
  cp -R "${fixture_source}/." "${case_directory}/"
  printf '%s\n' "${case_directory}"
}

rewrite_json() {
  local source_file="$1"
  local filter="$2"
  local temporary_file="${source_file}.tmp"
  jq "${filter}" "${source_file}" >"${temporary_file}"
  mv "${temporary_file}" "${source_file}"
}

refresh_receipt_lock() {
  local case_directory="$1"
  local lock_digest
  lock_digest="$(jq -cS . "${case_directory}/final-lock.json" | sha256sum | awk '{print $1}')"
  local temporary_file="${case_directory}/final-receipt.json.tmp"
  jq --arg digest "${lock_digest}" \
    --slurpfile lock "${case_directory}/final-lock.json" \
    '.lock_sha256 = $digest
      | .source_repository_id = $lock[0].source_repository_id
      | .observed.source_main_commit_sha = $lock[0].source.main_commit_sha
      | .observed.source_tree_sha = $lock[0].source.tree_sha
      | .observed.public_target_commit_sha = $lock[0].targets.public_commit_sha
      | .observed.private_target_commit_sha = $lock[0].targets.private_commit_sha
      | .postcondition.source_main_commit_sha = $lock[0].source.main_commit_sha
      | .postcondition.source_tree_sha = $lock[0].source.tree_sha' \
    "${case_directory}/final-receipt.json" >"${temporary_file}"
  mv "${temporary_file}" "${case_directory}/final-receipt.json"
}

prepare_web_runtime_receipts() {
  local case_directory="$1"
  local source_id="$2"
  jq -cnS \
    --arg source_id "${source_id}" \
    --arg public_sha "${public_target}" \
    --arg private_sha "${private_target}" \
    '{schema_version:"cerebro.web-monorepo-cutover-receipt/v1",
      source_repository_id:$source_id,
      release:{public_commit_sha:$public_sha,web_digest:("sha256:" + ("4" * 64))},
      deployment:{private_commit_sha:$private_sha,runtime_state:"ready",traffic_state:"serving",probe_state:"passed",observed_at_epoch:995},
      evidence:{product_release_sha256:("1" * 64),target_receipt_sha256:("2" * 64),runtime_observation_sha256:("3" * 64)}}' \
    >"${case_directory}/cutover.receipt"
  local cutover_digest
  cutover_digest="$(sha256sum "${case_directory}/cutover.receipt" | awk '{print $1}')"
  jq -cnS \
    --arg source_id "${source_id}" \
    --arg private_sha "${private_target}" \
    --arg cutover_digest "${cutover_digest}" \
    '{schema_version:"cerebro.web-monorepo-rollback-readiness-receipt/v1",
      source_repository_id:$source_id,cutover_receipt_sha256:$cutover_digest,
      rollback_target:{public_commit_sha:("9" * 40),private_commit_sha:$private_sha,web_digest:("sha256:" + ("8" * 64))},
      readiness:{artifact_state:"available",render_state:"verified",workflow_state:"verified",rehearsal_state:"verified",observed_at_epoch:996},
      evidence:{product_release_sha256:("5" * 64),target_receipt_sha256:("6" * 64),rehearsal_observation_sha256:("7" * 64)}}' \
    >"${case_directory}/rollback.receipt"
  local rollback_digest
  rollback_digest="$(sha256sum "${case_directory}/rollback.receipt" | awk '{print $1}')"
  rewrite_json "${case_directory}/final-lock.json" \
    ".receipts.cutover = {ref: \"receipt:sha256:${cutover_digest}\", sha256: \"${cutover_digest}\"}
      | .receipts.rollback = {ref: \"receipt:sha256:${rollback_digest}\", sha256: \"${rollback_digest}\"}"
}

run_validator() {
  local case_directory="$1"
  local source_authority="${2:-slack-authority.json}"
  local inventory_receipt="${3:-}"
  local observed_source_main="${4:-${source_main}}"
  local observed_public_target="${5:-${public_target}}"
  local arguments=(
    --lock "${case_directory}/final-lock.json"
    --receipt "${case_directory}/final-receipt.json"
    --ledger "${case_directory}/ledger.tsv"
    --source-authority "${case_directory}/${source_authority}"
    --cutover-receipt "${case_directory}/cutover.receipt"
    --rollback-receipt "${case_directory}/rollback.receipt"
    --live-source-main "${observed_source_main}"
    --live-source-tree "${source_tree}"
    --live-public-target "${observed_public_target}"
    --live-private-target "${private_target}"
    --authority-now-epoch 1000
  )
  if [[ -n "${inventory_receipt}" ]]; then
    arguments+=(--inventory-receipt "${case_directory}/${inventory_receipt}")
  fi
  last_stdout="${case_directory}/stdout.log"
  last_stderr="${case_directory}/stderr.log"
  set +e
  bash "${validator}" "${arguments[@]}" >"${last_stdout}" 2>"${last_stderr}"
  last_status=$?
  set -e
}

assert_pass() {
  local name="$1"
  if ((last_status != 0)); then
    echo "not ok: ${name} failed" >&2
    exit 1
  fi
  grep -Fxq 'final-archive-contract: verified' "${last_stdout}" || {
    echo "not ok: ${name} did not emit the bounded result" >&2
    exit 1
  }
  if grep -Eq '[0-9a-f]{40}' "${last_stdout}" "${last_stderr}"; then
    echo "not ok: ${name} exposed a commit identity" >&2
    exit 1
  fi
  echo "ok: ${name}"
}

assert_failure() {
  local name="$1"
  local code="$2"
  if ((last_status == 0)); then
    echo "not ok: ${name} unexpectedly passed" >&2
    exit 1
  fi
  grep -Fq "final-archive-contract: ${code}" "${last_stderr}" || {
    echo "not ok: ${name} returned the wrong bounded reason" >&2
    exit 1
  }
  if grep -Eq '[0-9a-f]{40}' "${last_stdout}" "${last_stderr}"; then
    echo "not ok: ${name} exposed a commit identity" >&2
    exit 1
  fi
  echo "ok: ${name}"
}

jq -e . "${repository_root}/infra/repository_retirement/final-archive-lock.schema.json" >/dev/null
jq -e . "${repository_root}/infra/repository_retirement/final-archive-receipt.schema.json" >/dev/null
jq -e . "${repository_root}/infra/repository_retirement/web-cutover-receipt.schema.json" >/dev/null
jq -e . "${repository_root}/infra/repository_retirement/web-rollback-readiness-receipt.schema.json" >/dev/null
if grep -Eq 'WriterInternal|writer/' \
  "${repository_root}/infra/repository_retirement/final-archive-lock.schema.json" \
  "${repository_root}/infra/repository_retirement/final-archive-receipt.schema.json" \
  "${repository_root}/infra/repository_retirement/web-cutover-receipt.schema.json" \
  "${repository_root}/infra/repository_retirement/web-rollback-readiness-receipt.schema.json"; then
  echo "not ok: schemas contain an account or endpoint value" >&2
  exit 1
fi
if jq -se 'any(.[]; has("$id"))' \
  "${repository_root}/infra/repository_retirement/final-archive-lock.schema.json" \
  "${repository_root}/infra/repository_retirement/final-archive-receipt.schema.json" \
  "${repository_root}/infra/repository_retirement/web-cutover-receipt.schema.json" \
  "${repository_root}/infra/repository_retirement/web-rollback-readiness-receipt.schema.json" >/dev/null; then
  echo "not ok: schemas contain a deployable schema endpoint" >&2
  exit 1
fi
echo "ok: schemas are strict environment-neutral JSON"

case_directory="$(new_case slack-dry-run)"
refresh_receipt_lock "${case_directory}"
run_validator "${case_directory}"
assert_pass "Slack adapter accepts a terminal dry run"

case_directory="$(new_case web-public-dry-run)"
rewrite_json "${case_directory}/final-lock.json" \
  '.source_repository_id = "web_public" | .ledger.adapter = "web_representation_v1"
    | .ledger.terminal_dispositions = [
      "covered_by_new_public_slice", "obsolete_or_generated", "obsolete_or_replaced",
      "private_host_ops", "represented_public"
    ]'
prepare_web_runtime_receipts "${case_directory}" web_public
refresh_receipt_lock "${case_directory}"
run_validator "${case_directory}" web-authority.json web-inventory.json
assert_pass "public web adapter accepts a terminal dry run"

case_directory="$(new_case web-private-dry-run)"
rewrite_json "${case_directory}/final-lock.json" \
  '.source_repository_id = "web_private" | .ledger.adapter = "web_representation_v1"
    | .ledger.terminal_dispositions = [
      "covered_by_new_public_slice", "obsolete_or_generated", "obsolete_or_replaced",
      "private_host_ops", "represented_public"
    ]'
prepare_web_runtime_receipts "${case_directory}" web_private
refresh_receipt_lock "${case_directory}"
run_validator "${case_directory}" web-authority.json web-inventory.json
assert_pass "private web adapter accepts a terminal dry run"

case_directory="$(new_case apply-postcondition)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" \
  '.intent = "apply" | .state = "archived"
    | .postcondition.checked = true | .postcondition.archived = true
    | .postcondition.observed_at_epoch = 995'
run_validator "${case_directory}"
assert_pass "apply requires a verified archived postcondition"

case_directory="$(new_case unbounded-repository)"
rewrite_json "${case_directory}/final-lock.json" '.source_repository = "unbounded/repository"'
run_validator "${case_directory}"
assert_failure "unbounded repository names are rejected" "invalid-lock"

case_directory="$(new_case stale-source-main)"
refresh_receipt_lock "${case_directory}"
run_validator "${case_directory}" slack-authority.json '' \
  "9999999999999999999999999999999999999999"
assert_failure "stale source main is rejected" "stale-source-main"

case_directory="$(new_case stale-public-target)"
refresh_receipt_lock "${case_directory}"
run_validator "${case_directory}" slack-authority.json '' "${source_main}" \
  "9999999999999999999999999999999999999999"
assert_failure "stale public target is rejected" "stale-public-target"

case_directory="$(new_case missing-source-authority)"
refresh_receipt_lock "${case_directory}"
rm "${case_directory}/slack-authority.json"
run_validator "${case_directory}"
assert_failure "missing source authority is rejected" "input-unavailable"

case_directory="$(new_case mismatched-ledger)"
refresh_receipt_lock "${case_directory}"
sed 's/complete/changed/' "${case_directory}/ledger.tsv" >"${case_directory}/ledger.tsv.tmp"
mv "${case_directory}/ledger.tsv.tmp" "${case_directory}/ledger.tsv"
run_validator "${case_directory}"
assert_failure "mismatched ledger digest is rejected" "ledger-digest-mismatch"

case_directory="$(new_case nonterminal-ledger)"
refresh_receipt_lock "${case_directory}"
sed 's/represented_public/missing_portable/' \
  "${case_directory}/ledger.tsv" >"${case_directory}/ledger.tsv.tmp"
mv "${case_directory}/ledger.tsv.tmp" "${case_directory}/ledger.tsv"
run_validator "${case_directory}"
assert_failure "nonterminal dispositions are rejected" "nonterminal-dispositions"

case_directory="$(new_case unfinished-slack-private-host)"
refresh_receipt_lock "${case_directory}"
sed 's/obsolete_or_replaced/private_host_ops/' \
  "${case_directory}/ledger.tsv" >"${case_directory}/ledger.tsv.tmp"
mv "${case_directory}/ledger.tsv.tmp" "${case_directory}/ledger.tsv"
run_validator "${case_directory}"
assert_failure "unfinished Slack private-host work remains nonterminal" "nonterminal-dispositions"

case_directory="$(new_case missing-capability)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" \
  '.observed.archive_capability.administration_write = false'
run_validator "${case_directory}"
assert_failure "missing archive capability is rejected" "invalid-receipt"

case_directory="$(new_case open-work)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" '.observed.work_queue.open_issue_count = 1'
run_validator "${case_directory}"
assert_failure "open work is rejected" "invalid-receipt"

case_directory="$(new_case stale-candidate-status)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" '.observed.freeze.candidate_status_count = 1'
run_validator "${case_directory}"
assert_failure "candidate status authority is rejected" "invalid-receipt"

case_directory="$(new_case missing-web-authority)"
rewrite_json "${case_directory}/final-lock.json" \
  '.source_repository_id = "web_public" | .ledger.adapter = "web_representation_v1"
    | .ledger.terminal_dispositions = [
      "covered_by_new_public_slice", "obsolete_or_generated", "obsolete_or_replaced",
      "private_host_ops", "represented_public"
    ]'
prepare_web_runtime_receipts "${case_directory}" web_public
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/web-authority.json" '.archive_ready = false'
run_validator "${case_directory}" web-authority.json web-inventory.json
assert_failure "missing web authority is rejected" "web-adapter-mismatch"

case_directory="$(new_case opaque-web-cutover-receipt)"
rewrite_json "${case_directory}/final-lock.json" \
  '.source_repository_id = "web_public" | .ledger.adapter = "web_representation_v1"
    | .ledger.terminal_dispositions = [
      "covered_by_new_public_slice", "obsolete_or_generated", "obsolete_or_replaced",
      "private_host_ops", "represented_public"
    ]'
prepare_web_runtime_receipts "${case_directory}" web_public
printf '%s\n' opaque >"${case_directory}/cutover.receipt"
cutover_digest="$(sha256sum "${case_directory}/cutover.receipt" | awk '{print $1}')"
rewrite_json "${case_directory}/final-lock.json" \
  ".receipts.cutover = {ref: \"receipt:sha256:${cutover_digest}\", sha256: \"${cutover_digest}\"}"
refresh_receipt_lock "${case_directory}"
run_validator "${case_directory}" web-authority.json web-inventory.json
assert_failure "opaque web cutover evidence is rejected" "invalid-cutover-receipt"

case_directory="$(new_case receipt-digest-mismatch)"
refresh_receipt_lock "${case_directory}"
printf '%s\n' 'changed cutover receipt' >"${case_directory}/cutover.receipt"
run_validator "${case_directory}"
assert_failure "mismatched cutover receipt is rejected" "cutover-receipt-mismatch"

case_directory="$(new_case stale-observation)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" \
  '.observed.work_queue.observed_at_epoch = 600'
run_validator "${case_directory}"
assert_failure "stale authority observations are rejected" "stale-observation"

case_directory="$(new_case invalid-apply-postcondition)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" \
  '.intent = "apply" | .state = "archived"'
run_validator "${case_directory}"
assert_failure "apply without archived postcondition is rejected" "invalid-receipt"

case_directory="$(new_case fractional-apply-postcondition)"
refresh_receipt_lock "${case_directory}"
rewrite_json "${case_directory}/final-receipt.json" \
  '.intent = "apply" | .state = "archived"
    | .postcondition.checked = true | .postcondition.archived = true
    | .postcondition.observed_at_epoch = 995.5'
run_validator "${case_directory}"
assert_failure "fractional apply postcondition time is rejected" "invalid-receipt"

echo "all final archive contract tests passed"
