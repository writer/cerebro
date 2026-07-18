#!/usr/bin/env bash

set -euo pipefail

test_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly test_directory
repository_root="$(cd "${test_directory}/../.." && pwd)"
readonly repository_root
readonly fixture_source="${test_directory}/fixtures/web-final-archive-producer"
readonly producer="${repository_root}/infra/scripts/produce_web_final_archive_dry_run.sh"

test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

last_status=0
last_stdout=""
last_stderr=""
last_case=""

new_case() {
  local name="$1"
  local case_directory="${test_root}/${name}"
  mkdir -p "${case_directory}/fixture" "${case_directory}/output"
  cp -R "${fixture_source}/." "${case_directory}/fixture/"
  chmod +x "${case_directory}/fixture/fake-gh.sh"
  printf '%s\n' "${case_directory}"
}

rewrite_json() {
  local file="$1"
  local filter="$2"
  local temporary_file="${file}.tmp"
  jq "${filter}" "${file}" >"${temporary_file}"
  mv "${temporary_file}" "${file}"
}

run_producer() {
  local case_directory="$1"
  local source_id="${2:-web_public}"
  shift 2 || true
  local arguments=(
    --source-id "${source_id}"
    --ledger "${case_directory}/fixture/ledger.tsv"
    --inventory-receipt "${case_directory}/fixture/inventory.json"
    --representation-proof "${case_directory}/fixture/representation-proof.json"
    --cutover-receipt "${case_directory}/fixture/cutover.receipt"
    --rollback-receipt "${case_directory}/fixture/rollback.receipt"
    --output-directory "${case_directory}/output"
    "$@"
  )
  last_case="${case_directory}"
  last_stdout="${case_directory}/stdout.log"
  last_stderr="${case_directory}/stderr.log"
  set +e
  GH_BIN="${case_directory}/fixture/fake-gh.sh" \
    FAKE_GH_FIXTURE_DIR="${case_directory}/fixture" \
    FAKE_GH_CALL_LOG="${case_directory}/gh-calls.log" \
    bash "${producer}" "${arguments[@]}" >"${last_stdout}" 2>"${last_stderr}"
  last_status=$?
  set -e
}

assert_bounded_logs() {
  if grep -Eiq 'WriterInternal|writer/|github\.com|[0-9a-f]{40}' \
    "${last_stdout}" "${last_stderr}"; then
    echo "not ok: command logs exposed repository or commit authority" >&2
    exit 1
  fi
}

assert_pass() {
  local name="$1"
  local source_id="$2"
  if ((last_status != 0)); then
    echo "not ok: ${name} failed" >&2
    exit 1
  fi
  grep -Fxq 'web-final-archive-dry-run: verified' "${last_stdout}" || {
    echo "not ok: ${name} did not emit the bounded result" >&2
    exit 1
  }
  [[ ! -s "${last_stderr}" ]] || {
    echo "not ok: ${name} emitted unexpected stderr" >&2
    exit 1
  }
  assert_bounded_logs
  local lock_file="${last_case}/output/${source_id}.final-archive-lock.json"
  local receipt_file="${last_case}/output/${source_id}.final-archive-receipt.json"
  [[ -f "${lock_file}" && -f "${receipt_file}" ]] || {
    echo "not ok: ${name} did not emit both artifacts" >&2
    exit 1
  }
  jq -e --arg id "${source_id}" \
    '.source_repository_id == $id
      and .ledger.adapter == "web_representation_v1"
      and .ledger.nonterminal_row_count == 0
      and .ledger.terminal_row_count == .ledger.row_count
      and (.receipts.cutover.ref == ("receipt:sha256:" + .receipts.cutover.sha256))
      and (.receipts.rollback.ref == ("receipt:sha256:" + .receipts.rollback.sha256))' \
    "${lock_file}" >/dev/null
  jq -e --arg id "${source_id}" \
    '.source_repository_id == $id and .intent == "dry-run" and .state == "verified"
      and .observed.work_queue.open_pull_request_count == 0
      and .observed.work_queue.open_issue_count == 0
      and .observed.freeze.active == true
      and .observed.freeze.required_check_present == true
      and .observed.freeze.bypass_actor_count == 0
      and .observed.freeze.candidate_status_count == 0
      and .observed.archive_capability.administration_write == true
      and .postcondition.checked == false and .postcondition.archived == false' \
    "${receipt_file}" >/dev/null
  if rg -qi 'WriterInternal|writer/|github\.com|cerebro-web' "${lock_file}" "${receipt_file}"; then
    echo "not ok: ${name} emitted a raw repository identity" >&2
    exit 1
  fi
  if awk -F '\t' '$1 != "api" {exit 1}' "${last_case}/gh-calls.log"; then
    :
  else
    echo "not ok: ${name} used a non-read GitHub command" >&2
    exit 1
  fi
  if rg -qi -- '--method|-X|PATCH|POST|PUT|DELETE' "${last_case}/gh-calls.log"; then
    echo "not ok: ${name} attempted a GitHub mutation" >&2
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
  grep -Fq "web-final-archive-dry-run: ${code}" "${last_stderr}" || {
    echo "not ok: ${name} returned the wrong reason" >&2
    exit 1
  }
  assert_bounded_logs
  if find "${last_case}/output" -type f -print -quit | grep -q .; then
    echo "not ok: ${name} left partial output" >&2
    exit 1
  fi
  echo "ok: ${name}"
}

case_directory="$(new_case public-success)"
run_producer "${case_directory}" web_public
assert_pass "public source produces a validated dry run" web_public

case_directory="$(new_case private-success)"
run_producer "${case_directory}" web_private
assert_pass "private source produces a validated dry run" web_private

case_directory="$(new_case unbounded-source)"
run_producer "${case_directory}" arbitrary/repository
assert_failure "unbounded source identity is rejected" "source-not-allowlisted"
[[ ! -e "${case_directory}/gh-calls.log" ]] || {
  echo "not ok: unbounded source reached GitHub" >&2
  exit 1
}

case_directory="$(new_case arbitrary-argument)"
run_producer "${case_directory}" web_public --repository arbitrary/repository
assert_failure "repository arguments are rejected" "invalid-arguments"
[[ ! -e "${case_directory}/gh-calls.log" ]] || {
  echo "not ok: arbitrary repository argument reached GitHub" >&2
  exit 1
}

case_directory="$(new_case open-pull-request)"
rewrite_json "${case_directory}/fixture/pulls.json" '[{"number": 1}]'
run_producer "${case_directory}" web_public
assert_failure "open pull requests fail closed" "open-pull-requests"

case_directory="$(new_case open-issue)"
rewrite_json "${case_directory}/fixture/issues.json" '[{"number": 2}]'
run_producer "${case_directory}" web_public
assert_failure "open issues fail closed" "open-issues"

case_directory="$(new_case missing-capability)"
rewrite_json "${case_directory}/fixture/source-repository.json" '.permissions.admin = false'
run_producer "${case_directory}" web_public
assert_failure "missing archive capability fails closed" "source-authority-unavailable"

case_directory="$(new_case missing-required-check)"
rewrite_json "${case_directory}/fixture/ruleset.json" \
  '(.rules[] | select(.type == "required_status_checks")
    | .parameters.required_status_checks) = []'
run_producer "${case_directory}" web_public
assert_failure "missing freeze check fails closed" "freeze-rule-invalid"

case_directory="$(new_case freeze-bypass)"
rewrite_json "${case_directory}/fixture/ruleset.json" '.bypass_actors = [{"actor_id": 1}]'
run_producer "${case_directory}" web_public
assert_failure "freeze bypass actors fail closed" "freeze-rule-invalid"

case_directory="$(new_case candidate-status)"
rewrite_json "${case_directory}/fixture/status.json" \
  '.statuses = [{"context": "legacy-retirement/source-pinned/web"}]'
run_producer "${case_directory}" web_public
assert_failure "candidate status authority fails closed" "stale-candidate-status"

case_directory="$(new_case truncated-tree)"
rewrite_json "${case_directory}/fixture/source-tree.json" '.truncated = true'
run_producer "${case_directory}" web_public
assert_failure "truncated source trees fail closed" "source-tree-truncated"

case_directory="$(new_case path-mismatch)"
rewrite_json "${case_directory}/fixture/source-tree.json" '.tree |= map(select(.path != "README.md"))'
run_producer "${case_directory}" web_public
assert_failure "source path mismatches fail closed" "source-path-mismatch"

case_directory="$(new_case target-moved)"
rewrite_json "${case_directory}/fixture/public-target-ref.json" \
  '.object.sha = "9999999999999999999999999999999999999999"'
run_producer "${case_directory}" web_public
assert_failure "target movement fails normalized validation" "validator-rejected"

case_directory="$(new_case nonterminal-ledger)"
sed 's/represented_public/missing_portable/' \
  "${case_directory}/fixture/ledger.tsv" >"${case_directory}/fixture/ledger.tsv.tmp"
mv "${case_directory}/fixture/ledger.tsv.tmp" "${case_directory}/fixture/ledger.tsv"
run_producer "${case_directory}" web_public
assert_failure "nonterminal ledgers fail closed" "nonterminal-dispositions"

case_directory="$(new_case missing-receipt)"
rm "${case_directory}/fixture/cutover.receipt"
run_producer "${case_directory}" web_public
assert_failure "missing cutover receipts fail closed" "input-unavailable"

case_directory="$(new_case empty-receipt)"
: >"${case_directory}/fixture/cutover.receipt"
run_producer "${case_directory}" web_public
assert_failure "empty cutover receipts fail closed" "receipt-empty"

case_directory="$(new_case output-exists)"
printf '%s\n' sentinel >"${case_directory}/output/web_public.final-archive-lock.json"
run_producer "${case_directory}" web_public
grep -Fxq sentinel "${case_directory}/output/web_public.final-archive-lock.json" || {
  echo "not ok: existing output was overwritten" >&2
  exit 1
}
rm "${case_directory}/output/web_public.final-archive-lock.json"
assert_failure "existing output is never overwritten" "output-exists"

if rg -n 'gh[^\n]*api[^\n]*(--method|-X)|archived=' "${producer}"; then
  echo "not ok: producer contains a GitHub mutation path" >&2
  exit 1
fi
echo "ok: producer contains no GitHub mutation path"

echo "all web final archive dry-run producer tests passed"
