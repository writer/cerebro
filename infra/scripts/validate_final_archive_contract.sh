#!/usr/bin/env bash

set -Eeuo pipefail

readonly lock_schema="cerebro-repository-final-archive-lock/v1"
readonly receipt_schema="cerebro-repository-final-archive-receipt/v1"
readonly terminal_dispositions_json='["covered_by_new_public_slice","obsolete_or_generated","obsolete_or_replaced","private_host_ops","represented_public"]'
readonly full_sha_pattern='^[0-9a-f]{40}$'
readonly digest_pattern='^[0-9a-f]{64}$'

lock_file=""
receipt_file=""
ledger_file=""
source_authority_file=""
inventory_receipt_file=""
cutover_receipt_file=""
rollback_receipt_file=""
live_source_main=""
live_source_tree=""
live_public_target=""
live_private_target=""
authority_now_epoch=""
failure_code="invalid-input"
temporary_directory=""

finish() {
  local result=$?
  trap - EXIT
  if ((result != 0)); then
    echo "::error::final-archive-contract: ${failure_code}" >&2
  fi
  if [[ -n "${temporary_directory}" ]]; then
    rm -rf -- "${temporary_directory}"
  fi
  exit "${result}"
}
trap finish EXIT

fail() {
  failure_code="$1"
  return 1
}

while (($# > 0)); do
  case "$1" in
    --lock) lock_file="$2"; shift 2 ;;
    --receipt) receipt_file="$2"; shift 2 ;;
    --ledger) ledger_file="$2"; shift 2 ;;
    --source-authority) source_authority_file="$2"; shift 2 ;;
    --inventory-receipt) inventory_receipt_file="$2"; shift 2 ;;
    --cutover-receipt) cutover_receipt_file="$2"; shift 2 ;;
    --rollback-receipt) rollback_receipt_file="$2"; shift 2 ;;
    --live-source-main) live_source_main="$2"; shift 2 ;;
    --live-source-tree) live_source_tree="$2"; shift 2 ;;
    --live-public-target) live_public_target="$2"; shift 2 ;;
    --live-private-target) live_private_target="$2"; shift 2 ;;
    --authority-now-epoch) authority_now_epoch="$2"; shift 2 ;;
    *) fail "invalid-arguments" ;;
  esac
done

for required_file in \
  "${lock_file}" "${receipt_file}" "${ledger_file}" "${source_authority_file}" \
  "${cutover_receipt_file}" "${rollback_receipt_file}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || fail "input-unavailable"
done
[[ "${live_source_main}" =~ ${full_sha_pattern} ]] || fail "invalid-live-snapshot"
[[ "${live_source_tree}" =~ ${full_sha_pattern} ]] || fail "invalid-live-snapshot"
[[ "${live_public_target}" =~ ${full_sha_pattern} ]] || fail "invalid-live-snapshot"
[[ "${live_private_target}" =~ ${full_sha_pattern} ]] || fail "invalid-live-snapshot"
[[ "${authority_now_epoch}" =~ ^[1-9][0-9]*$ ]] || fail "invalid-authority-time"

temporary_directory="$(mktemp -d)"
disposition_counts_file="${temporary_directory}/disposition-counts.json"
ledger_paths_file="${temporary_directory}/ledger-paths.txt"

jq -e . "${lock_file}" >/dev/null 2>&1 || fail "invalid-lock"
jq -e . "${receipt_file}" >/dev/null 2>&1 || fail "invalid-receipt"
jq -e . "${source_authority_file}" >/dev/null 2>&1 || fail "invalid-source-authority"

jq -e \
  --arg schema "${lock_schema}" \
  --arg sha_pattern "${full_sha_pattern}" \
  --arg digest_pattern "${digest_pattern}" \
  --argjson terminals "${terminal_dispositions_json}" \
  '(. | keys | sort) == ([
      "authorities", "ledger", "receipts", "schema_version", "source",
      "source_repository_id", "targets"
    ] | sort)
    and .schema_version == $schema
    and (.source_repository_id == "slack_companion"
      or .source_repository_id == "web_public"
      or .source_repository_id == "web_private")
    and (.source | keys | sort) == (["main_commit_sha", "path_inventory_sha256", "tree_sha"] | sort)
    and (.source.main_commit_sha | type == "string" and test($sha_pattern))
    and (.source.tree_sha | type == "string" and test($sha_pattern))
    and (.source.path_inventory_sha256 | type == "string" and test($digest_pattern))
    and (.targets | keys | sort) == (["private_commit_sha", "public_commit_sha"] | sort)
    and (.targets.public_commit_sha | type == "string" and test($sha_pattern))
    and (.targets.private_commit_sha | type == "string" and test($sha_pattern))
    and (.ledger | keys | sort) == ([
      "adapter", "disposition_counts", "nonterminal_row_count", "row_count", "sha256",
      "terminal_dispositions", "terminal_row_count"
    ] | sort)
    and ((.source_repository_id == "slack_companion" and .ledger.adapter == "slack_legacy_v1")
      or ((.source_repository_id == "web_public" or .source_repository_id == "web_private")
        and .ledger.adapter == "web_representation_v1"))
    and (.ledger.sha256 | type == "string" and test($digest_pattern))
    and (.ledger.row_count | type == "number" and floor == . and . > 0)
    and (.ledger.disposition_counts | type == "object" and length > 0)
    and ([.ledger.disposition_counts | to_entries[]
      | select((.key | test("^[a-z][a-z0-9_]*$") | not)
        or (.value | type != "number") or (.value | floor != .) or (.value < 1))] | length) == 0
    and .ledger.terminal_dispositions == $terminals
    and (.ledger.terminal_row_count | type == "number" and floor == . and . > 0)
    and .ledger.nonterminal_row_count == 0
    and (.receipts | keys | sort) == (["cutover", "rollback"] | sort)
    and all(.receipts[];
      (. | keys | sort) == (["ref", "sha256"] | sort)
      and (.sha256 | type == "string" and test($digest_pattern))
      and .ref == ("receipt:sha256:" + .sha256))
    and (.authorities | keys | sort) == ([
      "archive_capability_contract_sha256", "freeze_contract_sha256",
      "max_observation_age_seconds"
    ] | sort)
    and (.authorities.freeze_contract_sha256 | type == "string" and test($digest_pattern))
    and (.authorities.archive_capability_contract_sha256 | type == "string" and test($digest_pattern))
    and (.authorities.max_observation_age_seconds | type == "number"
      and floor == . and . >= 1 and . <= 900)' \
  "${lock_file}" >/dev/null 2>&1 || fail "invalid-lock"

source_repository_id="$(jq -r '.source_repository_id' "${lock_file}")"
locked_source_main="$(jq -r '.source.main_commit_sha' "${lock_file}")"
locked_source_tree="$(jq -r '.source.tree_sha' "${lock_file}")"
locked_public_target="$(jq -r '.targets.public_commit_sha' "${lock_file}")"
locked_private_target="$(jq -r '.targets.private_commit_sha' "${lock_file}")"

[[ "${locked_source_main}" == "${live_source_main}" ]] || fail "stale-source-main"
[[ "${locked_source_tree}" == "${live_source_tree}" ]] || fail "stale-source-tree"
[[ "${locked_public_target}" == "${live_public_target}" ]] || fail "stale-public-target"
[[ "${locked_private_target}" == "${live_private_target}" ]] || fail "stale-private-target"

[[ "$(tail -c 1 "${ledger_file}" | od -An -t u1 | tr -d ' ')" == "10" ]] \
  || fail "invalid-ledger"
expected_header=$'path\tcategory\tdisposition\ttarget\tnote'
IFS= read -r actual_header <"${ledger_file}"
[[ "${actual_header}" == "${expected_header}" ]] || fail "invalid-ledger"

set +e
awk -F '\t' '
  BEGIN {
    terminal["covered_by_new_public_slice"] = 1
    terminal["obsolete_or_generated"] = 1
    terminal["obsolete_or_replaced"] = 1
    terminal["private_host_ops"] = 1
    terminal["represented_public"] = 1
  }
  NR == 1 { next }
  NF != 5 { exit 2 }
  {
    for (field = 1; field <= 5; field += 1) {
      if ($field == "" || $field ~ /^[[:space:]]/ || $field ~ /[[:space:]]$/) exit 2
    }
    if ($1 ~ /^\// || $1 ~ /(^|\/)\.\.(\/|$)/ || $1 ~ /\\/ || seen[$1]++) exit 2
    counts[$3] += 1
    if (!($3 in terminal)) nonterminal += 1
  }
  END {
    if (nonterminal > 0) exit 42
    for (disposition in counts) print disposition "\t" counts[disposition]
  }
' "${ledger_file}" | LC_ALL=C sort >"${temporary_directory}/disposition-counts.tsv"
ledger_status=${PIPESTATUS[0]}
set -e
case "${ledger_status}" in
  0) ;;
  42) fail "nonterminal-dispositions" ;;
  *) fail "invalid-ledger" ;;
esac

jq -Rn '[inputs | split("\t") | {key: .[0], value: (.[1] | tonumber)}] | from_entries' \
  <"${temporary_directory}/disposition-counts.tsv" | jq -S . >"${disposition_counts_file}"
tail -n +2 "${ledger_file}" | cut -f 1 | LC_ALL=C sort >"${ledger_paths_file}"
actual_row_count="$(($(wc -l <"${ledger_file}") - 1))"
actual_ledger_digest="$(sha256sum "${ledger_file}" | awk '{print $1}')"
actual_inventory_digest="$(sha256sum "${ledger_paths_file}" | awk '{print $1}')"
[[ "${actual_row_count}" == "$(jq -r '.ledger.row_count' "${lock_file}")" ]] \
  || fail "ledger-count-mismatch"
[[ "${actual_row_count}" == "$(jq -r '.ledger.terminal_row_count' "${lock_file}")" ]] \
  || fail "terminal-count-mismatch"
[[ "${actual_ledger_digest}" == "$(jq -r '.ledger.sha256' "${lock_file}")" ]] \
  || fail "ledger-digest-mismatch"
[[ "${actual_inventory_digest}" == "$(jq -r '.source.path_inventory_sha256' "${lock_file}")" ]] \
  || fail "inventory-digest-mismatch"
jq -S '.ledger.disposition_counts' "${lock_file}" >"${temporary_directory}/expected-counts.json"
cmp -s "${disposition_counts_file}" "${temporary_directory}/expected-counts.json" \
  || fail "disposition-count-mismatch"

cutover_digest="$(sha256sum "${cutover_receipt_file}" | awk '{print $1}')"
rollback_digest="$(sha256sum "${rollback_receipt_file}" | awk '{print $1}')"
[[ "${cutover_digest}" == "$(jq -r '.receipts.cutover.sha256' "${lock_file}")" ]] \
  || fail "cutover-receipt-mismatch"
[[ "${rollback_digest}" == "$(jq -r '.receipts.rollback.sha256' "${lock_file}")" ]] \
  || fail "rollback-receipt-mismatch"

if [[ "${source_repository_id}" == "slack_companion" ]]; then
  [[ -z "${inventory_receipt_file}" ]] || fail "unexpected-inventory-receipt"
  jq -e \
    --arg source_sha "${locked_source_main}" \
    --arg source_tree "${locked_source_tree}" \
    --arg inventory "${actual_inventory_digest}" \
    --arg public_sha "${locked_public_target}" \
    --arg private_sha "${locked_private_target}" \
    --arg ledger_digest "${actual_ledger_digest}" \
    --argjson rows "${actual_row_count}" \
    --slurpfile counts "${disposition_counts_file}" \
    '.schema_version == "cerebro-slack-retirement-ledger/v1"
      and .source_commit_sha == $source_sha
      and .source_tree_sha == $source_tree
      and .source_path_inventory_sha256 == $inventory
      and .public_commit_sha == $public_sha
      and .private_commit_sha == $private_sha
      and .ledger_sha256 == $ledger_digest
      and .expected_rows == $rows
      and .unclassified_rows == 0
      and .expected_disposition_counts == $counts[0]' \
    "${source_authority_file}" >/dev/null 2>&1 || fail "slack-adapter-mismatch"
else
  [[ -f "${inventory_receipt_file}" && ! -L "${inventory_receipt_file}" ]] \
    || fail "inventory-receipt-unavailable"
  jq -e . "${inventory_receipt_file}" >/dev/null 2>&1 || fail "invalid-inventory-receipt"
  if [[ "${source_repository_id}" == "web_public" ]]; then
    expected_ledger_name="public-source-disposition.tsv"
  else
    expected_ledger_name="private-source-disposition.tsv"
  fi
  jq -e \
    --arg source_sha "${locked_source_main}" \
    --arg ledger_name "${expected_ledger_name}" \
    --arg ledger_digest "${actual_ledger_digest}" \
    --arg public_sha "${locked_public_target}" \
    --arg private_sha "${locked_private_target}" \
    --argjson rows "${actual_row_count}" \
    '.schema_version == "web-repository-representation-proof/v1"
      and .archive_ready == true
      and .public_target_commit_sha == $public_sha
      and .private_target_commit_sha == $private_sha
      and (.blockers | type == "array" and length == 0)
      and ([.sources[] | select(.source_commit_sha == $source_sha
        and .ledger_path == $ledger_name
        and .ledger_sha256 == $ledger_digest
        and .row_count == $rows
        and .nonterminal_row_count == 0)] | length) == 1
      and ([.source_freeze_evidence[] | select(.source_commit_sha == $source_sha
        and .ledger_path == $ledger_name
        and .open_pull_request_count == 0
        and .open_issue_count == 0)] | length) == 1' \
    "${source_authority_file}" >/dev/null 2>&1 || fail "web-adapter-mismatch"
  jq -e \
    --arg source_sha "${locked_source_main}" \
    --arg source_tree "${locked_source_tree}" \
    --arg inventory "${actual_inventory_digest}" \
    --arg ledger_digest "${actual_ledger_digest}" \
    --argjson rows "${actual_row_count}" \
    '.schema_version == "repository-retirement-inventory/v1"
      and .verified == true
      and .unclassified_rows == 0
      and .source_commit_sha == $source_sha
      and .source_tree_sha == $source_tree
      and .source_path_inventory_sha256 == $inventory
      and .rows == $rows
      and .ledger_sha256 == $ledger_digest' \
    "${inventory_receipt_file}" >/dev/null 2>&1 || fail "web-inventory-mismatch"
fi

canonical_lock_digest="$(jq -cS . "${lock_file}" | sha256sum | awk '{print $1}')"
jq -e \
  --arg schema "${receipt_schema}" \
  --arg lock_digest "${canonical_lock_digest}" \
  --arg repository_id "${source_repository_id}" \
  --arg source_sha "${locked_source_main}" \
  --arg source_tree "${locked_source_tree}" \
  --arg public_sha "${locked_public_target}" \
  --arg private_sha "${locked_private_target}" \
  --arg freeze_contract "$(jq -r '.authorities.freeze_contract_sha256' "${lock_file}")" \
  --arg capability_contract "$(jq -r '.authorities.archive_capability_contract_sha256' "${lock_file}")" \
  '(. | keys | sort) == ([
      "intent", "lock_sha256", "observed", "postcondition", "schema_version",
      "source_repository_id", "state"
    ] | sort)
    and .schema_version == $schema
    and .lock_sha256 == $lock_digest
    and .source_repository_id == $repository_id
    and (.intent == "dry-run" or .intent == "apply")
    and .observed.source_main_commit_sha == $source_sha
    and .observed.source_tree_sha == $source_tree
    and .observed.public_target_commit_sha == $public_sha
    and .observed.private_target_commit_sha == $private_sha
    and (.observed | keys | sort) == ([
      "archive_capability", "freeze", "private_target_commit_sha",
      "public_target_commit_sha", "source_main_commit_sha", "source_tree_sha", "work_queue"
    ] | sort)
    and (.observed.work_queue | keys | sort) == ([
      "observed_at_epoch", "open_issue_count", "open_pull_request_count"
    ] | sort)
    and .observed.work_queue.open_pull_request_count == 0
    and .observed.work_queue.open_issue_count == 0
    and (.observed.freeze | keys | sort) == ([
      "active", "bypass_actor_count", "candidate_status_count", "contract_sha256",
      "default_branch_only", "observed_at_epoch", "required_check_present"
    ] | sort)
    and .observed.freeze.contract_sha256 == $freeze_contract
    and .observed.freeze.active == true
    and .observed.freeze.default_branch_only == true
    and .observed.freeze.bypass_actor_count == 0
    and .observed.freeze.required_check_present == true
    and .observed.freeze.candidate_status_count == 0
    and (.observed.archive_capability | keys | sort) == ([
      "administration_write", "contract_sha256", "evidence_readable",
      "freeze_readable", "observed_at_epoch"
    ] | sort)
    and .observed.archive_capability.contract_sha256 == $capability_contract
    and .observed.archive_capability.evidence_readable == true
    and .observed.archive_capability.freeze_readable == true
    and .observed.archive_capability.administration_write == true
    and (.postcondition | keys | sort) == ([
      "archived", "checked", "observed_at_epoch", "source_main_commit_sha", "source_tree_sha"
    ] | sort)
    and .postcondition.source_main_commit_sha == $source_sha
    and .postcondition.source_tree_sha == $source_tree
    and ((.intent == "dry-run" and .state == "verified"
      and .postcondition.checked == false and .postcondition.archived == false
      and .postcondition.observed_at_epoch == 0)
      or (.intent == "apply" and .state == "archived"
      and .postcondition.checked == true and .postcondition.archived == true
      and (.postcondition.observed_at_epoch | type == "number" and . > 0)))' \
  "${receipt_file}" >/dev/null 2>&1 || fail "invalid-receipt"

max_age="$(jq -r '.authorities.max_observation_age_seconds' "${lock_file}")"
for observation_path in \
  '.observed.work_queue.observed_at_epoch' \
  '.observed.freeze.observed_at_epoch' \
  '.observed.archive_capability.observed_at_epoch'; do
  observed_epoch="$(jq -r "${observation_path}" "${receipt_file}")"
  [[ "${observed_epoch}" =~ ^[1-9][0-9]*$ ]] || fail "invalid-observation-time"
  ((observed_epoch <= authority_now_epoch)) || fail "future-observation"
  ((authority_now_epoch - observed_epoch <= max_age)) || fail "stale-observation"
done
if [[ "$(jq -r '.intent' "${receipt_file}")" == "apply" ]]; then
  postcondition_epoch="$(jq -r '.postcondition.observed_at_epoch' "${receipt_file}")"
  ((postcondition_epoch <= authority_now_epoch)) || fail "future-postcondition"
  ((authority_now_epoch - postcondition_epoch <= max_age)) || fail "stale-postcondition"
fi

echo "final-archive-contract: verified"
