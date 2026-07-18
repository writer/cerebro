#!/usr/bin/env bash

set -Eeuo pipefail

readonly lock_schema="cerebro-repository-final-archive-lock/v1"
readonly receipt_schema="cerebro-repository-final-archive-receipt/v1"
readonly freeze_ruleset_name="Legacy migration freeze"
readonly freeze_check_context="validate migration closure"
readonly freeze_workflow_path=".github/workflows/legacy-freeze.yml"
readonly candidate_context_prefix="legacy-retirement/source-pinned"
readonly public_target_repository="writer/cerebro"
readonly private_target_repository="WriterInternal/cerebro"
readonly web_terminal_dispositions_json='["covered_by_new_public_slice","obsolete_or_generated","obsolete_or_replaced","private_host_ops","represented_public"]'
readonly full_sha_pattern='^[0-9a-f]{40}$'
readonly digest_pattern='^[0-9a-f]{64}$'

source_id=""
ledger_file=""
inventory_receipt_file=""
representation_proof_file=""
cutover_receipt_file=""
rollback_receipt_file=""
output_directory=""
source_repository=""
failure_code="invalid-input"
temporary_directory=""
lock_output=""
receipt_output=""
lock_output_created=false
receipt_output_created=false
gh_bin="${GH_BIN:-gh}"
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
readonly validator="${script_directory}/validate_final_archive_contract.sh"

finish() {
  local result=$?
  trap - EXIT
  if ((result != 0)); then
    echo "::error::web-final-archive-dry-run: ${failure_code}" >&2
    if [[ "${receipt_output_created}" == true ]]; then
      rm -f -- "${receipt_output}"
    fi
    if [[ "${lock_output_created}" == true ]]; then
      rm -f -- "${lock_output}"
    fi
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

require_argument() {
  (($# >= 2)) || fail "invalid-arguments"
}

while (($# > 0)); do
  case "$1" in
    --source-id) require_argument "$@"; source_id="$2"; shift 2 ;;
    --ledger) require_argument "$@"; ledger_file="$2"; shift 2 ;;
    --inventory-receipt) require_argument "$@"; inventory_receipt_file="$2"; shift 2 ;;
    --representation-proof) require_argument "$@"; representation_proof_file="$2"; shift 2 ;;
    --cutover-receipt) require_argument "$@"; cutover_receipt_file="$2"; shift 2 ;;
    --rollback-receipt) require_argument "$@"; rollback_receipt_file="$2"; shift 2 ;;
    --output-directory) require_argument "$@"; output_directory="$2"; shift 2 ;;
    *) fail "invalid-arguments" ;;
  esac
done

case "${source_id}" in
  web_public)
    source_repository="writer/cerebro-web"
    ;;
  web_private)
    source_repository="WriterInternal/cerebro-web"
    ;;
  *) fail "source-not-allowlisted" ;;
esac

for required_file in \
  "${ledger_file}" "${inventory_receipt_file}" "${representation_proof_file}" \
  "${cutover_receipt_file}" "${rollback_receipt_file}" "${validator}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || fail "input-unavailable"
done
[[ "${cutover_receipt_file}" != "${rollback_receipt_file}" ]] || fail "invalid-receipt-pair"
[[ -d "${output_directory}" && ! -L "${output_directory}" ]] || fail "output-unavailable"

lock_output="${output_directory}/${source_id}.final-archive-lock.json"
receipt_output="${output_directory}/${source_id}.final-archive-receipt.json"
[[ ! -e "${lock_output}" && ! -L "${lock_output}" ]] || fail "output-exists"
[[ ! -e "${receipt_output}" && ! -L "${receipt_output}" ]] || fail "output-exists"

command -v "${gh_bin}" >/dev/null 2>&1 || fail "github-client-unavailable"
command -v jq >/dev/null 2>&1 || fail "jq-unavailable"
command -v sha256sum >/dev/null 2>&1 || fail "digest-tool-unavailable"

umask 077
temporary_directory="$(mktemp -d)"

cp -- "${ledger_file}" "${temporary_directory}/ledger.tsv" 2>/dev/null \
  || fail "input-unavailable"
cp -- "${inventory_receipt_file}" "${temporary_directory}/inventory.json" 2>/dev/null \
  || fail "input-unavailable"
cp -- "${representation_proof_file}" "${temporary_directory}/representation-proof.json" \
  2>/dev/null || fail "input-unavailable"
cp -- "${cutover_receipt_file}" "${temporary_directory}/cutover.receipt" 2>/dev/null \
  || fail "input-unavailable"
cp -- "${rollback_receipt_file}" "${temporary_directory}/rollback.receipt" 2>/dev/null \
  || fail "input-unavailable"
ledger_file="${temporary_directory}/ledger.tsv"
inventory_receipt_file="${temporary_directory}/inventory.json"
representation_proof_file="${temporary_directory}/representation-proof.json"
cutover_receipt_file="${temporary_directory}/cutover.receipt"
rollback_receipt_file="${temporary_directory}/rollback.receipt"
[[ -s "${cutover_receipt_file}" && -s "${rollback_receipt_file}" ]] \
  || fail "receipt-empty"

api_json() {
  local endpoint="$1"
  local destination="$2"
  "${gh_bin}" api "${endpoint}" >"${destination}" 2>/dev/null
}

read_repository_identity() {
  local repository="$1"
  local prefix="$2"
  local require_admin="$3"
  local repository_file="${prefix}-repository.json"
  local ref_file="${prefix}-ref.json"
  local commit_file="${prefix}-commit.json"

  api_json "repos/${repository}" "${repository_file}" || return 1
  jq -e --argjson require_admin "${require_admin}" \
    '.archived == false
      and .default_branch == "main"
      and ($require_admin == false or .permissions.admin == true)' \
    "${repository_file}" >/dev/null 2>&1 || return 1
  api_json "repos/${repository}/git/ref/heads/main" "${ref_file}" || return 1
  identity_sha="$(jq -er '.object.sha | select(type == "string")' "${ref_file}" 2>/dev/null)" \
    || return 1
  [[ "${identity_sha}" =~ ${full_sha_pattern} ]] || return 1
  api_json "repos/${repository}/git/commits/${identity_sha}" "${commit_file}" || return 1
  identity_tree_sha="$(jq -er '.tree.sha | select(type == "string")' "${commit_file}" 2>/dev/null)" \
    || return 1
  [[ "${identity_tree_sha}" =~ ${full_sha_pattern} ]] || return 1
}

read_repository_identity "${source_repository}" "${temporary_directory}/source" true \
  || fail "source-authority-unavailable"
source_main_sha="${identity_sha}"
source_tree_sha="${identity_tree_sha}"
read_repository_identity "${public_target_repository}" "${temporary_directory}/public-target" false \
  || fail "public-target-unavailable"
public_target_sha="${identity_sha}"
read_repository_identity "${private_target_repository}" "${temporary_directory}/private-target" false \
  || fail "private-target-unavailable"
private_target_sha="${identity_sha}"

pulls_file="${temporary_directory}/pulls.json"
issues_file="${temporary_directory}/issues.json"
api_json "repos/${source_repository}/pulls?state=open&per_page=1" "${pulls_file}" \
  || fail "work-queue-unavailable"
api_json "repos/${source_repository}/issues?state=open&per_page=1" "${issues_file}" \
  || fail "work-queue-unavailable"
jq -e 'type == "array" and length == 0' "${pulls_file}" >/dev/null 2>&1 \
  || fail "open-pull-requests"
jq -e 'type == "array" and length == 0' "${issues_file}" >/dev/null 2>&1 \
  || fail "open-issues"

workflow_file="${temporary_directory}/freeze-workflow.json"
rulesets_file="${temporary_directory}/rulesets.json"
ruleset_file="${temporary_directory}/ruleset.json"
status_file="${temporary_directory}/status.json"
api_json \
  "repos/${source_repository}/contents/${freeze_workflow_path}?ref=${source_main_sha}" \
  "${workflow_file}" || fail "freeze-workflow-unavailable"
workflow_blob_sha="$(jq -er --arg path "${freeze_workflow_path}" \
  '.sha | select(type == "string")' "${workflow_file}" 2>/dev/null)" \
  || fail "freeze-workflow-invalid"
jq -e --arg path "${freeze_workflow_path}" \
  '.type == "file" and .path == $path and (.size | type == "number" and . > 0)' \
  "${workflow_file}" >/dev/null 2>&1 || fail "freeze-workflow-invalid"
[[ "${workflow_blob_sha}" =~ ${full_sha_pattern} ]] || fail "freeze-workflow-invalid"

api_json "repos/${source_repository}/rulesets" "${rulesets_file}" \
  || fail "freeze-rule-unavailable"
jq -e --arg name "${freeze_ruleset_name}" \
  '[.[] | select(.name == $name
    and .enforcement == "active"
    and .target == "branch"
    and .source_type == "Repository")] | length == 1' \
  "${rulesets_file}" >/dev/null 2>&1 || fail "freeze-rule-invalid"
ruleset_id="$(jq -er --arg name "${freeze_ruleset_name}" \
  '.[] | select(.name == $name
    and .enforcement == "active"
    and .target == "branch"
    and .source_type == "Repository") | .id' \
  "${rulesets_file}" 2>/dev/null)" || fail "freeze-rule-invalid"
[[ "${ruleset_id}" =~ ^[1-9][0-9]*$ ]] || fail "freeze-rule-invalid"
api_json "repos/${source_repository}/rulesets/${ruleset_id}" "${ruleset_file}" \
  || fail "freeze-rule-unavailable"
jq -e --arg name "${freeze_ruleset_name}" --arg context "${freeze_check_context}" \
  '.name == $name
    and .enforcement == "active"
    and .target == "branch"
    and .source_type == "Repository"
    and (.bypass_actors | type == "array" and length == 0)
    and (.conditions | keys | sort) == ["ref_name"]
    and .conditions.ref_name.include == ["~DEFAULT_BRANCH"]
    and .conditions.ref_name.exclude == []
    and any(.rules[]?; .type == "deletion")
    and any(.rules[]?; .type == "non_fast_forward")
    and any(.rules[]?; .type == "pull_request")
    and any(.rules[]?;
      .type == "required_status_checks"
      and .parameters.strict_required_status_checks_policy == true
      and .parameters.do_not_enforce_on_create == false
      and any(.parameters.required_status_checks[]?; .context == $context))' \
  "${ruleset_file}" >/dev/null 2>&1 || fail "freeze-rule-invalid"

api_json "repos/${source_repository}/commits/${source_main_sha}/status" "${status_file}" \
  || fail "candidate-status-unavailable"
candidate_status_count="$(jq -er --arg prefix "${candidate_context_prefix}" \
  '[.statuses[]? | select(.context == $prefix or (.context | startswith($prefix + "/")))] | length' \
  "${status_file}" 2>/dev/null)" || fail "candidate-status-unavailable"
[[ "${candidate_status_count}" == "0" ]] || fail "stale-candidate-status"

ledger_paths_file="${temporary_directory}/ledger-paths.txt"
tree_file="${temporary_directory}/source-tree.json"
tree_paths_file="${temporary_directory}/source-tree-paths.txt"
tail -n +2 "${ledger_file}" | cut -f 1 | LC_ALL=C sort >"${ledger_paths_file}"
api_json "repos/${source_repository}/git/trees/${source_tree_sha}?recursive=1" "${tree_file}" \
  || fail "source-tree-unavailable"
jq -e '.truncated == false' "${tree_file}" >/dev/null 2>&1 \
  || fail "source-tree-truncated"
jq -r '.tree[] | select(.type == "blob" or .type == "commit") | .path' \
  "${tree_file}" 2>/dev/null \
  | LC_ALL=C sort >"${tree_paths_file}" || fail "source-tree-unavailable"
cmp -s "${tree_paths_file}" "${ledger_paths_file}" || fail "source-path-mismatch"

disposition_counts_tsv="${temporary_directory}/disposition-counts.tsv"
disposition_counts_json="${temporary_directory}/disposition-counts.json"
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
' "${ledger_file}" | LC_ALL=C sort >"${disposition_counts_tsv}"
ledger_status=${PIPESTATUS[0]}
set -e
case "${ledger_status}" in
  0) ;;
  42) fail "nonterminal-dispositions" ;;
  *) fail "invalid-ledger" ;;
esac
jq -Rn '[inputs | split("\t") | {key: .[0], value: (.[1] | tonumber)}] | from_entries' \
  <"${disposition_counts_tsv}" | jq -S . >"${disposition_counts_json}"

row_count="$(($(wc -l <"${ledger_file}") - 1))"
((row_count > 0)) || fail "invalid-ledger"
ledger_digest="$(sha256sum "${ledger_file}" | awk '{print $1}')"
inventory_digest="$(sha256sum "${ledger_paths_file}" | awk '{print $1}')"
cutover_digest="$(sha256sum "${cutover_receipt_file}" | awk '{print $1}')"
rollback_digest="$(sha256sum "${rollback_receipt_file}" | awk '{print $1}')"
for digest in \
  "${ledger_digest}" "${inventory_digest}" "${cutover_digest}" "${rollback_digest}"; do
  [[ "${digest}" =~ ${digest_pattern} ]] || fail "digest-unavailable"
done
[[ "${cutover_digest}" != "${rollback_digest}" ]] || fail "invalid-receipt-pair"

ruleset_digest="$(jq -cS . "${ruleset_file}" | sha256sum | awk '{print $1}')"
repository_capability_digest="$(jq -cS \
  '{archived, default_branch, permissions: {admin: .permissions.admin}}' \
  "${temporary_directory}/source-repository.json" | sha256sum | awk '{print $1}')"
freeze_contract_digest="$(jq -cnS \
  --arg workflow_blob_sha "${workflow_blob_sha}" \
  --arg ruleset_sha256 "${ruleset_digest}" \
  --argjson candidate_status_count "${candidate_status_count}" \
  '{schema_version: "web-final-archive-freeze-observation/v1",
    workflow_blob_sha: $workflow_blob_sha, ruleset_sha256: $ruleset_sha256,
    active: true, default_branch_only: true, bypass_actor_count: 0,
    required_check_present: true, candidate_status_count: $candidate_status_count}' \
  | sha256sum | awk '{print $1}')"
capability_contract_digest="$(jq -cnS \
  --arg repository_metadata_sha256 "${repository_capability_digest}" \
  '{schema_version: "web-final-archive-capability-observation/v1",
    repository_metadata_sha256: $repository_metadata_sha256,
    evidence_readable: true, freeze_readable: true, administration_write: true}' \
  | sha256sum | awk '{print $1}')"
[[ "${freeze_contract_digest}" =~ ${digest_pattern} ]] || fail "freeze-proof-unavailable"
[[ "${capability_contract_digest}" =~ ${digest_pattern} ]] \
  || fail "capability-proof-unavailable"

observed_at_epoch="$(date -u +%s)"
[[ "${observed_at_epoch}" =~ ^[1-9][0-9]*$ ]] || fail "authority-time-unavailable"

lock_file="${temporary_directory}/final-lock.json"
receipt_file="${temporary_directory}/final-receipt.json"
jq -nS \
  --arg schema_version "${lock_schema}" \
  --arg source_repository_id "${source_id}" \
  --arg source_main "${source_main_sha}" \
  --arg source_tree "${source_tree_sha}" \
  --arg inventory_digest "${inventory_digest}" \
  --arg public_target "${public_target_sha}" \
  --arg private_target "${private_target_sha}" \
  --arg ledger_digest "${ledger_digest}" \
  --arg cutover_digest "${cutover_digest}" \
  --arg rollback_digest "${rollback_digest}" \
  --arg freeze_digest "${freeze_contract_digest}" \
  --arg capability_digest "${capability_contract_digest}" \
  --argjson row_count "${row_count}" \
  --argjson terminals "${web_terminal_dispositions_json}" \
  --slurpfile counts "${disposition_counts_json}" \
  '{schema_version: $schema_version,
    source_repository_id: $source_repository_id,
    source: {main_commit_sha: $source_main, tree_sha: $source_tree,
      path_inventory_sha256: $inventory_digest},
    targets: {public_commit_sha: $public_target, private_commit_sha: $private_target},
    ledger: {adapter: "web_representation_v1", sha256: $ledger_digest,
      row_count: $row_count, disposition_counts: $counts[0],
      terminal_dispositions: $terminals, terminal_row_count: $row_count,
      nonterminal_row_count: 0},
    receipts: {
      cutover: {ref: ("receipt:sha256:" + $cutover_digest), sha256: $cutover_digest},
      rollback: {ref: ("receipt:sha256:" + $rollback_digest), sha256: $rollback_digest}
    },
    authorities: {freeze_contract_sha256: $freeze_digest,
      archive_capability_contract_sha256: $capability_digest,
      max_observation_age_seconds: 300}}' >"${lock_file}"

lock_digest="$(jq -cS . "${lock_file}" | sha256sum | awk '{print $1}')"
jq -nS \
  --arg schema_version "${receipt_schema}" \
  --arg lock_digest "${lock_digest}" \
  --arg source_repository_id "${source_id}" \
  --arg source_main "${source_main_sha}" \
  --arg source_tree "${source_tree_sha}" \
  --arg public_target "${public_target_sha}" \
  --arg private_target "${private_target_sha}" \
  --arg freeze_digest "${freeze_contract_digest}" \
  --arg capability_digest "${capability_contract_digest}" \
  --argjson observed_at "${observed_at_epoch}" \
  '{schema_version: $schema_version, lock_sha256: $lock_digest,
    source_repository_id: $source_repository_id, intent: "dry-run", state: "verified",
    observed: {source_main_commit_sha: $source_main, source_tree_sha: $source_tree,
      public_target_commit_sha: $public_target, private_target_commit_sha: $private_target,
      work_queue: {open_pull_request_count: 0, open_issue_count: 0,
        observed_at_epoch: $observed_at},
      freeze: {contract_sha256: $freeze_digest, active: true,
        default_branch_only: true, bypass_actor_count: 0,
        required_check_present: true, candidate_status_count: 0,
        observed_at_epoch: $observed_at},
      archive_capability: {contract_sha256: $capability_digest,
        evidence_readable: true, freeze_readable: true, administration_write: true,
        observed_at_epoch: $observed_at}},
    postcondition: {checked: false, archived: false,
      source_main_commit_sha: $source_main, source_tree_sha: $source_tree,
      observed_at_epoch: 0}}' >"${receipt_file}"

read_repository_identity "${source_repository}" "${temporary_directory}/source-final" true \
  || fail "source-authority-unavailable"
[[ "${identity_sha}" == "${source_main_sha}" && "${identity_tree_sha}" == "${source_tree_sha}" ]] \
  || fail "source-state-moved"
read_repository_identity \
  "${public_target_repository}" "${temporary_directory}/public-target-final" false \
  || fail "public-target-unavailable"
[[ "${identity_sha}" == "${public_target_sha}" ]] || fail "public-target-moved"
read_repository_identity \
  "${private_target_repository}" "${temporary_directory}/private-target-final" false \
  || fail "private-target-unavailable"
[[ "${identity_sha}" == "${private_target_sha}" ]] || fail "private-target-moved"

validator_output="${temporary_directory}/validator.out"
if ! bash "${validator}" \
  --lock "${lock_file}" \
  --receipt "${receipt_file}" \
  --ledger "${ledger_file}" \
  --source-authority "${representation_proof_file}" \
  --inventory-receipt "${inventory_receipt_file}" \
  --cutover-receipt "${cutover_receipt_file}" \
  --rollback-receipt "${rollback_receipt_file}" \
  --live-source-main "${source_main_sha}" \
  --live-source-tree "${source_tree_sha}" \
  --live-public-target "${public_target_sha}" \
  --live-private-target "${private_target_sha}" \
  --authority-now-epoch "${observed_at_epoch}" \
  >"${validator_output}" 2>/dev/null; then
  fail "validator-rejected"
fi
grep -Fxq 'final-archive-contract: verified' "${validator_output}" \
  || fail "validator-rejected"

if ! (set -o noclobber; : >"${lock_output}") 2>/dev/null; then
  fail "output-exists"
fi
lock_output_created=true
install -m 0600 "${lock_file}" "${lock_output}"
if ! (set -o noclobber; : >"${receipt_output}") 2>/dev/null; then
  fail "output-exists"
fi
receipt_output_created=true
install -m 0600 "${receipt_file}" "${receipt_output}"
echo "web-final-archive-dry-run: verified"
