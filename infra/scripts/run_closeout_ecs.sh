#!/usr/bin/env bash
# Helper script used by .github/workflows/closeout.yml to:
#   1. Assert that the env's task role has the required KMS encrypt
#      permissions on the audit bucket KMS key (no Decrypt).
#   2. Launch the cerebro closeout subcommand on the existing API ECS
#      task definition via aws ecs run-task with containerOverrides,
#      tail the resulting task's CloudWatch log group, and exit with
#      the task container's exit code.
#
# The script is intentionally idempotent and side-effect free outside
# the AWS calls it issues; all required configuration is taken from
# environment variables set by the workflow.

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  run_closeout_ecs.sh assert-kms-allow
  run_closeout_ecs.sh run
USAGE
}

require_env() {
    local name="$1"
    if [ -z "${!name:-}" ]; then
        echo "::error title=closeout::Required env var ${name} is unset" >&2
        exit 64
    fi
}

derive_env_config() {
    require_env CEREBRO_ENV
    case "${CEREBRO_ENV}" in
        sec-dev)
            : "${CEREBRO_CLUSTER:=cerebro-sec-dev-cluster}"
            : "${CEREBRO_TASK_FAMILY:=cerebro-sec-dev}"
            : "${CEREBRO_SERVICE:=cerebro-sec-dev-api}"
            : "${CEREBRO_LOG_GROUP:=/ecs/cerebro-sec-dev}"
            : "${CEREBRO_TASK_ROLE_NAME:=cerebro-sec-dev-task-role}"
            ;;
        go-prod)
            : "${CEREBRO_CLUSTER:=cerebro-go-production-cluster}"
            : "${CEREBRO_TASK_FAMILY:=cerebro-go-production}"
            : "${CEREBRO_SERVICE:=cerebro-go-production-api}"
            : "${CEREBRO_LOG_GROUP:=/ecs/cerebro-go-production}"
            : "${CEREBRO_TASK_ROLE_NAME:=cerebro-go-production-task-role}"
            ;;
        *)
            echo "::error title=closeout::Unknown CEREBRO_ENV='${CEREBRO_ENV}'; expected 'sec-dev' or 'go-prod'" >&2
            exit 64
            ;;
    esac
    export CEREBRO_CLUSTER CEREBRO_TASK_FAMILY CEREBRO_SERVICE CEREBRO_LOG_GROUP CEREBRO_TASK_ROLE_NAME
}

cmd_assert_kms_allow() {
    derive_env_config
    require_env CEREBRO_TASK_ROLE_NAME
    require_env AUDIT_BUCKET_KMS_KEY_ARN

    local role_arn
    role_arn="$(aws iam get-role --role-name "${CEREBRO_TASK_ROLE_NAME}" --query 'Role.Arn' --output text)"

    local allowed_actions=(kms:Encrypt kms:GenerateDataKey kms:DescribeKey)
    local denied_actions=(kms:Decrypt)

    echo "Simulating allowed actions on ${AUDIT_BUCKET_KMS_KEY_ARN} for ${role_arn}"
    local allowed_json
    allowed_json="$(aws iam simulate-principal-policy \
        --policy-source-arn "${role_arn}" \
        --action-names "${allowed_actions[@]}" \
        --resource-arns "${AUDIT_BUCKET_KMS_KEY_ARN}" \
        --output json)"

    local failures=0
    for action in "${allowed_actions[@]}"; do
        local decision
        decision="$(printf '%s' "${allowed_json}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
target = sys.argv[1]
for entry in data.get('EvaluationResults', []):
    if entry.get('EvalActionName') == target:
        print(entry.get('EvalDecision', ''))
        break
" "${action}")"
        if [ "${decision}" != "allowed" ]; then
            echo "::error title=closeout::Task role ${role_arn} is NOT allowed to perform ${action} on ${AUDIT_BUCKET_KMS_KEY_ARN} (decision=${decision})" >&2
            failures=$((failures + 1))
        else
            echo "  ${action}: allowed"
        fi
    done

    echo "Simulating denied actions on ${AUDIT_BUCKET_KMS_KEY_ARN} for ${role_arn}"
    local denied_json
    denied_json="$(aws iam simulate-principal-policy \
        --policy-source-arn "${role_arn}" \
        --action-names "${denied_actions[@]}" \
        --resource-arns "${AUDIT_BUCKET_KMS_KEY_ARN}" \
        --output json)"

    for action in "${denied_actions[@]}"; do
        local decision
        decision="$(printf '%s' "${denied_json}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
target = sys.argv[1]
for entry in data.get('EvaluationResults', []):
    if entry.get('EvalActionName') == target:
        print(entry.get('EvalDecision', ''))
        break
" "${action}")"
        if [ "${decision}" = "allowed" ]; then
            echo "::error title=closeout::Task role ${role_arn} unexpectedly allowed for ${action} on ${AUDIT_BUCKET_KMS_KEY_ARN} (decision=${decision})" >&2
            failures=$((failures + 1))
        else
            echo "  ${action}: ${decision} (expected non-allowed)"
        fi
    done

    if [ "${failures}" -gt 0 ]; then
        exit 1
    fi
}

build_command_array() {
    local env_name="$1"
    local dry_run="$2"
    local rule_ids_csv="$3"
    local source_csv="$4"
    local older_than="$5"
    local reason="$6"
    local change_ticket="$7"
    local audit_bucket="$8"
    local actor="$9"
    local run_id="${10}"

    python3 - "${env_name}" "${dry_run}" "${rule_ids_csv}" "${source_csv}" "${older_than}" "${reason}" "${change_ticket}" "${audit_bucket}" "${actor}" "${run_id}" <<'PY'
import json
import sys

(env_name, dry_run, rule_ids_csv, source_csv, older_than,
 reason, change_ticket, audit_bucket, actor, run_id) = sys.argv[1:11]

command = ["closeout"]

rule_ids = [v.strip() for v in rule_ids_csv.split(",") if v.strip()]
for rule_id in rule_ids:
    command.extend(["--rule-id", rule_id])

sources = [v.strip() for v in source_csv.split(",") if v.strip()]
for src in sources:
    command.extend(["--source", src])

if older_than:
    command.extend(["--older-than", older_than])

command.extend(["--reason", reason])

if change_ticket:
    command.extend(["--change-ticket", change_ticket])

command.extend(["--allow-env", env_name])

if dry_run.lower() == "false":
    command.append("--apply")

if audit_bucket:
    command.extend(["--audit-s3-bucket", audit_bucket])

if actor:
    command.extend(["--actor", actor])

if run_id:
    command.extend(["--run-id", run_id])

print(json.dumps(command))
PY
}

cmd_run() {
    require_env AWS_REGION
    derive_env_config
    require_env CEREBRO_CLUSTER
    require_env CEREBRO_TASK_FAMILY
    require_env CEREBRO_SERVICE
    require_env CEREBRO_LOG_GROUP
    require_env AUDIT_BUCKET
    require_env INPUT_ENV
    require_env INPUT_REASON

    local dry_run_value="${INPUT_DRY_RUN:-true}"
    local rule_ids_csv="${INPUT_RULE_IDS:-}"
    local source_csv="${INPUT_SOURCE:-}"
    local older_than="${INPUT_OLDER_THAN:-}"
    local reason="${INPUT_REASON}"
    local change_ticket="${INPUT_CHANGE_TICKET:-}"
    local actor="${GITHUB_ACTOR_ARG:-}"
    local run_id="${GITHUB_RUN_ID:-}"

    local command_json
    command_json="$(build_command_array "${INPUT_ENV}" "${dry_run_value}" "${rule_ids_csv}" "${source_csv}" "${older_than}" "${reason}" "${change_ticket}" "${AUDIT_BUCKET}" "${actor}" "${run_id}")"

    echo "containerOverrides command: ${command_json}"

    local overrides_json
    overrides_json="$(python3 - "${command_json}" "${INPUT_ENV}" "${AUDIT_BUCKET}" <<'PY'
import json
import sys

command = json.loads(sys.argv[1])
allow_env = sys.argv[2]
audit_bucket = sys.argv[3]

overrides = {
    "containerOverrides": [
        {
            "name": "cerebro",
            "command": command,
            "environment": [
                {"name": "CEREBRO_CLOSEOUT_ALLOW", "value": allow_env},
                {"name": "CEREBRO_CLOSEOUT_AUDIT_BUCKET", "value": audit_bucket},
            ],
        }
    ]
}
print(json.dumps(overrides))
PY
)"

    echo "Task overrides: ${overrides_json}"

    local network_config
    network_config="$(aws ecs describe-services \
        --cluster "${CEREBRO_CLUSTER}" \
        --services "${CEREBRO_SERVICE}" \
        --query 'services[0].networkConfiguration' \
        --output json)"

    if [ -z "${network_config}" ] || [ "${network_config}" = "null" ]; then
        echo "::error title=closeout::Failed to resolve network configuration from service ${CEREBRO_SERVICE}" >&2
        exit 1
    fi

    local task_arn
    task_arn="$(aws ecs run-task \
        --cluster "${CEREBRO_CLUSTER}" \
        --task-definition "${CEREBRO_TASK_FAMILY}" \
        --launch-type FARGATE \
        --network-configuration "${network_config}" \
        --overrides "${overrides_json}" \
        --query 'tasks[0].taskArn' \
        --output text)"

    if [ -z "${task_arn}" ] || [ "${task_arn}" = "None" ]; then
        echo "::error title=closeout::aws ecs run-task did not return a taskArn" >&2
        exit 1
    fi

    echo "Started task ${task_arn}; waiting for completion..."
    aws ecs wait tasks-stopped --cluster "${CEREBRO_CLUSTER}" --tasks "${task_arn}"

    local task_id
    task_id="${task_arn##*/}"
    local log_stream="ecs/cerebro/${task_id}"

    echo "Fetching log events from ${CEREBRO_LOG_GROUP}/${log_stream}"
    aws logs filter-log-events \
        --log-group-name "${CEREBRO_LOG_GROUP}" \
        --log-stream-names "${log_stream}" \
        --output json \
        | python3 -c "
import json, sys
for event in json.load(sys.stdin).get('events', []):
    print(event.get('message', ''))
" || true

    local described
    described="$(aws ecs describe-tasks --cluster "${CEREBRO_CLUSTER}" --tasks "${task_arn}" --output json)"
    local exit_code
    exit_code="$(printf '%s' "${described}" | python3 -c "
import json, sys
data = json.load(sys.stdin)
tasks = data.get('tasks', [])
if not tasks:
    print('1')
    sys.exit(0)
containers = tasks[0].get('containers', [])
for c in containers:
    if c.get('name') == 'cerebro':
        code = c.get('exitCode')
        print(code if code is not None else 1)
        sys.exit(0)
code = containers[0].get('exitCode') if containers else None
print(code if code is not None else 1)
")"

    echo "Task container exit code: ${exit_code}"
    exit "${exit_code}"
}

main() {
    if [ "${#}" -lt 1 ]; then
        usage >&2
        exit 64
    fi

    local subcommand="$1"
    shift || true

    case "${subcommand}" in
        assert-kms-allow)
            cmd_assert_kms_allow
            ;;
        run)
            cmd_run
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            echo "Unknown subcommand: ${subcommand}" >&2
            usage >&2
            exit 64
            ;;
    esac
}

main "$@"
