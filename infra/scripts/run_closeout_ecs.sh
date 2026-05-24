#!/usr/bin/env bash
# Helper script used by .github/workflows/closeout.yml to:
#   1. Assert that the env's task role has the required KMS
#      permissions for encrypt-only audit bucket writes.
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

canonical_iam_role_arn() {
    local arn="$1"
    python3 - "${arn}" <<'PY'
import re
import sys

arn = sys.argv[1]
match = re.match(r"^arn:aws:sts::([0-9]{12}):assumed-role/([^/]+)/.+$", arn)
if match:
    print(f"arn:aws:iam::{match.group(1)}:role/{match.group(2)}")
else:
    print(arn)
PY
}

task_role_session_policy() {
    local key_arn="$1"
    python3 - "${key_arn}" <<'PY'
import json
import sys

key_arn = sys.argv[1]
print(json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey",
        ],
        "Resource": key_arn,
    }],
}, separators=(",", ":")))
PY
}

try_use_task_role_credentials() {
    local role_arn="$1"
    local key_arn="$2"
    local current_arn
    current_arn="$(aws sts get-caller-identity --query 'Arn' --output text)"
    local current_role_arn
    current_role_arn="$(canonical_iam_role_arn "${current_arn}")"

    if [ "${current_role_arn}" = "${role_arn}" ]; then
        echo "Already running with task role credentials: ${role_arn}"
        return 0
    fi

    local session_name
    session_name="closeout-kms-assert-${GITHUB_RUN_ID:-manual}-$$"
    # AWS role session names allow [A-Za-z0-9+=,.@-] and max 64 chars.
    session_name="$(printf '%s' "${session_name}" | tr -c 'A-Za-z0-9+=,.@-' '-' | cut -c1-64)"

    echo "Attempting to assume task role ${role_arn} for real KMS validation"
    local assume_error
    assume_error="$(mktemp)"
    local creds_json
    if ! creds_json="$(aws sts assume-role \
        --role-arn "${role_arn}" \
        --role-session-name "${session_name}" \
        --duration-seconds 900 \
        --policy "$(task_role_session_policy "${key_arn}")" \
        --output json 2>"${assume_error}")"; then
        echo "::warning title=closeout::Could not assume ${role_arn}; falling back to task-role policy inspection plus a real KMS probe with current credentials" >&2
        sed 's/^/  /' "${assume_error}" >&2 || true
        rm -f "${assume_error}"
        return 1
    fi
    rm -f "${assume_error}"

    export AWS_ACCESS_KEY_ID
    AWS_ACCESS_KEY_ID="$(printf '%s' "${creds_json}" | python3 -c "import json, sys; print(json.load(sys.stdin)['Credentials']['AccessKeyId'])")"
    export AWS_SECRET_ACCESS_KEY
    AWS_SECRET_ACCESS_KEY="$(printf '%s' "${creds_json}" | python3 -c "import json, sys; print(json.load(sys.stdin)['Credentials']['SecretAccessKey'])")"
    export AWS_SESSION_TOKEN
    AWS_SESSION_TOKEN="$(printf '%s' "${creds_json}" | python3 -c "import json, sys; print(json.load(sys.stdin)['Credentials']['SessionToken'])")"
    unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE
    echo "Assumed task role ${role_arn}; KMS validation will run with task role credentials"
    return 0
}

assert_task_role_policy_allows_kms() {
    local role_name="$1"
    local key_arn="$2"

    python3 - "${role_name}" "${key_arn}" <<'PY'
import fnmatch
import json
import subprocess
import sys
import urllib.parse

role_name, key_arn = sys.argv[1:3]
required_actions = ["kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]


def aws_json(args):
    return json.loads(subprocess.check_output(["aws", *args, "--output", "json"], text=True))


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def action_matches(pattern, action):
    return fnmatch.fnmatchcase(action.lower(), str(pattern).lower())


def resource_matches(pattern, resource):
    return fnmatch.fnmatchcase(resource, str(pattern))


def document_allows(document):
    allowed = set()
    denied = set()
    for statement in as_list(document.get("Statement", [])):
        effect = str(statement.get("Effect", "")).lower()
        actions = as_list(statement.get("Action"))
        not_actions = as_list(statement.get("NotAction"))
        resources = as_list(statement.get("Resource") or "*")
        if not actions and not_actions:
            # The closeout audit grant is expected to be an explicit Action
            # allow. Do not infer permissions from NotAction statements.
            continue
        matching_actions = {
            action
            for action in required_actions
            if any(action_matches(pattern, action) for pattern in actions)
        }
        if not matching_actions:
            continue
        if not any(resource_matches(pattern, key_arn) or str(pattern) == "*" for pattern in resources):
            continue
        if effect == "deny":
            denied.update(matching_actions)
        elif effect == "allow":
            allowed.update(matching_actions)
    return allowed, denied


allowed = set()
denied = set()

inline_names = aws_json(["iam", "list-role-policies", "--role-name", role_name]).get("PolicyNames", [])
for name in inline_names:
    raw_doc = aws_json(["iam", "get-role-policy", "--role-name", role_name, "--policy-name", name])["PolicyDocument"]
    if isinstance(raw_doc, str):
        raw_doc = json.loads(urllib.parse.unquote(raw_doc))
    doc_allowed, doc_denied = document_allows(raw_doc)
    allowed.update(doc_allowed)
    denied.update(doc_denied)

attached = aws_json(["iam", "list-attached-role-policies", "--role-name", role_name]).get("AttachedPolicies", [])
for policy in attached:
    policy_arn = policy["PolicyArn"]
    default_version = aws_json(["iam", "get-policy", "--policy-arn", policy_arn])["Policy"]["DefaultVersionId"]
    raw_doc = aws_json(["iam", "get-policy-version", "--policy-arn", policy_arn, "--version-id", default_version])["PolicyVersion"]["Document"]
    if isinstance(raw_doc, str):
        raw_doc = json.loads(urllib.parse.unquote(raw_doc))
    doc_allowed, doc_denied = document_allows(raw_doc)
    allowed.update(doc_allowed)
    denied.update(doc_denied)

missing = sorted(set(required_actions) - allowed)
if denied:
    print(f"::error title=closeout::Task role {role_name} has an explicit deny for KMS actions on {key_arn}: {', '.join(sorted(denied))}", file=sys.stderr)
    sys.exit(1)
if missing:
    print(f"::error title=closeout::Task role {role_name} policies do not allow required KMS actions on {key_arn}: {', '.join(missing)}", file=sys.stderr)
    sys.exit(1)

print(f"Task role {role_name} identity policies allow {', '.join(required_actions)} on {key_arn}")
PY
}

assert_kms_key_policy_delegates_to_iam() {
    local key_arn="$1"

    python3 - "${key_arn}" <<'PY'
import fnmatch
import json
import re
import subprocess
import sys

key_arn = sys.argv[1]
match = re.match(r"^arn:aws:kms:[^:]+:([0-9]{12}):key/.+$", key_arn)
if not match:
    print(f"::error title=closeout::Cannot extract account id from KMS key ARN {key_arn}", file=sys.stderr)
    sys.exit(1)

account_id = match.group(1)
account_root = f"arn:aws:iam::{account_id}:root"
required_actions = ["kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def action_matches(pattern, action):
    return fnmatch.fnmatchcase(action.lower(), str(pattern).lower())


def principal_matches(principal):
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    return account_root in [str(value) for value in as_list(principal.get("AWS"))]


raw = subprocess.check_output(
    ["aws", "kms", "get-key-policy", "--key-id", key_arn, "--policy-name", "default", "--query", "Policy", "--output", "text"],
    text=True,
)
policy = json.loads(raw)

for statement in as_list(policy.get("Statement", [])):
    if str(statement.get("Effect", "")).lower() != "allow":
        continue
    if not principal_matches(statement.get("Principal")):
        continue
    actions = as_list(statement.get("Action"))
    if all(any(action_matches(pattern, action) for pattern in actions) for action in required_actions):
        print(f"KMS key policy for {key_arn} delegates required KMS actions to IAM in account {account_id}")
        sys.exit(0)

print(f"::error title=closeout::KMS key policy for {key_arn} does not delegate required KMS actions to account IAM policies", file=sys.stderr)
sys.exit(1)
PY
}

assert_kms_describe_encrypt_and_generate_data_key() {
    local key_arn="$1"
    local caller_arn
    caller_arn="$(aws sts get-caller-identity --query 'Arn' --output text)"
    echo "Running real KMS DescribeKey/Encrypt/GenerateDataKey probe as ${caller_arn}"

    local described_key
    described_key="$(aws kms describe-key \
        --key-id "${key_arn}" \
        --query 'KeyMetadata.Arn' \
        --output text)"
    if [ -z "${described_key}" ] || [ "${described_key}" = "None" ]; then
        echo "::error title=closeout::kms:DescribeKey returned no key ARN for ${key_arn}" >&2
        exit 1
    fi
    echo "  kms:DescribeKey succeeded for ${described_key}"

    local payload_file
    payload_file="$(mktemp)"
    printf 'cerebro-closeout-kms-probe:%s\n' "${GITHUB_RUN_ID:-manual}" > "${payload_file}"
    local ciphertext
    if ! ciphertext="$(aws kms encrypt \
        --key-id "${key_arn}" \
        --plaintext "fileb://${payload_file}" \
        --query 'CiphertextBlob' \
        --output text)"; then
        rm -f "${payload_file}"
        exit 1
    fi
    rm -f "${payload_file}"

    if [ -z "${ciphertext}" ] || [ "${ciphertext}" = "None" ]; then
        echo "::error title=closeout::kms:Encrypt returned an empty CiphertextBlob for ${key_arn}" >&2
        exit 1
    fi
    echo "  kms:Encrypt succeeded and returned a CiphertextBlob"

    local data_key_ciphertext
    data_key_ciphertext="$(aws kms generate-data-key \
        --key-id "${key_arn}" \
        --key-spec AES_256 \
        --query 'CiphertextBlob' \
        --output text)"
    if [ -z "${data_key_ciphertext}" ] || [ "${data_key_ciphertext}" = "None" ]; then
        echo "::error title=closeout::kms:GenerateDataKey returned an empty CiphertextBlob for ${key_arn}" >&2
        exit 1
    fi
    echo "  kms:GenerateDataKey succeeded and returned an encrypted data key"
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

    echo "Informational IAM simulation for allowed actions on ${AUDIT_BUCKET_KMS_KEY_ARN} for ${role_arn}"
    local allowed_json
    allowed_json="$(aws iam simulate-principal-policy \
        --policy-source-arn "${role_arn}" \
        --action-names "${allowed_actions[@]}" \
        --resource-arns "${AUDIT_BUCKET_KMS_KEY_ARN}" \
        --output json)"

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
        echo "  ${action}: ${decision:-missing} (informational only)"
    done

    echo "Informational IAM simulation for denied actions on ${AUDIT_BUCKET_KMS_KEY_ARN} for ${role_arn}"
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
        echo "  ${action}: ${decision:-missing} (informational only; expected non-allowed)"
    done

    local using_task_role=false
    if try_use_task_role_credentials "${role_arn}" "${AUDIT_BUCKET_KMS_KEY_ARN}"; then
        using_task_role=true
    else
        assert_task_role_policy_allows_kms "${CEREBRO_TASK_ROLE_NAME}" "${AUDIT_BUCKET_KMS_KEY_ARN}"
        assert_kms_key_policy_delegates_to_iam "${AUDIT_BUCKET_KMS_KEY_ARN}"
    fi

    assert_kms_describe_encrypt_and_generate_data_key "${AUDIT_BUCKET_KMS_KEY_ARN}"

    if [ "${using_task_role}" != "true" ]; then
        echo "::warning title=closeout::KMS probe succeeded with current credentials; task-role access was validated from attached IAM policy because direct STS AssumeRole is not trusted for ECS task roles" >&2
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
    local tenant_id="${11}"

    python3 - "${env_name}" "${dry_run}" "${rule_ids_csv}" "${source_csv}" "${older_than}" "${reason}" "${change_ticket}" "${audit_bucket}" "${actor}" "${run_id}" "${tenant_id}" <<'PY'
import json
import sys

(env_name, dry_run, rule_ids_csv, source_csv, older_than,
 reason, change_ticket, audit_bucket, actor, run_id, tenant_id) = sys.argv[1:12]

command = ["closeout"]

rule_ids = [v.strip() for v in rule_ids_csv.split(",") if v.strip()]
for rule_id in rule_ids:
    command.extend(["--rule-id", rule_id])

sources = [v.strip() for v in source_csv.split(",") if v.strip()]
for src in sources:
    command.extend(["--source", src])

if older_than:
    command.extend(["--older-than", older_than])

command.extend(["--tenant-id", tenant_id])
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
    require_env INPUT_TENANT_ID
    require_env INPUT_REASON

    local dry_run_value="${INPUT_DRY_RUN:-true}"
    local rule_ids_csv="${INPUT_RULE_IDS:-}"
    local source_csv="${INPUT_SOURCE:-}"
    local tenant_id="${INPUT_TENANT_ID}"
    local older_than="${INPUT_OLDER_THAN:-}"
    local reason="${INPUT_REASON}"
    local change_ticket="${INPUT_CHANGE_TICKET:-}"
    local actor="${GITHUB_ACTOR_ARG:-}"
    local run_id="${GITHUB_RUN_ID:-}"

    local command_json
    command_json="$(build_command_array "${INPUT_ENV}" "${dry_run_value}" "${rule_ids_csv}" "${source_csv}" "${older_than}" "${reason}" "${change_ticket}" "${AUDIT_BUCKET}" "${actor}" "${run_id}" "${tenant_id}")"

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
