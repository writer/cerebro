#!/usr/bin/env bash
set -euo pipefail

stack_name="${1:?usage: wait-for-ecr-image.sh <stack-name>}"
config_file="infra/aws/Pulumi.${stack_name}.yaml"
ecr_repository="${ECR_REPOSITORY:-cerebro}"
aws_region="${AWS_REGION:-us-east-1}"
max_attempts="${MAX_ATTEMPTS:-60}"
sleep_seconds="${SLEEP_SECONDS:-10}"

image_tag="$(awk '$1 == "cerebro:imageTag:" { print $2; exit }' "${config_file}")"
if [ -z "${image_tag}" ]; then
  echo "ERROR: cerebro:imageTag not found in ${config_file}"
  exit 1
fi
web_image_tag="$(awk '$1 == "cerebro:webImageTag:" { print $2; exit }' "${config_file}")"

wait_for_tag() {
  local image_tag="$1"
  local label="$2"

  echo "Waiting for ${label} ${ecr_repository}:${image_tag} in ${aws_region} before deploying ${stack_name}..."
  for attempt in $(seq 1 "${max_attempts}"); do
    err_file="$(mktemp)"
    if aws ecr describe-images --repository-name "${ecr_repository}" --image-ids imageTag="${image_tag}" >/dev/null 2>"${err_file}"; then
      rm -f "${err_file}"
      echo "Found ${label} ${ecr_repository}:${image_tag}; continuing"
      return 0
    fi

    if ! grep -q "ImageNotFoundException" "${err_file}"; then
      cat "${err_file}" >&2
      rm -f "${err_file}"
      echo "ERROR: failed to check ECR image availability"
      exit 1
    fi
    rm -f "${err_file}"

    if [ "${attempt}" -eq "${max_attempts}" ]; then
      break
    fi
    echo "${label} image not available yet (attempt ${attempt}/${max_attempts}); retrying in ${sleep_seconds} seconds"
    sleep "${sleep_seconds}"
  done

  echo "ERROR: ${label} ${ecr_repository}:${image_tag} was not found in ECR after ${max_attempts} attempts"
  exit 1
}

wait_for_tag "${image_tag}" "api"

if [ -n "${web_image_tag}" ]; then
  wait_for_tag "${web_image_tag}" "web"
fi
