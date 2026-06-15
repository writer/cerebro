#!/usr/bin/env bash
set -euo pipefail

command="${1:-}"

run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

usage() {
  echo "usage: $0 create <environment> <image-tag> <web-image-tag> <production-environment> | status <deployment-id> <environment> <state> <description>" >&2
}

case "${command}" in
  create)
    environment="${2:-}"
    image_tag="${3:-}"
    web_image_tag="${4:-}"
    production_environment="${5:-false}"
    if [ -z "${environment}" ] || [ -z "${image_tag}" ]; then
      usage
      exit 2
    fi

    transient_environment=false
    if [ "${production_environment}" != "true" ]; then
      transient_environment=true
    fi

    description="Deploy ${environment} Cerebro ${image_tag}"
    body="$(
      jq -nc \
        --arg ref "${GITHUB_SHA}" \
        --arg environment "${environment}" \
        --arg description "${description}" \
        --arg image_tag "${image_tag}" \
        --arg web_image_tag "${web_image_tag}" \
        --arg run_url "${run_url}" \
        --argjson production_environment "${production_environment}" \
        --argjson transient_environment "${transient_environment}" \
        '{
          ref: $ref,
          environment: $environment,
          auto_merge: false,
          required_contexts: [],
          production_environment: $production_environment,
          transient_environment: $transient_environment,
          description: $description,
          payload: ({
            imageTag: $image_tag,
            workflowRun: $run_url
          } + (if $web_image_tag == "" then {} else {webImageTag: $web_image_tag} end))
        }'
    )"

    response="$(gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments" --input - <<<"${body}")"
    deployment_id="$(jq -r '.id' <<<"${response}")"
    deployment_url="$(jq -r '.url' <<<"${response}")"
    html_url="$(jq -r '.statuses_url' <<<"${response}")"
    {
      echo "deployment_id=${deployment_id}"
      echo "deployment_url=${deployment_url}"
      echo "deployment_statuses_url=${html_url}"
    } >> "${GITHUB_OUTPUT}"
    echo "Created GitHub deployment ${deployment_id} for ${environment}"
    ;;
  status)
    deployment_id="${2:-}"
    environment="${3:-}"
    state="${4:-}"
    description="${5:-}"
    if [ -z "${deployment_id}" ] || [ -z "${environment}" ] || [ -z "${state}" ]; then
      usage
      exit 2
    fi

    body="$(
      jq -nc \
        --arg state "${state}" \
        --arg environment "${environment}" \
        --arg description "${description:-Deployment ${state}}" \
        --arg run_url "${run_url}" \
        '{
          state: $state,
          environment: $environment,
          description: $description,
          log_url: $run_url,
          auto_inactive: false
        }'
    )"

    gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments/${deployment_id}/statuses" --input - <<<"${body}" >/dev/null
    echo "Marked GitHub deployment ${deployment_id} ${state}"
    ;;
  *)
    usage
    exit 2
    ;;
esac
