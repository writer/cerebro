#!/usr/bin/env bash
set -euo pipefail

readonly cosign_image="ghcr.io/sigstore/cosign/cosign@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037"
readonly docker_config="${HOME}/.docker"

test -f "${docker_config}/config.json"

docker_args=(
  run
  --rm
  --user "$(id -u):$(id -g)"
  --volume "${docker_config}:/cosign-docker:ro"
  --env DOCKER_CONFIG=/cosign-docker
  --env HOME=/tmp
)

if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
  docker_args+=(
    --volume "${GITHUB_WORKSPACE}:${GITHUB_WORKSPACE}:ro"
    --workdir "${GITHUB_WORKSPACE}"
  )
fi

for variable in ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
  if [[ -n "${!variable:-}" ]]; then
    docker_args+=(--env "${variable}")
  fi
done

exec docker "${docker_args[@]}" "${cosign_image}" "$@"
