#!/usr/bin/env bash
set -euo pipefail

version="${COSIGN_VERSION:-v2.6.1}"
install_dir="${RUNNER_TEMP:?RUNNER_TEMP is required}/cosign"
attempts="${COSIGN_INSTALL_ATTEMPTS:-3}"
delay_seconds="${COSIGN_INSTALL_RETRY_SECONDS:-10}"
mkdir -p "${install_dir}"

for attempt in $(seq 1 "${attempts}"); do
  if GOBIN="${install_dir}" go install "github.com/sigstore/cosign/v2/cmd/cosign@${version}"; then
    break
  fi
  if [ "${attempt}" -eq "${attempts}" ]; then
    exit 1
  fi
  echo "cosign install failed on attempt ${attempt}/${attempts}; retrying in ${delay_seconds}s" >&2
  sleep "${delay_seconds}"
  delay_seconds=$((delay_seconds * 2))
done

echo "COSIGN_BIN=${install_dir}/cosign" >> "${GITHUB_ENV:?GITHUB_ENV is required}"
"${install_dir}/cosign" version
