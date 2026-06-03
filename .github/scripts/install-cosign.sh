#!/usr/bin/env bash
set -euo pipefail

version="${COSIGN_VERSION:-v2.6.1}"
install_dir="${RUNNER_TEMP:?RUNNER_TEMP is required}/cosign"
mkdir -p "${install_dir}"

GOBIN="${install_dir}" go install "github.com/sigstore/cosign/v2/cmd/cosign@${version}"
echo "COSIGN_BIN=${install_dir}/cosign" >> "${GITHUB_ENV:?GITHUB_ENV is required}"
"${install_dir}/cosign" version
