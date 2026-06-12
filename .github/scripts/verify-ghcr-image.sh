#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: verify-ghcr-image.sh <image> <tag> <certificate-identity-regexp> [attestation-mode]}"
tag="${2:?usage: verify-ghcr-image.sh <image> <tag> <certificate-identity-regexp> [attestation-mode]}"
certificate_identity_regexp="${3:?usage: verify-ghcr-image.sh <image> <tag> <certificate-identity-regexp> [attestation-mode]}"
attestation_mode="${4:-warn}"
cosign_bin="${COSIGN_BIN:-${RUNNER_TEMP:-/tmp}/cosign/cosign}"

if [ ! -x "${cosign_bin}" ]; then
  echo "cosign binary not found at ${cosign_bin}; run .github/scripts/install-cosign.sh first" >&2
  exit 1
fi

image_ref="${image}:${tag}"
verify_json="$("${cosign_bin}" verify \
  --certificate-identity-regexp "${certificate_identity_regexp}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${image_ref}")"

digest="$(jq -r '.[0].critical.image["docker-manifest-digest"] // empty' <<<"${verify_json}")"
if ! [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Could not resolve verified digest for ${image_ref}" >&2
  exit 1
fi

case "${attestation_mode}" in
  signature-only)
    ;;
  true | require | warn | false)
    tree="$("${cosign_bin}" tree "${image}@${digest}")"
    if ! grep -Eq 'Attestation|SBOM|Provenance' <<<"${tree}"; then
      if [ "${attestation_mode}" = "true" ] || [ "${attestation_mode}" = "require" ]; then
        echo "No SBOM/provenance attestations found for ${image}@${digest}" >&2
        printf '%s\n' "${tree}" >&2
        exit 1
      fi
      echo "::warning::No SBOM/provenance attestations found for ${image}@${digest}; signature and digest are verified" >&2
    fi
    ;;
  *)
    echo "Unknown attestation mode ${attestation_mode}; expected signature-only, warn, or require" >&2
    exit 1
    ;;
esac

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "digest=${digest}" >> "${GITHUB_OUTPUT}"
fi
echo "Verified ${image_ref} at ${digest}"
