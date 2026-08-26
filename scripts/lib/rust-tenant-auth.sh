#!/usr/bin/env bash

# Shared tenant authentication for direct Rust platform qualification probes.
# The message framing must stay byte-for-byte compatible with TenantRequestAuth.
cerebro_rust_tenant_bearer() {
  local secret="${1:?shared secret is required}"
  local tenant="${2:?tenant ID is required}"
  local secret_bytes
  local tenant_bytes
  local tenant_length_hex
  local tenant_length_escapes=""
  local offset
  local digest

  secret_bytes="$(printf '%s' "${secret}" | LC_ALL=C wc -c | tr -d '[:space:]')"
  if ((secret_bytes < 32)); then
    echo "Rust graph shared secret must be at least 32 bytes" >&2
    return 1
  fi

  tenant_bytes="$(printf '%s' "${tenant}" | LC_ALL=C wc -c | tr -d '[:space:]')"
  printf -v tenant_length_hex '%016x' "${tenant_bytes}"
  for ((offset = 0; offset < 16; offset += 2)); do
    tenant_length_escapes+="\\x${tenant_length_hex:offset:2}"
  done

  digest="$({
    printf 'cerebro-organizational-graph/tenant/v1\0'
    printf '%b' "${tenant_length_escapes}"
    printf '%s' "${tenant}"
  } | openssl dgst -sha256 -hmac "${secret}" -r)"
  digest="${digest%% *}"
  if ! [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Unable to derive Rust graph tenant authentication" >&2
    return 1
  fi
  printf '%s\n' "${digest}"
}
