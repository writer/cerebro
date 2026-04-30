#!/usr/bin/env bash
# Portable cerebro build with the Kuzu graph store enabled.
#
# `github.com/kuzudb/go-kuzu` ships a per-OS/arch shared library and bakes its module-cache path
# into the rpath via `${SRCDIR}` when CGO links the binary. Shipping the resulting binary off the
# build host means libkuzu can no longer be located at run time. This script stages the matching
# libkuzu next to ./bin/cerebro and overrides CGO_LDFLAGS to use a `$ORIGIN`-relative rpath so the
# binary stays portable.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"
mkdir -p "${BIN_DIR}"

GO_KUZU_DIR="$(go list -m -f '{{.Dir}}' github.com/kuzudb/go-kuzu 2>/dev/null || true)"
if [[ -z "${GO_KUZU_DIR}" ]]; then
  echo "scripts/build_with_kuzu.sh: github.com/kuzudb/go-kuzu not in module graph" >&2
  exit 1
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64|Darwin-x86_64) LIB_SUBDIR="lib/dynamic/darwin"; LIB_NAME="libkuzu.dylib";;
  Linux-x86_64)               LIB_SUBDIR="lib/dynamic/linux-amd64"; LIB_NAME="libkuzu.so";;
  Linux-aarch64|Linux-arm64)  LIB_SUBDIR="lib/dynamic/linux-arm64"; LIB_NAME="libkuzu.so";;
  *) echo "scripts/build_with_kuzu.sh: unsupported host $(uname -s)/$(uname -m)" >&2; exit 1;;
esac

LIB_SRC="${GO_KUZU_DIR}/${LIB_SUBDIR}/${LIB_NAME}"
if [[ ! -e "${LIB_SRC}" ]]; then
  echo "scripts/build_with_kuzu.sh: missing libkuzu at ${LIB_SRC}" >&2
  exit 1
fi
cp -f "${LIB_SRC}" "${BIN_DIR}/${LIB_NAME}"
chmod 0644 "${BIN_DIR}/${LIB_NAME}"

# Override the rpath baked by go-kuzu's #cgo LDFLAGS with a runtime-portable one.
case "$(uname -s)" in
  Darwin) RPATH="-Wl,-rpath,@loader_path";;
  Linux)  RPATH="-Wl,-rpath,\$ORIGIN";;
esac

export CGO_LDFLAGS="${RPATH}${CGO_LDFLAGS:+ ${CGO_LDFLAGS}}"
exec go build -o "${BIN_DIR}/cerebro" ./cmd/cerebro
