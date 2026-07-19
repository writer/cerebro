#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
evidence_dir="$repo_root/tmp/rust-source-kernel-evidence"
rust_module="$repo_root/target/wasm32-unknown-unknown/release/cerebro_sourceruntime_recordkernel.wasm"
go_module="$evidence_dir/go-wasi-baseline.wasm"
cargo_home=${CARGO_HOME:-"$HOME/.cargo"}

mkdir -p "$evidence_dir"
cd "$repo_root"

RUSTFLAGS="--remap-path-prefix=$repo_root=/workspace --remap-path-prefix=$cargo_home=/cargo" \
  cargo build --locked --release --target wasm32-unknown-unknown -p cerebro-sourceruntime-recordkernel
GOOS=wasip1 GOARCH=wasm go build -buildvcs=false -trimpath -o "$go_module" ./tools/wasminspect/testdata/go-wasi-baseline
go run ./tools/wasminspect "$rust_module" "$go_module"
