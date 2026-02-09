#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FEATURES=(--features loader_halo2 --features loader_evm)
if [[ "${RUN_REVM:-0}" == "1" ]]; then
  FEATURES+=(--features revm)
fi

cargo run --package snark-verifier-sdk \
  --example midnight_keccak_poseidon \
  "${FEATURES[@]}" \
  --release
