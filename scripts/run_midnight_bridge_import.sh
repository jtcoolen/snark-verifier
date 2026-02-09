#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VK_PATH="${1:-}"
PROOF_PATH="${2:-}"
INSTANCES_PATH="${3:-}"
OUTPUT_STEM="${4:-examples/midnight_bridge_poseidon_import}"

if [[ -z "$VK_PATH" || -z "$PROOF_PATH" || -z "$INSTANCES_PATH" ]]; then
  echo "usage: run_midnight_bridge_import.sh <vk.bin> <proof.bin> <instances.json> [output_stem]" >&2
  exit 2
fi

cargo run --package snark-verifier-sdk \
  --example midnight_bridge_import \
  --features loader_halo2 \
  --features loader_evm \
  -- \
  "$VK_PATH" \
  "$PROOF_PATH" \
  "$INSTANCES_PATH" \
  "$OUTPUT_STEM"
