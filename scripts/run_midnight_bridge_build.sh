#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROFILE_PATH="${1:-snark-verifier-sdk/examples/midnight_bridge_protocol_profile.example.json}"
PROOF_PATH="${2:-snark-verifier-sdk/examples/midnight_bridge_proof_metadata.example.json}"
OUTPUT_STEM="${3:-examples/midnight_bridge_poseidon}"
INSTANCES_JSON="${4:-}"
PROOF_BIN="${5:-}"

if [[ -n "$INSTANCES_JSON" || -n "$PROOF_BIN" ]]; then
  if [[ -z "$INSTANCES_JSON" || -z "$PROOF_BIN" ]]; then
    echo "error: provide both instances_json and proof_bin, or neither" >&2
    exit 2
  fi
  cargo run --package snark-verifier-sdk \
    --example midnight_bridge_build \
    --features loader_halo2 \
    --features loader_evm \
    -- \
    "$PROFILE_PATH" \
    "$PROOF_PATH" \
    "$OUTPUT_STEM" \
    "$INSTANCES_JSON" \
    "$PROOF_BIN"
else
  cargo run --package snark-verifier-sdk \
    --example midnight_bridge_build \
    --features loader_halo2 \
    --features loader_evm \
    -- \
    "$PROFILE_PATH" \
    "$PROOF_PATH" \
    "$OUTPUT_STEM"
fi
