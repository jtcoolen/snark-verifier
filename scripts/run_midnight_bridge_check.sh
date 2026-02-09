#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PROFILE_PATH="${1:-examples/midnight_protocol_profile.json}"
PROOF_PATH="${2:-examples/midnight_proof_metadata.json}"

cargo run --package snark-verifier-sdk --example midnight_bridge_check -- \
  "$PROFILE_PATH" \
  "$PROOF_PATH"
