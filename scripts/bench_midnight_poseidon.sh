#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

OUT_ROOT="${1:-out/bench/midnight_poseidon}"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${OUT_ROOT}/${STAMP}"
ARTIFACT_DIR="${RUN_DIR}/artifacts"
LOG_PATH="${RUN_DIR}/run.log"
SUMMARY_PATH="${ARTIFACT_DIR}/midnight_poseidon_bench.json"

# Baselines (override via env for your network/circuit profile).
: "${BASELINE_UNCOMPRESSED_CALL_GAS:=601333}"
: "${BASELINE_COMPRESSED_CALL_GAS:=1025549}"

mkdir -p "${RUN_DIR}" "${ARTIFACT_DIR}"

echo "Running midnight_poseidon_evm benchmark..."
echo "  output: ${RUN_DIR}"

MIDNIGHT_EVM_OUT_DIR="${ARTIFACT_DIR}" RUN_REVM=1 \
  cargo run --example midnight_poseidon_evm --features midnight,loader_evm,revm -p snark-verifier-sdk \
  | tee "${LOG_PATH}"

if [[ ! -f "${SUMMARY_PATH}" ]]; then
  echo "Missing summary JSON: ${SUMMARY_PATH}" >&2
  exit 1
fi

uncompressed_call_gas="$(jq -r '.revm.uncompressed.call_gas // empty' "${SUMMARY_PATH}")"
compressed_call_gas="$(jq -r '.revm.compressed.call_gas // empty' "${SUMMARY_PATH}")"
preferred_variant="$(jq -r '.revm.preferred_variant // "unknown"' "${SUMMARY_PATH}")"

if [[ -z "${uncompressed_call_gas}" || ! "${uncompressed_call_gas}" =~ ^[0-9]+$ ]]; then
  echo "Missing or non-numeric uncompressed call gas in ${SUMMARY_PATH}" >&2
  exit 1
fi

if [[ -n "${compressed_call_gas}" && ! "${compressed_call_gas}" =~ ^[0-9]+$ ]]; then
  echo "Non-numeric compressed call gas in ${SUMMARY_PATH}" >&2
  exit 1
fi

max_uncompressed_call_gas=$(( (BASELINE_UNCOMPRESSED_CALL_GAS * 102 + 99) / 100 ))
max_compressed_call_gas=$(( (BASELINE_COMPRESSED_CALL_GAS * 102 + 99) / 100 ))

echo "Regression checks:"
echo "  uncompressed call gas: ${uncompressed_call_gas} (max ${max_uncompressed_call_gas}; baseline ${BASELINE_UNCOMPRESSED_CALL_GAS})"
if [[ -n "${compressed_call_gas}" ]]; then
  echo "  compressed call gas:   ${compressed_call_gas} (max ${max_compressed_call_gas}; baseline ${BASELINE_COMPRESSED_CALL_GAS})"
fi
echo "  preferred variant:     ${preferred_variant}"

fail=0
if (( uncompressed_call_gas > max_uncompressed_call_gas )); then
  echo "FAIL: uncompressed call gas regressed by >2% vs baseline" >&2
  fail=1
fi
if [[ -n "${compressed_call_gas}" ]] && (( compressed_call_gas > max_compressed_call_gas )); then
  echo "FAIL: compressed call gas regressed by >2% vs baseline" >&2
  fail=1
fi

mkdir -p "${OUT_ROOT}"
cp "${SUMMARY_PATH}" "${OUT_ROOT}/latest.json"
echo "Summary JSON: ${SUMMARY_PATH}"
echo "Latest JSON:  ${OUT_ROOT}/latest.json"

if (( fail != 0 )); then
  exit 1
fi

echo "All regression checks passed."
