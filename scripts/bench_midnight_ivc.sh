#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

OUT_ROOT="${1:-out/bench/midnight_ivc}"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${OUT_ROOT}/${STAMP}"
ARTIFACT_DIR="${RUN_DIR}/artifacts"
LOG_PATH="${RUN_DIR}/run.log"
SUMMARY_PATH="${ARTIFACT_DIR}/midnight_ivc_bench.json"

# Baselines (can be overridden by env for network/circuit-specific tuning).
: "${BASELINE_HYBRID_CALL_GAS:=7171196}"
: "${BASELINE_HYBRID_PAGE_BYTES:=717668}"
: "${BASELINE_COMPACT_CALL_GAS:=7564158}"
: "${BASELINE_COMPACT_PROGRAM_WORDS:=27517}"
: "${MAX_UNROLLED_SHARDED_CALL_GAS:=1600000}"
: "${EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES:=24576}"
: "${EVM_INITCODE_SIZE_LIMIT_BYTES:=49152}"
: "${REQUIRE_UNROLLED_DEPLOYABLE:=0}"
: "${REQUIRE_UNROLLED_SHARDED_DEPLOYABLE:=1}"

mkdir -p "${RUN_DIR}" "${ARTIFACT_DIR}"

echo "Running midnight_ivc_evm benchmark..."
echo "  output: ${RUN_DIR}"

MIDNIGHT_EVM_OUT_DIR="${ARTIFACT_DIR}" \
  cargo run --example midnight_ivc_evm --features midnight,loader_evm,revm -p snark-verifier-sdk \
  | tee "${LOG_PATH}"

if [[ ! -f "${SUMMARY_PATH}" ]]; then
  echo "Missing summary JSON: ${SUMMARY_PATH}" >&2
  exit 1
fi

hybrid_call_gas="$(jq -r '.hybrid.revm.call_gas // empty' "${SUMMARY_PATH}")"
hybrid_page_bytes="$(jq -r '.hybrid.page_runtime_total_bytes // empty' "${SUMMARY_PATH}")"
compact_call_gas="$(jq -r '.compact.revm.call_gas // empty' "${SUMMARY_PATH}")"
compact_program_words="$(jq -r '.compact.program_words // empty' "${SUMMARY_PATH}")"
compact_page_bytes="$(jq -r '.compact.page_runtime_total_bytes // empty' "${SUMMARY_PATH}")"
unrolled_runtime_bytes="$(jq -r '.unrolled.runtime_code_bytes // empty' "${SUMMARY_PATH}")"
unrolled_initcode_bytes="$(jq -r '.unrolled.deployment_code_bytes // empty' "${SUMMARY_PATH}")"
unrolled_runtime_within_limit="$(jq -r '.unrolled.runtime_code_within_limit // empty' "${SUMMARY_PATH}")"
unrolled_initcode_within_limit="$(jq -r '.unrolled.initcode_within_limit // empty' "${SUMMARY_PATH}")"
unrolled_call_gas="$(jq -r '.unrolled.revm.call_gas // empty' "${SUMMARY_PATH}")"
unrolled_deploy_gas="$(jq -r '.unrolled.revm.deployment_gas // empty' "${SUMMARY_PATH}")"
unrolled_sharded_call_gas="$(jq -r '.unrolled_sharded.revm.call_gas // empty' "${SUMMARY_PATH}")"
unrolled_sharded_dispatcher_runtime_bytes="$(jq -r '.unrolled_sharded.dispatcher_runtime_code_bytes // empty' "${SUMMARY_PATH}")"
unrolled_sharded_dispatcher_initcode_bytes="$(jq -r '.unrolled_sharded.dispatcher_initcode_bytes // empty' "${SUMMARY_PATH}")"
unrolled_sharded_dispatcher_runtime_within_limit="$(jq -r '.unrolled_sharded.dispatcher_runtime_code_within_limit // empty' "${SUMMARY_PATH}")"
unrolled_sharded_dispatcher_initcode_within_limit="$(jq -r '.unrolled_sharded.dispatcher_initcode_within_limit // empty' "${SUMMARY_PATH}")"
unrolled_sharded_all_shard_runtime_within_limit="$(jq -r '.unrolled_sharded.all_shard_runtime_within_limit // empty' "${SUMMARY_PATH}")"
unrolled_sharded_all_shard_initcode_within_limit="$(jq -r '.unrolled_sharded.all_shard_initcode_within_limit // empty' "${SUMMARY_PATH}")"
unrolled_sharded_shard_count="$(jq -r '.unrolled_sharded.shard_count // empty' "${SUMMARY_PATH}")"

for metric in hybrid_call_gas hybrid_page_bytes compact_call_gas compact_program_words compact_page_bytes unrolled_runtime_bytes unrolled_initcode_bytes unrolled_sharded_dispatcher_runtime_bytes unrolled_sharded_dispatcher_initcode_bytes unrolled_sharded_shard_count; do
  value="${!metric}"
  if [[ -z "${value}" || ! "${value}" =~ ^[0-9]+$ ]]; then
    echo "Missing or non-numeric metric '${metric}' in ${SUMMARY_PATH}" >&2
    exit 1
  fi
done

if [[ "${unrolled_runtime_within_limit}" != "true" && "${unrolled_runtime_within_limit}" != "false" ]]; then
  if (( unrolled_runtime_bytes <= EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES )); then
    unrolled_runtime_within_limit="true"
  else
    unrolled_runtime_within_limit="false"
  fi
fi
if [[ -n "${unrolled_sharded_call_gas}" && ! "${unrolled_sharded_call_gas}" =~ ^[0-9]+$ ]]; then
  echo "Missing or non-numeric unrolled_sharded_call_gas in ${SUMMARY_PATH}" >&2
  exit 1
fi
if [[ "${unrolled_sharded_dispatcher_runtime_within_limit}" != "true" && "${unrolled_sharded_dispatcher_runtime_within_limit}" != "false" ]]; then
  if (( unrolled_sharded_dispatcher_runtime_bytes <= EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES )); then
    unrolled_sharded_dispatcher_runtime_within_limit="true"
  else
    unrolled_sharded_dispatcher_runtime_within_limit="false"
  fi
fi
if [[ "${unrolled_sharded_dispatcher_initcode_within_limit}" != "true" && "${unrolled_sharded_dispatcher_initcode_within_limit}" != "false" ]]; then
  if (( unrolled_sharded_dispatcher_initcode_bytes <= EVM_INITCODE_SIZE_LIMIT_BYTES )); then
    unrolled_sharded_dispatcher_initcode_within_limit="true"
  else
    unrolled_sharded_dispatcher_initcode_within_limit="false"
  fi
fi
if [[ "${unrolled_sharded_all_shard_runtime_within_limit}" != "true" && "${unrolled_sharded_all_shard_runtime_within_limit}" != "false" ]]; then
  unrolled_sharded_all_shard_runtime_within_limit="false"
fi
if [[ "${unrolled_sharded_all_shard_initcode_within_limit}" != "true" && "${unrolled_sharded_all_shard_initcode_within_limit}" != "false" ]]; then
  unrolled_sharded_all_shard_initcode_within_limit="false"
fi
if [[ "${unrolled_initcode_within_limit}" != "true" && "${unrolled_initcode_within_limit}" != "false" ]]; then
  if (( unrolled_initcode_bytes <= EVM_INITCODE_SIZE_LIMIT_BYTES )); then
    unrolled_initcode_within_limit="true"
  else
    unrolled_initcode_within_limit="false"
  fi
fi

max_hybrid_call_gas=$(( (BASELINE_HYBRID_CALL_GAS * 92 + 99) / 100 ))
max_hybrid_page_bytes=$(( (BASELINE_HYBRID_PAGE_BYTES * 105 + 99) / 100 ))
max_compact_call_gas=$(( (BASELINE_COMPACT_CALL_GAS * 102 + 99) / 100 ))

echo "Key metrics:"
echo "  unrolled runtime bytes: ${unrolled_runtime_bytes} (limit ${EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES}; within_limit=${unrolled_runtime_within_limit})"
echo "  unrolled initcode bytes: ${unrolled_initcode_bytes} (limit ${EVM_INITCODE_SIZE_LIMIT_BYTES}; within_limit=${unrolled_initcode_within_limit})"
echo "  unrolled-sharded shard count: ${unrolled_sharded_shard_count}"
echo "  unrolled-sharded dispatcher runtime bytes: ${unrolled_sharded_dispatcher_runtime_bytes} (limit ${EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES}; within_limit=${unrolled_sharded_dispatcher_runtime_within_limit})"
echo "  unrolled-sharded dispatcher initcode bytes: ${unrolled_sharded_dispatcher_initcode_bytes} (limit ${EVM_INITCODE_SIZE_LIMIT_BYTES}; within_limit=${unrolled_sharded_dispatcher_initcode_within_limit})"
echo "  unrolled-sharded all shard runtime within limit: ${unrolled_sharded_all_shard_runtime_within_limit}"
echo "  unrolled-sharded all shard initcode within limit: ${unrolled_sharded_all_shard_initcode_within_limit}"
if [[ -n "${unrolled_deploy_gas}" ]]; then
  echo "  unrolled deployment gas: ${unrolled_deploy_gas}"
fi
if [[ -n "${unrolled_call_gas}" ]]; then
  echo "  unrolled call gas: ${unrolled_call_gas}"
fi
echo "  compact program words: ${compact_program_words}"
echo "  compact page bytes: ${compact_page_bytes}"
echo "  compact call gas: ${compact_call_gas}"
echo "  hybrid page bytes: ${hybrid_page_bytes}"
echo "  hybrid call gas: ${hybrid_call_gas}"
if [[ -n "${unrolled_sharded_call_gas}" ]]; then
  echo "  unrolled-sharded call gas: ${unrolled_sharded_call_gas} (max ${MAX_UNROLLED_SHARDED_CALL_GAS})"
fi

echo "Regression checks:"
echo "  hybrid call gas:   ${hybrid_call_gas} (max ${max_hybrid_call_gas}; baseline ${BASELINE_HYBRID_CALL_GAS})"
echo "  hybrid page bytes: ${hybrid_page_bytes} (max ${max_hybrid_page_bytes}; baseline ${BASELINE_HYBRID_PAGE_BYTES})"
echo "  compact call gas:  ${compact_call_gas} (max ${max_compact_call_gas}; baseline ${BASELINE_COMPACT_CALL_GAS})"
echo "  compact words:     ${compact_program_words} (max ${BASELINE_COMPACT_PROGRAM_WORDS})"

fail=0
if (( hybrid_call_gas > max_hybrid_call_gas )); then
  echo "FAIL: hybrid call gas did not improve by >=8% vs baseline" >&2
  fail=1
fi
if (( hybrid_page_bytes > max_hybrid_page_bytes )); then
  echo "FAIL: hybrid page bytes regressed by >5% vs baseline" >&2
  fail=1
fi
if (( compact_call_gas > max_compact_call_gas )); then
  echo "FAIL: compact call gas regressed by >2% vs baseline" >&2
  fail=1
fi
if (( compact_program_words > BASELINE_COMPACT_PROGRAM_WORDS )); then
  echo "FAIL: compact program words did not decrease vs baseline" >&2
  fail=1
fi
if [[ -n "${unrolled_sharded_call_gas}" ]] && (( unrolled_sharded_call_gas > MAX_UNROLLED_SHARDED_CALL_GAS )); then
  echo "FAIL: unrolled-sharded call gas exceeds target (${MAX_UNROLLED_SHARDED_CALL_GAS})" >&2
  fail=1
fi
if [[ "${REQUIRE_UNROLLED_DEPLOYABLE}" == "1" ]]; then
  if [[ "${unrolled_runtime_within_limit}" != "true" ]]; then
    echo "FAIL: unrolled runtime exceeds EIP-170 contract size limit (${EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES} bytes)" >&2
    fail=1
  fi
  if [[ "${unrolled_initcode_within_limit}" != "true" ]]; then
    echo "FAIL: unrolled initcode exceeds EIP-3860 initcode size limit (${EVM_INITCODE_SIZE_LIMIT_BYTES} bytes)" >&2
    fail=1
  fi
fi
if [[ "${REQUIRE_UNROLLED_SHARDED_DEPLOYABLE}" == "1" ]]; then
  if [[ "${unrolled_sharded_dispatcher_runtime_within_limit}" != "true" ]]; then
    echo "FAIL: unrolled-sharded dispatcher runtime exceeds EIP-170 contract size limit (${EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES} bytes)" >&2
    fail=1
  fi
  if [[ "${unrolled_sharded_dispatcher_initcode_within_limit}" != "true" ]]; then
    echo "FAIL: unrolled-sharded dispatcher initcode exceeds EIP-3860 initcode size limit (${EVM_INITCODE_SIZE_LIMIT_BYTES} bytes)" >&2
    fail=1
  fi
  if [[ "${unrolled_sharded_all_shard_runtime_within_limit}" != "true" ]]; then
    echo "FAIL: at least one unrolled-sharded shard runtime exceeds EIP-170 contract size limit (${EVM_RUNTIME_CODE_SIZE_LIMIT_BYTES} bytes)" >&2
    fail=1
  fi
  if [[ "${unrolled_sharded_all_shard_initcode_within_limit}" != "true" ]]; then
    echo "FAIL: at least one unrolled-sharded shard initcode exceeds EIP-3860 initcode size limit (${EVM_INITCODE_SIZE_LIMIT_BYTES} bytes)" >&2
    fail=1
  fi
fi

mkdir -p "${OUT_ROOT}"
cp "${SUMMARY_PATH}" "${OUT_ROOT}/latest.json"
echo "Summary JSON: ${SUMMARY_PATH}"
echo "Latest JSON:  ${OUT_ROOT}/latest.json"

if (( fail != 0 )); then
  exit 1
fi

echo "All regression checks passed."
