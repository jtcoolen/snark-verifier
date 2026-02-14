#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy_midnight_ivc.sh [hybrid|compact|unrolled-sharded] [call|no-call]

Environment:
  RPC_URL      JSON-RPC endpoint
  PRIVATE_KEY  Deployer EOA private key (0x...)

Examples:
  RPC_URL=http://127.0.0.1:8545 PRIVATE_KEY=0x... scripts/deploy_midnight_ivc.sh hybrid call
  RPC_URL=http://127.0.0.1:8545 PRIVATE_KEY=0x... scripts/deploy_midnight_ivc.sh compact no-call
  RPC_URL=http://127.0.0.1:8545 PRIVATE_KEY=0x... scripts/deploy_midnight_ivc.sh unrolled-sharded call
EOF
}

MODE="${1:-hybrid}"
DO_CALL="${2:-call}"

if [[ "${MODE}" != "hybrid" && "${MODE}" != "compact" && "${MODE}" != "unrolled-sharded" ]]; then
  usage
  exit 1
fi
if [[ "${DO_CALL}" != "call" && "${DO_CALL}" != "no-call" ]]; then
  usage
  exit 1
fi

: "${RPC_URL:?RPC_URL is required}"
: "${PRIVATE_KEY:?PRIVATE_KEY is required}"

EXAMPLES_DIR="snark-verifier-sdk/examples"

case "${MODE}" in
  hybrid)
    RUNTIME_PATH="${EXAMPLES_DIR}/midnight_ivc_hybrid_runtime.bytecode"
    PAGES_PATH="${EXAMPLES_DIR}/midnight_ivc_hybrid_pages.bytecode"
    MANIFEST_PATH="${EXAMPLES_DIR}/midnight_ivc_hybrid_manifest.txt"
    ;;
  compact)
    RUNTIME_PATH="${EXAMPLES_DIR}/midnight_ivc_compact_runtime.bytecode"
    PAGES_PATH="${EXAMPLES_DIR}/midnight_ivc_compact_pages.bytecode"
    MANIFEST_PATH="${EXAMPLES_DIR}/midnight_ivc_compact_manifest.txt"
    ;;
  unrolled-sharded)
    RUNTIME_PATH="${EXAMPLES_DIR}/midnight_ivc_unrolled_sharded_dispatcher.bytecode"
    PAGES_PATH="${EXAMPLES_DIR}/midnight_ivc_unrolled_sharded_shards.bytecode"
    MANIFEST_PATH="${EXAMPLES_DIR}/midnight_ivc_unrolled_sharded_manifest.txt"
    ;;
esac
CALLDATA_PATH="${EXAMPLES_DIR}/midnight_ivc.calldata"

for f in "${RUNTIME_PATH}" "${PAGES_PATH}" "${MANIFEST_PATH}" "${CALLDATA_PATH}"; do
  if [[ ! -f "${f}" ]]; then
    echo "Missing required artifact: ${f}" >&2
    exit 1
  fi
done

program_words=""
opcode_version=""
if [[ "${MODE}" == "compact" || "${MODE}" == "hybrid" ]]; then
  program_words="$(awk -F': ' '$1=="program_words"{print $2; exit}' "${MANIFEST_PATH}")"
  if [[ -z "${program_words}" ]]; then
    echo "Could not parse program_words from ${MANIFEST_PATH}" >&2
    exit 1
  fi
  opcode_version="$(awk -F': ' '$1=="opcode_version"{print $2; exit}' "${MANIFEST_PATH}")"
  if [[ -z "${opcode_version}" ]]; then
    echo "Could not parse opcode_version from ${MANIFEST_PATH}" >&2
    exit 1
  fi
  if [[ "${opcode_version}" != "2" ]]; then
    echo "Unsupported opcode_version=${opcode_version} in ${MANIFEST_PATH} (expected 2)" >&2
    exit 1
  fi
fi

runtime_init="$(tr -d '[:space:]' < "${RUNTIME_PATH}")"
if [[ -z "${runtime_init}" ]]; then
  echo "Runtime bytecode file is empty: ${RUNTIME_PATH}" >&2
  exit 1
fi

if [[ "${MODE}" == "unrolled-sharded" ]]; then
  mapfile -t page_init_codes < <(awk -F' = ' '/^shard\[[0-9]+\] = 0x/ {print $2}' "${PAGES_PATH}")
else
  mapfile -t page_init_codes < <(awk -F' = ' '/^page\[[0-9]+\] = 0x/ {print $2}' "${PAGES_PATH}")
fi
if [[ "${#page_init_codes[@]}" -eq 0 ]]; then
  echo "No shard/page bytecodes found in ${PAGES_PATH}" >&2
  exit 1
fi

send_create() {
  local init_code="$1"
  local tx_json tx_hash receipt contract gas_used
  tx_json="$(cast send --json --rpc-url "${RPC_URL}" --private-key "${PRIVATE_KEY}" --gas-limit 30000000 --create "${init_code}")"
  tx_hash="$(jq -r '.transactionHash // .hash // empty' <<<"${tx_json}")"
  if [[ -z "${tx_hash}" ]]; then
    echo "Could not extract tx hash for create tx" >&2
    echo "${tx_json}" >&2
    exit 1
  fi
  receipt="$(cast receipt --json --rpc-url "${RPC_URL}" "${tx_hash}")"
  contract="$(jq -r '.contractAddress // .contract_address // empty' <<<"${receipt}")"
  if [[ -z "${contract}" || "${contract}" == "null" ]]; then
    echo "Create tx did not return contract address: ${tx_hash}" >&2
    echo "${receipt}" >&2
    exit 1
  fi
  gas_used="$(jq -r '.gasUsed // .gas_used // empty' <<<"${receipt}")"
  if [[ -z "${gas_used}" ]]; then
    echo "Could not extract deployment gas from receipt: ${tx_hash}" >&2
    echo "${receipt}" >&2
    exit 1
  fi
  echo "${contract}|${gas_used}"
}

send_call() {
  local to="$1"
  local data="$2"
  local tx_json tx_hash receipt status gas_used
  tx_json="$(cast send --json --rpc-url "${RPC_URL}" --private-key "${PRIVATE_KEY}" --gas-limit 30000000 --data "${data}" "${to}")"
  tx_hash="$(jq -r '.transactionHash // .hash // empty' <<<"${tx_json}")"
  if [[ -z "${tx_hash}" ]]; then
    echo "Could not extract tx hash for call tx" >&2
    echo "${tx_json}" >&2
    exit 1
  fi
  receipt="$(cast receipt --json --rpc-url "${RPC_URL}" "${tx_hash}")"
  status="$(jq -r '.status // empty' <<<"${receipt}")"
  gas_used="$(jq -r '.gasUsed // .gas_used // empty' <<<"${receipt}")"
  echo "${tx_hash}|${status}|${gas_used}"
}

echo "Deploying ${#page_init_codes[@]} ${MODE} pages..."
page_addresses=()
page_deploy_gas=0
for i in "${!page_init_codes[@]}"; do
  page_result="$(send_create "${page_init_codes[$i]}")"
  addr="${page_result%%|*}"
  gas_used="${page_result##*|}"
  page_addresses+=("${addr}")
  page_deploy_gas=$((page_deploy_gas + gas_used))
  echo "  page[${i}] => ${addr} (gas=${gas_used})"
done

addresses_csv="$(IFS=,; echo "${page_addresses[*]}")"
if [[ "${MODE}" == "unrolled-sharded" ]]; then
  constructor_args="$(cast abi-encode 'constructor(address[])' "[${addresses_csv}]")"
else
  constructor_args="$(cast abi-encode 'constructor(address[],uint256)' "[${addresses_csv}]" "${program_words}")"
fi
verifier_init="${runtime_init}${constructor_args#0x}"

if [[ "${MODE}" == "unrolled-sharded" ]]; then
  echo "Deploying verifier dispatcher (mode=${MODE}, shards=${#page_init_codes[@]})..."
else
  echo "Deploying verifier runtime (mode=${MODE}, program_words=${program_words})..."
fi
verifier_result="$(send_create "${verifier_init}")"
verifier_address="${verifier_result%%|*}"
verifier_deploy_gas="${verifier_result##*|}"
if [[ "${MODE}" == "unrolled-sharded" ]]; then
  echo "Dispatcher: ${verifier_address} (gas=${verifier_deploy_gas})"
else
  echo "Verifier: ${verifier_address} (gas=${verifier_deploy_gas})"
fi

if [[ "${DO_CALL}" == "call" ]]; then
  calldata_hex="$(tr -d '[:space:]' < "${CALLDATA_PATH}")"
  if [[ -z "${calldata_hex}" ]]; then
    echo "Calldata file is empty: ${CALLDATA_PATH}" >&2
    exit 1
  fi
  if [[ "${calldata_hex}" != 0x* ]]; then
    calldata_hex="0x${calldata_hex}"
  fi
  echo "Calling verifier fallback with ${CALLDATA_PATH}..."
  call_result="$(send_call "${verifier_address}" "${calldata_hex}")"
  call_tx_hash="${call_result%%|*}"
  status_and_gas="${call_result#*|}"
  call_status="${status_and_gas%%|*}"
  call_gas="${status_and_gas##*|}"
  echo "Call tx: ${call_tx_hash}"
  echo "Call status: ${call_status}"
  echo "Call gas used: ${call_gas}"
fi

echo
echo "Done."
echo "Mode: ${MODE}"
echo "Pages: ${#page_init_codes[@]}"
if [[ "${MODE}" != "unrolled-sharded" ]]; then
  echo "Opcode version: ${opcode_version}"
  echo "Program words: ${program_words}"
fi
echo "Page deployment gas total: ${page_deploy_gas}"
if [[ "${MODE}" == "unrolled-sharded" ]]; then
  echo "Dispatcher deployment gas: ${verifier_deploy_gas}"
else
  echo "Verifier deployment gas: ${verifier_deploy_gas}"
fi
echo "Total deployment gas: $((page_deploy_gas + verifier_deploy_gas))"
echo "Verifier address: ${verifier_address}"
