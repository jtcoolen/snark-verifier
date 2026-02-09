#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd anvil
require_cmd cast

DEFAULT_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
HOST="127.0.0.1"
# Optional external RPC override.
# If unset, the script will auto-use http://127.0.0.1:8545 only when reachable.
USER_RPC_URL_OVERRIDE="${BENCH_RPC_URL:-}"
DEFAULT_EXTERNAL_RPC_URL="http://127.0.0.1:8545"
DEPLOYER_PK_OVERRIDE="${BENCH_PRIVATE_KEY:-$DEFAULT_PK}"
DEPLOYER_FROM_OVERRIDE="${BENCH_FROM:-}"
PROBE_BLS_PRECOMPILES="${BENCH_PROBE_BLS:-1}"
BENCH_PREFLIGHT_MODE="${BENCH_PREFLIGHT:-auto}"
BENCH_PROTOCOL_PROFILE_PATH="${BENCH_PROTOCOL_PROFILE_PATH:-$ROOT_DIR/examples/midnight_protocol_profile.json}"
BENCH_PROOF_METADATA_PATH="${BENCH_PROOF_METADATA_PATH:-$ROOT_DIR/examples/midnight_proof_metadata.json}"

GEN_LOG=""
ANVIL_LOG=""
ANVIL_PID=""
DOCKER_CONTAINER_NAME=""

PROOF_SIZE=""
DEPLOYMENT_CODE_LEN=""
DEPLOY_GAS=""
VERIFY_GAS=""
VERIFY_STATUS=""
VERIFY_ERROR=""
BLS_PRECOMPILES_STATUS=""
CONTRACT_ADDR=""
TRACE_OUT=""
RPC_URL=""
CLIENT_LABEL=""
BLS_PROBE_DETAIL=""
G2_ORDERING="default_c0c1"
TRACE_FILE=""
PREFLIGHT_STATUS="not_run"
PREFLIGHT_ERROR=""
PREFLIGHT_PROFILE=""

cleanup() {
  stop_docker_anvil
  stop_anvil
  [[ -n "$GEN_LOG" ]] && rm -f "$GEN_LOG"
  [[ -n "$ANVIL_LOG" ]] && rm -f "$ANVIL_LOG"
}
trap cleanup EXIT

stop_anvil() {
  if [[ -n "$ANVIL_PID" ]]; then
    kill "$ANVIL_PID" >/dev/null 2>&1 || true
    wait "$ANVIL_PID" 2>/dev/null || true
    ANVIL_PID=""
  fi
}

stop_docker_anvil() {
  if [[ -n "$DOCKER_CONTAINER_NAME" ]]; then
    docker rm -f "$DOCKER_CONTAINER_NAME" >/dev/null 2>&1 || true
    DOCKER_CONTAINER_NAME=""
  fi
}

find_free_port() {
  local port
  for port in $(seq 8545 8565); do
    if ! cast rpc --rpc-url "http://$HOST:$port" web3_clientVersion >/dev/null 2>&1; then
      echo "$port"
      return 0
    fi
  done
  return 1
}

rpc_is_reachable() {
  local rpc_url="$1"
  cast rpc --rpc-url "$rpc_url" web3_clientVersion >/dev/null 2>&1
}

extract_last_hex() {
  local text="$1"
  echo "$text" | rg -o "0x[0-9a-fA-F]*" | tail -1
}

hex_to_dec() {
  local hex="${1#0x}"
  if [[ -z "$hex" ]]; then
    echo ""
    return 1
  fi
  echo "$((16#$hex))"
}

run_midnight_preflight() {
  case "$BENCH_PREFLIGHT_MODE" in
    off|0|false|FALSE|False)
      PREFLIGHT_STATUS="disabled"
      return 0
      ;;
    on|1|true|TRUE|True|auto)
      ;;
    *)
      echo "error: invalid BENCH_PREFLIGHT value '$BENCH_PREFLIGHT_MODE' (expected off|on|auto)" >&2
      exit 1
      ;;
  esac

  local profile_path="$BENCH_PROTOCOL_PROFILE_PATH"
  local proof_path="$BENCH_PROOF_METADATA_PATH"

  if [[ "$BENCH_PREFLIGHT_MODE" == "auto" ]]; then
    if [[ ! -f "$profile_path" || ! -f "$proof_path" ]]; then
      PREFLIGHT_STATUS="skipped"
      PREFLIGHT_ERROR="profile/metadata files not found"
      return 0
    fi
  fi

  if [[ ! -f "$profile_path" ]]; then
    echo "error: missing BENCH_PROTOCOL_PROFILE_PATH file: $profile_path" >&2
    exit 1
  fi
  if [[ ! -f "$proof_path" ]]; then
    echo "error: missing BENCH_PROOF_METADATA_PATH file: $proof_path" >&2
    exit 1
  fi

  PREFLIGHT_PROFILE="$profile_path"
  echo "[0/5] Midnight preflight check ($BENCH_PREFLIGHT_MODE)"

  local preflight_out=""
  if preflight_out="$(cargo run --package snark-verifier-sdk --example midnight_preflight -- "$profile_path" "$proof_path" 2>&1)"; then
    PREFLIGHT_STATUS="ok"
    return 0
  fi

  PREFLIGHT_STATUS="failed"
  PREFLIGHT_ERROR="$(echo "$preflight_out" | tail -n 2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
  echo "$preflight_out" >&2
  echo "error: preflight failed; refusing to run benchmark" >&2
  exit 1
}

probe_bls_precompiles() {
  local rpc_url="$1"

  local g1add_input="0x$(printf '00%.0s' {1..256})"
  local g1msm_input="0x$(printf '00%.0s' {1..160})"
  local pairing_input="0x$(printf '00%.0s' {1..384})"

  local g1add_raw g1msm_raw pairing_raw
  g1add_raw="$(cast call --rpc-url "$rpc_url" 0x000000000000000000000000000000000000000b --data "$g1add_input" 2>&1 || true)"
  g1msm_raw="$(cast call --rpc-url "$rpc_url" 0x000000000000000000000000000000000000000c --data "$g1msm_input" 2>&1 || true)"
  pairing_raw="$(cast call --rpc-url "$rpc_url" 0x000000000000000000000000000000000000000f --data "$pairing_input" 2>&1 || true)"

  local g1add_out g1msm_out pairing_out
  g1add_out="$(extract_last_hex "$g1add_raw")"
  g1msm_out="$(extract_last_hex "$g1msm_raw")"
  pairing_out="$(extract_last_hex "$pairing_raw")"

  BLS_PROBE_DETAIL="0x0b=${g1add_out:-none},0x0c=${g1msm_out:-none},0x0f=${pairing_out:-none}"

  # Supported behavior: non-empty return payloads with expected sizes.
  # G1 add / MSM return 128-byte point -> 2 + 256 hex chars.
  # Pairing returns 32-byte bool -> 2 + 64 hex chars.
  if [[ "${#g1add_out}" -eq 258 && "${#g1msm_out}" -eq 258 && "${#pairing_out}" -eq 66 ]]; then
    BLS_PRECOMPILES_STATUS="active"
    return 0
  fi

  BLS_PRECOMPILES_STATUS="inactive_or_unsupported"
  return 1
}

generate_artifacts() {
  local legacy_g2_ordering="${1:-0}"
  local step_label="[1/5] Generating proof + verifier artifacts"
  local -a cargo_cmd=(
    cargo run --package snark-verifier-sdk --example standard_plonk
    --features loader_halo2 --features loader_evm --release
  )

  if [[ "$legacy_g2_ordering" == "1" ]]; then
    G2_ORDERING="legacy_c1c0"
    step_label="$step_label (legacy G2 order: c1,c0)"
  else
    G2_ORDERING="default_c0c1"
    step_label="$step_label (default G2 order: c0,c1)"
  fi

  echo "$step_label"
  [[ -n "$GEN_LOG" ]] && rm -f "$GEN_LOG"
  GEN_LOG="$(mktemp)"
  if [[ "$legacy_g2_ordering" == "1" ]]; then
    SNARK_VERIFIER_EVM_G2_LEGACY_C1C0=1 "${cargo_cmd[@]}" | tee "$GEN_LOG"
  else
    "${cargo_cmd[@]}" | tee "$GEN_LOG"
  fi

  PROOF_SIZE="$(awk '/^proof size:/ {print $3}' "$GEN_LOG" | tail -1)"
  DEPLOYMENT_CODE_LEN="$(awk '/^deployment code len:/ {print $4}' "$GEN_LOG" | tail -1)"

  if [[ -z "$PROOF_SIZE" || -z "$DEPLOYMENT_CODE_LEN" ]]; then
    echo "error: could not parse proof/deployment size from example output" >&2
    exit 1
  fi

  local bytecode_file="$ROOT_DIR/examples/standard_plonk.bytecode"
  local calldata_file="$ROOT_DIR/examples/standard_plonk.calldata"
  if [[ ! -s "$bytecode_file" || ! -s "$calldata_file" ]]; then
    echo "error: expected artifact files were not produced" >&2
    exit 1
  fi
}

maybe_retry_legacy_g2_ordering() {
  if [[ "${BENCH_TRY_G2_ORDERING:-1}" != "1" ]]; then
    return 1
  fi
  if [[ "$VERIFY_STATUS" == "success" || "$BLS_PRECOMPILES_STATUS" != "active" ]]; then
    return 1
  fi
  if [[ "$G2_ORDERING" == "legacy_c1c0" ]]; then
    return 1
  fi

  echo "[5/5] Retrying with legacy G2 ordering (c1,c0)"
  generate_artifacts 1
  run_deploy_and_trace
  return 0
}

start_anvil() {
  local anvil_bin="$1"
  local rpc_port="$2"

  stop_anvil
  [[ -n "$ANVIL_LOG" ]] && rm -f "$ANVIL_LOG"

  RPC_URL="http://$HOST:$rpc_port"
  ANVIL_LOG="$(mktemp)"
  "$anvil_bin" \
    --host "$HOST" \
    --port "$rpc_port" \
    --hardfork prague \
    --disable-block-gas-limit >"$ANVIL_LOG" 2>&1 &
  ANVIL_PID="$!"

  local ready=0
  for _ in $(seq 1 40); do
    if cast rpc --rpc-url "$RPC_URL" web3_clientVersion >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" -ne 1 ]]; then
    echo "error: failed to start node at $RPC_URL using $anvil_bin" >&2
    cat "$ANVIL_LOG" >&2
    exit 1
  fi
}

run_deploy_and_trace() {
  local bytecode_file="$ROOT_DIR/examples/standard_plonk.bytecode"
  local calldata_file="$ROOT_DIR/examples/standard_plonk.calldata"

  if [[ "$PROBE_BLS_PRECOMPILES" == "1" ]]; then
    echo "[3/5] Probing BLS precompiles on $CLIENT_LABEL"
    if ! probe_bls_precompiles "$RPC_URL"; then
      VERIFY_STATUS="reverted"
      VERIFY_GAS="unknown"
      VERIFY_ERROR="BLS precompile probe failed ($BLS_PROBE_DETAIL)"
      CONTRACT_ADDR=""
      DEPLOY_GAS=""
      TRACE_OUT=""
      echo "note: skipping deploy/trace because EIP-2537 precompiles are inactive on $CLIENT_LABEL" >&2
      return
    fi
  else
    BLS_PRECOMPILES_STATUS="skipped"
    BLS_PROBE_DETAIL="skipped (set BENCH_PROBE_BLS=1 to enable)"
    echo "[3/5] Skipping BLS precompile probe on $CLIENT_LABEL (BENCH_PROBE_BLS=0)"
  fi

  echo "[3/5] Deploying verifier contract on $CLIENT_LABEL"
  local bytecode
  bytecode="$(cat "$bytecode_file")"
  local deploy_out
  if [[ -n "$DEPLOYER_PK_OVERRIDE" ]]; then
    deploy_out="$(cast send --rpc-url "$RPC_URL" --private-key "$DEPLOYER_PK_OVERRIDE" --create "$bytecode" 2>&1)" || {
      echo "$deploy_out" >&2
      exit 1
    }
  elif [[ -n "$DEPLOYER_FROM_OVERRIDE" ]]; then
    deploy_out="$(cast send --rpc-url "$RPC_URL" --unlocked --from "$DEPLOYER_FROM_OVERRIDE" --create "$bytecode" 2>&1)" || {
      echo "$deploy_out" >&2
      exit 1
    }
  elif ! deploy_out="$(cast send --rpc-url "$RPC_URL" --private-key "$DEFAULT_PK" --create "$bytecode" 2>&1)"; then
    local from_account
    from_account="$(
      cast rpc --rpc-url "$RPC_URL" eth_accounts \
        | rg -o "0x[a-fA-F0-9]{40}" \
        | head -1 \
        || true
    )"
    if [[ -n "$from_account" ]]; then
      deploy_out="$(cast send --rpc-url "$RPC_URL" --unlocked --from "$from_account" --create "$bytecode" 2>&1)" || {
        echo "$deploy_out" >&2
        exit 1
      }
    else
      echo "$deploy_out" >&2
      exit 1
    fi
  fi

  CONTRACT_ADDR="$(echo "$deploy_out" | awk '/contractAddress/ {print $2}' | tail -1)"
  DEPLOY_GAS="$(echo "$deploy_out" | awk '/gasUsed/ {print $2}' | tail -1)"
  if [[ -z "$CONTRACT_ADDR" ]]; then
    echo "error: failed to parse deployed contract address" >&2
    echo "$deploy_out" >&2
    exit 1
  fi

  echo "[4/5] Running verifier call on $CLIENT_LABEL"
  local calldata
  calldata="0x$(cat "$calldata_file")"
  local call_out
  if call_out="$(cast call --rpc-url "$RPC_URL" "$CONTRACT_ADDR" --data "$calldata" 2>&1)"; then
    VERIFY_STATUS="success"
    VERIFY_ERROR=""
  else
    VERIFY_STATUS="reverted"
    VERIFY_ERROR="$(
      echo "$call_out" \
        | rg -m1 -o "execution reverted(:.*)?|Error: .*|VM error:.*" \
        || true
    )"
    if [[ -z "$VERIFY_ERROR" ]]; then
      VERIFY_ERROR="empty revert data / no reason string"
    fi
  fi

  # Prefer debug_traceCall for authoritative gas usage and internal call trace.
  local trace_out
  local trace_req
  trace_req="{\"to\":\"$CONTRACT_ADDR\",\"data\":\"$calldata\",\"gas\":\"0x3b9aca00\"}"
  trace_out="$(cast rpc --rpc-url "$RPC_URL" debug_traceCall "$trace_req" latest '{"tracer":"callTracer"}' 2>&1 || true)"
  TRACE_OUT="$trace_out"
  TRACE_FILE="$ROOT_DIR/examples/standard_plonk.trace.${G2_ORDERING}.json"
  printf "%s\n" "$TRACE_OUT" >"$TRACE_FILE"
  echo "wrote ${TRACE_FILE#$ROOT_DIR/}"

  local gas_hex
  gas_hex="$(
    echo "$TRACE_OUT" \
      | rg -o '"gasUsed":"0x[0-9a-fA-F]+"' \
      | head -n1 \
      | rg -o "0x[0-9a-fA-F]+" \
      || true
  )"
  if [[ -n "$gas_hex" ]]; then
    VERIFY_GAS="$(hex_to_dec "$gas_hex" || true)"
  else
    VERIFY_GAS="unknown"
  fi
}

install_or_update_nightly_anvil() {
  require_cmd foundryup
  local foundry_dir="$ROOT_DIR/.foundry-bench"
  local nightly_anvil="$foundry_dir/bin/anvil"
  local force_update="${BENCH_UPDATE_NIGHTLY:-0}"

  if [[ -x "$nightly_anvil" && "$force_update" != "1" ]]; then
    echo "$nightly_anvil"
    return 0
  fi

  echo "[5/5] Installing/updating isolated nightly Anvil for BLS precompiles" >&2
  mkdir -p "$foundry_dir/bin" "$foundry_dir/versions" "$foundry_dir/share/man/man1"
  if ! FOUNDRY_DIR="$foundry_dir" foundryup --install nightly >/dev/null; then
    echo "error: failed to install nightly anvil with foundryup" >&2
    echo "note: ensure no 'anvil' process is running and retry the same command" >&2
    return 1
  fi

  if [[ ! -x "$nightly_anvil" ]]; then
    echo "error: nightly anvil was not installed at $nightly_anvil" >&2
    return 1
  fi

  echo "$nightly_anvil"
}

docker_daemon_available() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

start_docker_nightly_anvil() {
  local rpc_port="$1"
  local image="ghcr.io/foundry-rs/foundry:nightly"

  require_cmd docker
  stop_docker_anvil
  stop_anvil

  DOCKER_CONTAINER_NAME="snark-bench-anvil-$rpc_port-$$"

  echo "[5/5] Starting isolated Docker nightly Anvil for BLS precompiles"
  docker run -d --rm \
    --name "$DOCKER_CONTAINER_NAME" \
    -p "$rpc_port:8545" \
    "$image" \
    anvil \
      --host 0.0.0.0 \
      --port 8545 \
      --hardfork prague \
      --disable-block-gas-limit >/dev/null

  RPC_URL="http://$HOST:$rpc_port"
  local ready=0
  for _ in $(seq 1 40); do
    if cast rpc --rpc-url "$RPC_URL" web3_clientVersion >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    echo "error: docker nightly anvil failed to start" >&2
    docker logs "$DOCKER_CONTAINER_NAME" >&2 || true
    exit 1
  fi
}

start_docker_geth_prague() {
  local rpc_port="$1"
  local image="${GETH_IMAGE:-ethereum/client-go:latest}"

  require_cmd docker
  stop_docker_anvil
  stop_anvil

  RPC_URL="http://$HOST:$rpc_port"
  local ready=0
  local args_common=(
    --dev
    --dev.period 1
    --http
    --http.addr 0.0.0.0
    --http.port 8545
    --http.vhosts "*"
    --http.corsdomain "*"
    --http.api eth,net,web3,debug,txpool,personal
    --allow-insecure-unlock
    --nodiscover
    --maxpeers 0
  )

  for extra in "--override.prague=0" ""; do
    DOCKER_CONTAINER_NAME="snark-bench-geth-$rpc_port-$$-$RANDOM"
    echo "[5/5] Starting isolated Docker Geth (Prague/dev) for BLS precompiles"
    if [[ -n "$extra" ]]; then
      docker run -d --rm \
        --name "$DOCKER_CONTAINER_NAME" \
        -p "$rpc_port:8545" \
        "$image" \
        "${args_common[@]}" \
        "$extra" >/dev/null || true
    else
      docker run -d --rm \
        --name "$DOCKER_CONTAINER_NAME" \
        -p "$rpc_port:8545" \
        "$image" \
        "${args_common[@]}" >/dev/null || true
    fi

    ready=0
    for _ in $(seq 1 60); do
      if cast rpc --rpc-url "$RPC_URL" web3_clientVersion >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 1
    done
    if [[ "$ready" -eq 1 ]]; then
      return
    fi

    docker logs "$DOCKER_CONTAINER_NAME" >&2 || true
    stop_docker_anvil
  done

  echo "error: docker geth prague fallback failed to start" >&2
  exit 1
}

print_summary() {
  echo
  echo "=== Standard Plonk (BLS) Figures ==="
  echo "proof_size_bytes: $PROOF_SIZE"
  echo "preflight: ${PREFLIGHT_STATUS:-unknown}"
  if [[ -n "$PREFLIGHT_PROFILE" ]]; then
    echo "preflight_profile: ${PREFLIGHT_PROFILE#$ROOT_DIR/}"
  fi
  if [[ "$PREFLIGHT_STATUS" == "failed" && -n "$PREFLIGHT_ERROR" ]]; then
    echo "preflight_error: $PREFLIGHT_ERROR"
  fi
  echo "deployment_code_bytes: $DEPLOYMENT_CODE_LEN"
  echo "deployment_gas_used: ${DEPLOY_GAS:-unknown}"
  echo "verify_exec_gas_used: ${VERIFY_GAS:-unknown}"
  echo "verify_result: ${VERIFY_STATUS:-unknown}"
  if [[ "$VERIFY_STATUS" != "success" ]]; then
    echo "verify_error: ${VERIFY_ERROR:-unknown}"
  fi
  echo "bls_precompiles: ${BLS_PRECOMPILES_STATUS:-unknown}"
  echo "g2_ordering: ${G2_ORDERING:-unknown}"
  if [[ -n "$BLS_PROBE_DETAIL" ]]; then
    echo "bls_probe: $BLS_PROBE_DETAIL"
  fi
  echo "client: $CLIENT_LABEL"
  echo "rpc_url: $RPC_URL"
  echo "contract_address: ${CONTRACT_ADDR:-unknown}"
  if [[ -n "$TRACE_FILE" ]]; then
    echo "trace_file: ${TRACE_FILE#$ROOT_DIR/}"
  fi

  if [[ "$VERIFY_STATUS" != "success" ]]; then
    echo "note: verifier call reverted on this local client; gas shown is execution gas from trace."
  fi
}

main() {
  run_midnight_preflight
  generate_artifacts

  if [[ -n "$USER_RPC_URL_OVERRIDE" ]]; then
    if ! rpc_is_reachable "$USER_RPC_URL_OVERRIDE"; then
      echo "error: BENCH_RPC_URL is set but unreachable: $USER_RPC_URL_OVERRIDE" >&2
      echo "note: start the node or provide a reachable BENCH_RPC_URL" >&2
      exit 1
    fi
    RPC_URL="$USER_RPC_URL_OVERRIDE"
    CLIENT_LABEL="rpc-external"
    echo "[2/5] Using external RPC at $RPC_URL"
    run_deploy_and_trace
    maybe_retry_legacy_g2_ordering || true
    print_summary
    return
  fi

  if rpc_is_reachable "$DEFAULT_EXTERNAL_RPC_URL"; then
    RPC_URL="$DEFAULT_EXTERNAL_RPC_URL"
    CLIENT_LABEL="rpc-external"
    echo "[2/5] Using external RPC at $RPC_URL"
    run_deploy_and_trace
    maybe_retry_legacy_g2_ordering || true
    print_summary
    return
  fi

  local port
  port="$(find_free_port)"
  if [[ -z "$port" ]]; then
    echo "error: no free local port found in range 8545-8565" >&2
    exit 1
  fi

  local system_anvil
  system_anvil="$(command -v anvil)"
  CLIENT_LABEL="anvil-system"
  echo "[2/5] Starting $CLIENT_LABEL on http://$HOST:$port"
  start_anvil "$system_anvil" "$port"
  run_deploy_and_trace
  maybe_retry_legacy_g2_ordering || true

  if [[ "$VERIFY_STATUS" == "success" ]]; then
    print_summary
    return
  fi

  if [[ "$BLS_PRECOMPILES_STATUS" == "active" ]]; then
    print_summary
    return
  fi

  if docker_daemon_available; then
    CLIENT_LABEL="geth-docker-prague"
    echo "[2/5] Retrying on $CLIENT_LABEL at http://$HOST:$port"
    start_docker_geth_prague "$port"
    run_deploy_and_trace
    maybe_retry_legacy_g2_ordering || true
    if [[ "$VERIFY_STATUS" == "success" || "$BLS_PRECOMPILES_STATUS" == "active" ]]; then
      print_summary
      return
    fi

    stop_docker_anvil
    CLIENT_LABEL="anvil-docker-nightly"
    echo "[2/5] Retrying on $CLIENT_LABEL at http://$HOST:$port"
    start_docker_nightly_anvil "$port"
    run_deploy_and_trace
    maybe_retry_legacy_g2_ordering || true
    if [[ "$VERIFY_STATUS" == "success" || "$BLS_PRECOMPILES_STATUS" == "active" ]]; then
      print_summary
      return
    fi
  fi

  local nightly_anvil
  stop_docker_anvil
  stop_anvil
  nightly_anvil="$(install_or_update_nightly_anvil)" || {
    print_summary
    exit 1
  }
  CLIENT_LABEL="anvil-nightly"
  echo "[2/5] Retrying on $CLIENT_LABEL at http://$HOST:$port"
  start_anvil "$nightly_anvil" "$port"
  run_deploy_and_trace
  maybe_retry_legacy_g2_ordering || true
  print_summary
}

main "$@"
