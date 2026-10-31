#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/target/sim-e2e"
export CASHU_VAULT_SIM_DIR="${CASHU_VAULT_SIM_DIR:-$HOME/.cashu-vault-sim}"
# shellcheck source=simulator.sh
source "$root/scripts/simulator.sh"
refuse_running_simulator

rm -rf "$out"
mkdir -p "$out" "$CASHU_VAULT_SIM_DIR"
touch "$CASHU_VAULT_SIM_DIR/reset"
cargo build --quiet --manifest-path "$root/Cargo.toml" -p cashu-vault-sim-e2e
driver="$root/target/debug/sim-e2e"

finish() {
  local status=$?
  stop_simulator
  exit "$status"
}
trap finish EXIT

start_simulator run
SHOTS_DIR="$out" "$driver"
echo "Cashu Vault simulator end-to-end check passed."
