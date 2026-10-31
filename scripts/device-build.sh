#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

exec "$REPO_ROOT/scripts/sdk-shell.sh" bash -c '
  set -euo pipefail
  export CC_armv7a_unknown_xous_elf="arm-none-eabi-gcc"
  export AR_armv7a_unknown_xous_elf="arm-none-eabi-ar"
  export RUSTFLAGS="--cfg keyos -C relocation-model=pic -Zunstable-options"
  echo "toolchain: $(rustc --version)"
  cargo build --target armv7a-unknown-xous-elf --target-dir target/device --lib "$@"
' device-build "$@"
