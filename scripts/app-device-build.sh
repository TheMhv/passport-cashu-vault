#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
app="$root/passport-app"
themes="$app/target/foundation/themes/rust"
if [ ! -f "$themes/app_theme.rs" ]; then
  echo "No generated theme in $themes: run 'foundation sim' in passport-app once first." >&2
  exit 1
fi

exec "$root/scripts/sdk-shell.sh" bash -c '
  cd "$1" && shift
  export CC_armv7a_unknown_xous_elf="arm-none-eabi-gcc"
  export AR_armv7a_unknown_xous_elf="arm-none-eabi-ar"
  FOUNDATION_THEMES_RUST_DIR="$PWD/target/foundation/themes/rust" \
  RUSTFLAGS="--cfg keyos -C relocation-model=pic -C link-arg=-pie -Zunstable-options" \
    cargo build --release --target armv7a-unknown-xous-elf --target-dir target/device "$@"
' app-device-build "$app" "$@"
