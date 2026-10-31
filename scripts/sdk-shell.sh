#!/usr/bin/env bash
set -euo pipefail

SDK_ROOT="${FOUNDATION_SDK_ROOT:-$HOME/.foundation/sdk/current}"
if [ ! -f "$SDK_ROOT/flake.nix" ]; then
  echo "Foundation SDK not found at $SDK_ROOT (set FOUNDATION_SDK_ROOT)" >&2
  exit 1
fi
if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

export FOUNDATION_SDK_ROOT="$SDK_ROOT"
exec nix develop "$SDK_ROOT" --command "$@"
