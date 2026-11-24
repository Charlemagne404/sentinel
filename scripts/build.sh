#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL_TOOLCHAIN_ROOT="${SENTINEL_TOOLCHAIN_ROOT:-$HOME/.local/share/sentinel-rust}"
if [[ -d "$SENTINEL_TOOLCHAIN_ROOT/cargo/bin" ]]; then
  export PATH="$SENTINEL_TOOLCHAIN_ROOT/cargo/bin:$PATH"
  export CARGO_HOME="${CARGO_HOME:-$SENTINEL_TOOLCHAIN_ROOT/cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$SENTINEL_TOOLCHAIN_ROOT/rustup}"
elif [[ -d "$HOME/.cargo/bin" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
command -v npm >/dev/null || { echo "npm is required" >&2; exit 1; }

cd "$ROOT_DIR/frontend"
npm ci --no-audit --no-fund --maxsockets=1
nice -n 10 npm run build

cd "$ROOT_DIR"
nice -n 10 cargo build --locked --release -j1
echo "Build complete: $ROOT_DIR/target/release/sentinel and $ROOT_DIR/frontend/dist"
