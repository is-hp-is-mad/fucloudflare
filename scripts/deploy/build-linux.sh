#!/usr/bin/env bash
# Build a static Linux binary of fucf inside WSL (musl target).
# Usage (from Windows): wsl -e bash /mnt/d/fucloudflare/scripts/deploy/build-linux.sh
set -euo pipefail
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$HOME/fucf-build"
TARGET=x86_64-unknown-linux-musl

if ! [ -x "$HOME/.cargo/bin/cargo" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
. "$HOME/.cargo/env"
rustup target add "$TARGET" >/dev/null

# build on the Linux filesystem: /mnt/* is far too slow for cargo
mkdir -p "$BUILD"
rsync -a --delete --exclude target --exclude data --exclude .git "$SRC"/ "$BUILD"/
cd "$BUILD"
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --target "$TARGET"
mkdir -p "$SRC/dist"
cp "target/$TARGET/release/fucf" "$SRC/dist/fucf-linux-x86_64"
ls -la "$SRC/dist/fucf-linux-x86_64"
file "$SRC/dist/fucf-linux-x86_64" || true
