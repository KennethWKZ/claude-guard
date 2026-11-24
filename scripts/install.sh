#!/bin/dash
# Not Rust: thin wrapper around cargo build and an atomic copy (rust-first-cli exception 3).
# Build claude-guard and install it as ~/.local/bin/claude-guard. Run from anywhere.
set -eu
cd "${0%/*}/.."
commit=$(git rev-parse --short HEAD)
git diff --quiet HEAD || commit="$commit-dirty"
CLAUDE_GUARD_COMMIT=$commit nice -n "$(test-workers --nice 2>/dev/null || echo 10)" \
  cargo build --release --locked -j "$(test-workers 2>/dev/null || echo 2)"
# A new file renamed over the old one, never a write into the binary running hooks right now.
mkdir -p ~/.local/bin
cp target/release/claude-guard ~/.local/bin/.claude-guard.new
chmod 755 ~/.local/bin/.claude-guard.new
mv ~/.local/bin/.claude-guard.new ~/.local/bin/claude-guard
~/.local/bin/claude-guard --version
