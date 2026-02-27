#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT_DIR/bin"
INSTALL_DIR="${1:-/usr/local/bin}"

# Why(中文): 统一在脚本内构建并安装，避免手工多步执行时出现版本不一致。
# Why(English): Build and install in one script to prevent version mismatch from manual multi-step commands.
build_and_install() {
  mkdir -p "$BIN_DIR"
  go build -o "$BIN_DIR/mdlock-enc" ./cmd/mdlock-enc
  go build -o "$BIN_DIR/mdlock-dec" ./cmd/mdlock-dec

  if [ ! -d "$INSTALL_DIR" ]; then
    sudo mkdir -p "$INSTALL_DIR"
  fi

  sudo install -m 0755 "$BIN_DIR/mdlock-enc" "$INSTALL_DIR/mdlock-enc"
  sudo install -m 0755 "$BIN_DIR/mdlock-dec" "$INSTALL_DIR/mdlock-dec"
}

cd "$ROOT_DIR"
build_and_install
echo "Installed: $INSTALL_DIR/mdlock-enc $INSTALL_DIR/mdlock-dec"
