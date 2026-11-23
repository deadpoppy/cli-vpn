#!/usr/bin/env bash
# Uninstaller for cli-vpn (macOS & Linux)

set -euo pipefail

INSTALL_DIR="${CLI_VPN_HOME:-$HOME/.cli-vpn}"
KEEP_CONFIG=0

for arg in "$@"; do
    case "$arg" in
        --keep-config) KEEP_CONFIG=1 ;;
    esac
done

PY_BIN="python3"
if [ -x "$INSTALL_DIR/.venv/bin/python3" ]; then
    PY_BIN="$INSTALL_DIR/.venv/bin/python3"
fi

if [ -f "$INSTALL_DIR/vpn.py" ] && command -v "$PY_BIN" >/dev/null 2>&1; then
    CLI_VPN_HOME="$INSTALL_DIR" "$PY_BIN" "$INSTALL_DIR/vpn.py" off 2>/dev/null || true
fi

for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
    [ -f "$rc" ] || continue
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$rc" <<'PY'
import re
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="replace") as f:
    text = f.read()

pattern = re.compile(r"\n?# >>> cli-vpn >>>.*?# <<< cli-vpn <<<\n?", re.DOTALL)
new_text = pattern.sub("\n", text)
if new_text != text:
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
PY
    fi
done

if [ "$KEEP_CONFIG" -eq 1 ] && [ -f "$INSTALL_DIR/config.json" ]; then
    tmp_cfg="$(mktemp)"
    cp "$INSTALL_DIR/config.json" "$tmp_cfg"
    rm -rf "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    mv "$tmp_cfg" "$INSTALL_DIR/config.json"
    chmod 600 "$INSTALL_DIR/config.json"
    echo "[cli-vpn] 已卸载程序文件，保留配置于 $INSTALL_DIR/config.json"
else
    rm -rf "$INSTALL_DIR"
    echo "[cli-vpn] 已完全卸载 ($INSTALL_DIR)"
fi
