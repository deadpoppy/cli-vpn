#!/usr/bin/env bash
# One-click installer for cli-vpn (macOS & Linux)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/deadpoppy/cli-vpn/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/deadpoppy/cli-vpn/main/install.sh | bash -s -- --sub-url "https://..."

set -euo pipefail

REPO_SLUG="${CLI_VPN_REPO:-deadpoppy/cli-vpn}"
REPO_BRANCH="${CLI_VPN_BRANCH:-main}"
INSTALL_DIR="${CLI_VPN_HOME:-$HOME/.cli-vpn}"
SUB_URL="${CLI_VPN_SUB_URL:-}"
PROXY_PORT=""
API_PORT=""
UPGRADE_MIHOMO=0
NO_RC=0
NON_INTERACTIVE=0
FALLBACK_MIHOMO_TAG="v1.19.34"

info()  { printf '\033[1;34m[cli-vpn]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[cli-vpn]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[cli-vpn]\033[0m %s\n' "$*" >&2; }
err()   { printf '\033[1;31m[cli-vpn] 错误:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --sub-url)
            [ $# -ge 2 ] || err "--sub-url 需要提供参数"
            SUB_URL="$2"
            shift 2
            ;;
        --dir)
            [ $# -ge 2 ] || err "--dir 需要提供安装路径"
            INSTALL_DIR="$2"
            shift 2
            ;;
        --port)
            [ $# -ge 2 ] || err "--port 需要提供端口号"
            PROXY_PORT="$2"
            shift 2
            ;;
        --api-port)
            [ $# -ge 2 ] || err "--api-port 需要提供端口号"
            API_PORT="$2"
            shift 2
            ;;
        --upgrade-mihomo)
            UPGRADE_MIHOMO=1
            shift
            ;;
        --no-rc)
            NO_RC=1
            shift
            ;;
        -y|--non-interactive)
            NON_INTERACTIVE=1
            shift
            ;;
        -h|--help)
            cat <<'EOF'
cli-vpn 一键安装脚本 (支持 macOS & Linux)

可选参数:
  --sub-url <URL>     配置 Clash/Mihomo 订阅链接 (推荐)
  --dir <PATH>        指定安装目录 (默认: ~/.cli-vpn)
  --port <PORT>       本地 HTTP/SOCKS5 代理端口 (默认: 7890)
  --api-port <PORT>   mihomo API 控制端口 (默认: 9090)
  --upgrade-mihomo    强制下载/更新最新版 mihomo 二进制到 ~/.cli-vpn/bin/
  --no-rc             不自动修改 ~/.zshrc 或 ~/.bashrc
  -y                  非交互模式，不提示输入订阅链接
EOF
            exit 0
            ;;
        *)
            err "未知参数: $1 (使用 --help 查看帮助)"
            ;;
    esac
done

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 1
    fi
}

install_sys_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get update -qq && run_privileged apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y -q "$@"
    elif command -v yum >/dev/null 2>&1; then
        run_privileged yum install -y -q "$@"
    elif command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -Sy --noconfirm "$@"
    elif command -v apk >/dev/null 2>&1; then
        run_privileged apk add --no-cache "$@"
    else
        return 1
    fi
}

ensure_base_tools() {
    local missing=()
    for cmd in curl gzip python3; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        info "检测到缺少基础依赖 (${missing[*]})，正在尝试安装..."
        install_sys_packages "${missing[@]}" || err "无法自动安装 ${missing[*]}，请先手动安装后重试。"
    fi
}

download_url() {
    local url="$1"
    local dest="$2"
    local proxies=()

    if [ -n "${CLI_VPN_GH_PROXY:-}" ]; then
        proxies+=("${CLI_VPN_GH_PROXY%/}/")
    fi
    proxies+=("" "https://ghfast.top/" "https://gh-proxy.com/")

    for prefix in "${proxies[@]}"; do
        local full_url="${url}"
        if [ -n "$prefix" ]; then
            case "$url" in
                https://github.com/*|https://raw.githubusercontent.com/*)
                    full_url="${prefix}${url}"
                    ;;
                *)
                    continue
                    ;;
            esac
        fi
        if curl -fsSL --connect-timeout 8 --max-time 90 "$full_url" -o "$dest" 2>/dev/null; then
            if [ -s "$dest" ]; then
                return 0
            fi
        fi
    done
    return 1
}

detect_platform() {
    local uname_s uname_m
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    case "$uname_s" in
        Darwin) OS_NAME="darwin" ;;
        Linux)  OS_NAME="linux" ;;
        *)      err "暂不支持的操作系统: $uname_s (仅支持 macOS 与 Linux)" ;;
    esac

    case "$uname_m" in
        x86_64|amd64)   ARCH_NAME="amd64-compatible" ;;
        arm64|aarch64)  ARCH_NAME="arm64" ;;
        armv7l|armv7*)  ARCH_NAME="armv7" ;;
        armv6l|armv6*)  ARCH_NAME="armv6" ;;
        i386|i686)      ARCH_NAME="386" ;;
        *)              err "暂不支持的 CPU 架构: $uname_m" ;;
    esac
}

find_existing_mihomo() {
    local p
    for p in \
        "$INSTALL_DIR/bin/mihomo" \
        "$(command -v mihomo 2>/dev/null || true)" \
        "$HOME/.local/bin/mihomo" \
        "/opt/homebrew/bin/mihomo" \
        "/usr/local/bin/mihomo" \
        "/usr/bin/mihomo"
    do
        if [ -n "$p" ] && [ -x "$p" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

ensure_mihomo() {
    if [ "$UPGRADE_MIHOMO" -eq 0 ]; then
        local existing
        if existing="$(find_existing_mihomo)"; then
            ok "已检测到 mihomo: $existing"
            return 0
        fi
    fi

    detect_platform
    mkdir -p "$INSTALL_DIR/bin"
    local tmp_ver tmp_gz target_bin tag asset_url
    tmp_ver="$(mktemp)"
    tmp_gz="$(mktemp)"
    target_bin="$INSTALL_DIR/bin/mihomo"

    tag="$FALLBACK_MIHOMO_TAG"
    if download_url "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt" "$tmp_ver"; then
        local fetched_tag
        fetched_tag="$(tr -d ' \t\r\n' < "$tmp_ver")"
        if [[ "$fetched_tag" == v* ]]; then
            tag="$fetched_tag"
        fi
    fi
    rm -f "$tmp_ver"

    asset_url="https://github.com/MetaCubeX/mihomo/releases/download/${tag}/mihomo-${OS_NAME}-${ARCH_NAME}-${tag}.gz"
    info "正在下载 mihomo ${tag} (${OS_NAME}/${ARCH_NAME})..."
    if download_url "$asset_url" "$tmp_gz"; then
        gzip -dc "$tmp_gz" > "${target_bin}.tmp"
        rm -f "$tmp_gz"
        chmod +x "${target_bin}.tmp"
        if [ "$OS_NAME" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
            xattr -d com.apple.quarantine "${target_bin}.tmp" 2>/dev/null || true
        fi
        mv "${target_bin}.tmp" "$target_bin"
        if "$target_bin" -v >/dev/null 2>&1; then
            ok "mihomo 安装完成: $target_bin"
            return 0
        fi
    fi
    rm -f "$tmp_gz" "${target_bin}.tmp"

    if [ "$OS_NAME" = "darwin" ] && command -v brew >/dev/null 2>&1; then
        info "尝试通过 Homebrew 安装 mihomo..."
        brew install mihomo && return 0
    fi

    err "下载安装 mihomo 失败，请检查网络连接或手动安装 mihomo。"
}

python_has_clean_yaml() {
    local py="$1"
    [ -n "$py" ] && [ -x "$py" ] || return 1
    local err_out
    err_out="$("$py" -c "import hashlib, ssl, urllib.request, yaml" 2>&1 >/dev/null)" || return 1
    [ -z "$err_out" ]
}

python_has_clean_stdlib() {
    local py="$1"
    [ -n "$py" ] && [ -x "$py" ] || return 1
    local err_out
    err_out="$("$py" -c "import hashlib, ssl, urllib.request" 2>&1 >/dev/null)" || return 1
    [ -z "$err_out" ]
}

save_python_bin() {
    PYTHON_BIN="$1"
    printf '%s\n' "$PYTHON_BIN" > "$INSTALL_DIR/.python_bin"
}

ensure_pyyaml() {
    local candidates=(
        "$INSTALL_DIR/.venv/bin/python3"
        "/opt/homebrew/bin/python3"
        "/usr/local/bin/python3"
        "/usr/bin/python3"
        "$(command -v python3 2>/dev/null || true)"
    )

    local py
    for py in "${candidates[@]}"; do
        if python_has_clean_yaml "$py"; then
            save_python_bin "$py"
            ok "Python 依赖已就绪 ($PYTHON_BIN)"
            return 0
        fi
    done

    local base_py=""
    for py in "/opt/homebrew/bin/python3" "/usr/local/bin/python3" "/usr/bin/python3" "$(command -v python3 2>/dev/null || true)"; do
        if python_has_clean_stdlib "$py"; then
            base_py="$py"
            break
        fi
    done
    [ -n "$base_py" ] || base_py="$(command -v python3)"

    info "正在配置 Python PyYAML 依赖 (基于 $base_py)..."
    if "$base_py" -m venv "$INSTALL_DIR/.venv" >/dev/null 2>&1; then
        if "$INSTALL_DIR/.venv/bin/pip" install -q --disable-pip-version-check pyyaml 2>/dev/null || \
           "$INSTALL_DIR/.venv/bin/pip" install -q --disable-pip-version-check -i https://pypi.tuna.tsinghua.edu.cn/simple pyyaml 2>/dev/null; then
            save_python_bin "$INSTALL_DIR/.venv/bin/python3"
            ok "已在独立虚拟环境中安装 PyYAML ($PYTHON_BIN)"
            return 0
        fi
        rm -rf "$INSTALL_DIR/.venv"
    fi

    if command -v apt-get >/dev/null 2>&1; then
        install_sys_packages python3-yaml || true
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        install_sys_packages python3-pyyaml || true
    elif command -v pacman >/dev/null 2>&1; then
        install_sys_packages python-yaml || true
    elif command -v apk >/dev/null 2>&1; then
        install_sys_packages py3-yaml || true
    fi

    for py in "/usr/bin/python3" "$base_py" "$(command -v python3 2>/dev/null || true)"; do
        if [ -n "$py" ] && [ -x "$py" ] && "$py" -c "import yaml" >/dev/null 2>&1; then
            save_python_bin "$py"
            ok "已通过系统包管理器配置 PyYAML ($PYTHON_BIN)"
            return 0
        fi
    done

    if "$base_py" -m pip install --user -q pyyaml 2>/dev/null || \
       "$base_py" -m pip install --user --break-system-packages -q pyyaml 2>/dev/null || \
       "$base_py" -m pip install --user --break-system-packages -q -i https://pypi.tuna.tsinghua.edu.cn/simple pyyaml 2>/dev/null; then
        save_python_bin "$base_py"
        ok "已通过 pip 安装 PyYAML ($PYTHON_BIN)"
        return 0
    fi

    err "无法自动安装 Python 模块 PyYAML，请执行例如 sudo apt install python3-yaml 或 pip3 install pyyaml 后重试。"
}

install_core_files() {
    mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/runtime"

    local script_dir=""
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi

    local files=("vpn.py" "vpn_env.sh" "uninstall.sh")
    if [ -n "$script_dir" ] && [ -f "$script_dir/vpn.py" ] && [ -f "$script_dir/vpn_env.sh" ]; then
        info "正在从本地目录安装脚本到 $INSTALL_DIR ..."
        for f in "${files[@]}"; do
            if [ -f "$script_dir/$f" ] && [ "$script_dir/$f" != "$INSTALL_DIR/$f" ]; then
                cp "$script_dir/$f" "$INSTALL_DIR/$f"
            fi
        done
    else
        info "正在从 GitHub (${REPO_SLUG}@${REPO_BRANCH}) 下载脚本到 $INSTALL_DIR ..."
        local base_raw="https://raw.githubusercontent.com/${REPO_SLUG}/${REPO_BRANCH}"
        for f in "${files[@]}"; do
            download_url "${base_raw}/${f}" "$INSTALL_DIR/$f" || err "下载 ${f} 失败"
        done
    fi

    chmod +x "$INSTALL_DIR/vpn.py" "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
}

configure_shell_rc() {
    [ "$NO_RC" -eq 0 ] || return 0

    local targets=()
    local user_shell
    user_shell="$(basename "${SHELL:-}")"

    if [ "$(uname -s)" = "Darwin" ]; then
        targets+=("$HOME/.zshrc")
        [ -f "$HOME/.bashrc" ] && targets+=("$HOME/.bashrc")
    else
        targets+=("$HOME/.bashrc")
        if [ "$user_shell" = "zsh" ] || [ -f "$HOME/.zshrc" ]; then
            targets+=("$HOME/.zshrc")
        fi
    fi

    local marker_start="# >>> cli-vpn >>>"
    local marker_end="# <<< cli-vpn <<<"
    local block="${marker_start}
export CLI_VPN_HOME=\"${INSTALL_DIR}\"
[ -s \"${INSTALL_DIR}/vpn_env.sh\" ] && . \"${INSTALL_DIR}/vpn_env.sh\"
${marker_end}"

    for rc in "${targets[@]}"; do
        touch "$rc"
        "$PYTHON_BIN" - "$rc" "$marker_start" "$marker_end" "$block" <<'PY'
import re
import sys

rc_path, start, end, block = sys.argv[1:5]
with open(rc_path, "r", encoding="utf-8", errors="replace") as f:
    content = f.read()

# Remove existing managed block if present
pattern = re.compile(r"\n?" + re.escape(start) + r".*?" + re.escape(end) + r"\n?", re.DOTALL)
content = pattern.sub("\n", content)

# Also clean up legacy manual two-line snippet if present
legacy = re.compile(r"\n?# CLI VPN\nsource [^\n]*cli-vpn/vpn_env\.sh\n?")
content = legacy.sub("\n", content)

content = content.rstrip() + "\n\n" + block + "\n"
with open(rc_path, "w", encoding="utf-8") as f:
    f.write(content)
PY
        ok "已更新 Shell 配置: $rc"
    done
}

configure_subscription() {
    local cfg_args=()
    if [ -z "$SUB_URL" ] && [ "$NON_INTERACTIVE" -eq 0 ]; then
        local has_existing=0
        if [ -f "$INSTALL_DIR/config.json" ]; then
            if "$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("sub_url") else 1)' "$INSTALL_DIR/config.json" 2>/dev/null; then
                has_existing=1
            fi
        fi
        if [ "$has_existing" -eq 0 ] && [ -t 1 ] && ( : </dev/tty ) 2>/dev/null; then
            printf '\n请输入你的 Clash 订阅链接 (直接回车可稍后通过 `vpn config --sub-url` 配置): ' >/dev/tty
            read -r SUB_URL </dev/tty || true
        fi
    fi

    [ -n "$SUB_URL" ] && cfg_args+=(--sub-url "$SUB_URL")
    [ -n "$PROXY_PORT" ] && cfg_args+=(--port "$PROXY_PORT")
    [ -n "$API_PORT" ] && cfg_args+=(--api-port "$API_PORT")

    if [ "${#cfg_args[@]}" -gt 0 ]; then
        CLI_VPN_HOME="$INSTALL_DIR" "$PYTHON_BIN" "$INSTALL_DIR/vpn.py" config "${cfg_args[@]}"
    fi
}

main() {
    info "开始安装 cli-vpn 到 $INSTALL_DIR ..."
    ensure_base_tools
    install_core_files
    ensure_pyyaml
    ensure_mihomo
    configure_shell_rc
    configure_subscription

    printf '\n'
    ok "cli-vpn 安装完成！"
    printf '  1) 让当前终端立即生效:\n     source "%s/vpn_env.sh"\n' "$INSTALL_DIR"
    if [ ! -f "$INSTALL_DIR/config.json" ] || ! "$PYTHON_BIN" -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("sub_url") else 1)' "$INSTALL_DIR/config.json" 2>/dev/null; then
        printf '  2) 配置订阅链接:\n     vpn config --sub-url "https://你的Clash订阅地址"\n'
        printf '  3) 一键开启并选最快海外节点:\n     vpn on\n'
    else
        printf '  2) 一键开启并选最快海外节点:\n     vpn on\n'
    fi
}

main
