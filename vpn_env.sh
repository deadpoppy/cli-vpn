# Universal shell helper for CLI VPN (supports bash & zsh on macOS & Linux)
# Source this file in ~/.zshrc or ~/.bashrc:
#   source "$HOME/.cli-vpn/vpn_env.sh"

if [ -z "${CLI_VPN_HOME:-}" ]; then
    if [ -n "${BASH_SOURCE[0]:-}" ]; then
        CLI_VPN_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    elif [ -n "${ZSH_VERSION:-}" ]; then
        eval 'CLI_VPN_HOME="$(cd "$(dirname "${(%):-%x}")" && pwd)"'
    else
        CLI_VPN_HOME="$HOME/.cli-vpn"
    fi
fi
export CLI_VPN_HOME

_vpn_python() {
    if [ -n "${CLI_VPN_PYTHON:-}" ] && [ -x "${CLI_VPN_PYTHON}" ]; then
        printf '%s\n' "${CLI_VPN_PYTHON}"
        return 0
    fi
    if [ -f "${CLI_VPN_HOME}/.python_bin" ]; then
        local pinned
        pinned="$(tr -d '\r\n' < "${CLI_VPN_HOME}/.python_bin")"
        if [ -n "${pinned}" ] && [ -x "${pinned}" ]; then
            printf '%s\n' "${pinned}"
            return 0
        fi
    fi
    if [ -x "${CLI_VPN_HOME}/.venv/bin/python3" ]; then
        printf '%s\n' "${CLI_VPN_HOME}/.venv/bin/python3"
    elif command -v python3 >/dev/null 2>&1; then
        command -v python3
    else
        printf '%s\n' "/usr/bin/python3"
    fi
}

_vpn_proxy_addr() {
    if [ -n "${CLI_VPN_PROXY_ADDR:-}" ]; then
        printf '%s\n' "${CLI_VPN_PROXY_ADDR}"
    elif [ -f "${CLI_VPN_HOME}/runtime/proxy_addr" ]; then
        tr -d ' \t\r\n' < "${CLI_VPN_HOME}/runtime/proxy_addr"
    else
        printf '%s\n' "127.0.0.1:7890"
    fi
}

_vpn_enable_env() {
    local addr
    addr="$(_vpn_proxy_addr)"
    export http_proxy="http://${addr}"
    export https_proxy="http://${addr}"
    export HTTP_PROXY="http://${addr}"
    export HTTPS_PROXY="http://${addr}"
    export ALL_PROXY="socks5://${addr}"
    export all_proxy="socks5://${addr}"
    export no_proxy="localhost,127.0.0.1,::1"
    export NO_PROXY="localhost,127.0.0.1,::1"
}

_vpn_disable_env() {
    unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy no_proxy NO_PROXY
}

vpn() {
    local cmd="${1:-status}"
    if [ $# -gt 0 ]; then
        shift
    fi
    local py
    py="$(_vpn_python)"
    local script="${CLI_VPN_HOME}/vpn.py"

    case "$cmd" in
        on|update)
            "$py" "$script" "$cmd" "$@" || return 1
            _vpn_enable_env
            echo "当前终端代理环境变量已开启 ($(_vpn_proxy_addr))。"
            ;;
        best)
            "$py" "$script" best "$@" || return 1
            _vpn_enable_env
            echo "当前终端代理环境变量已开启 ($(_vpn_proxy_addr))。"
            ;;
        off)
            _vpn_disable_env
            "$py" "$script" off "$@"
            echo "当前终端代理环境变量已关闭。"
            ;;
        env-on)
            _vpn_enable_env
            echo "当前终端代理环境变量已开启 ($(_vpn_proxy_addr))。"
            ;;
        env-off)
            _vpn_disable_env
            echo "当前终端代理环境变量已关闭。"
            ;;
        status)
            "$py" "$script" status "$@"
            if [ -n "${http_proxy:-}" ]; then
                echo "终端代理环境变量: 已开启 (${http_proxy})"
            else
                echo "终端代理环境变量: 未开启 (可执行 vpn env-on 在当前终端开启)"
            fi
            ;;
        config)
            "$py" "$script" config "$@" || return 1
            if [ -n "${http_proxy:-}" ]; then
                _vpn_enable_env
            fi
            ;;
        logs)
            "$py" "$script" logs "$@"
            ;;
        uninstall)
            if [ -x "${CLI_VPN_HOME}/uninstall.sh" ]; then
                _vpn_disable_env
                "${CLI_VPN_HOME}/uninstall.sh" "$@"
            else
                echo "未找到卸载脚本: ${CLI_VPN_HOME}/uninstall.sh" >&2
                return 1
            fi
            ;;
        help|-h|--help)
            echo "用法: vpn {on|off|best|update|status|config|logs|env-on|env-off|uninstall}"
            echo ""
            echo "常用命令:"
            echo "  vpn on                启动后台 mihomo、自动选最快海外节点并开启当前终端代理"
            echo "  vpn off               关闭当前终端代理并停止后台 mihomo"
            echo "  vpn best              重新并发测速并切换到最优海外节点"
            echo "  vpn update            强制刷新订阅并重新测速选节点"
            echo "  vpn status            查看运行状态、当前节点与出口 IP"
            echo "  vpn config --sub-url  配置或更新 Clash 订阅链接及本地端口"
            echo "  vpn env-on / env-off  仅在当前终端开启/关闭代理环境变量（不停止后台服务）"
            echo "  vpn logs              查看 mihomo 日志"
            echo "  vpn uninstall         一键卸载 cli-vpn"
            ;;
        *)
            echo "未知命令: $cmd" >&2
            echo "用法: vpn {on|off|best|update|status|config|logs|env-on|env-off|uninstall}" >&2
            return 1
            ;;
    esac
}
