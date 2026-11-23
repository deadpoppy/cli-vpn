#!/usr/bin/env python3
"""Cross-platform CLI VPN controller (macOS & Linux) powered by mihomo.

Supports:
- Encrypted built-in airport bundle (`bundle.enc`) for zero-network out-of-the-box setup
- Clash YAML subscriptions, `?flag=clash` panel URLs, Base64 URI subscriptions, and local YAML files
- Direct + proxy-fallback subscription fetching (for GFW-blocked airport domains)
- Fast concurrent latency testing, non-CN/HK/TW exit IP verification, and bandwidth benchmarking
"""

import argparse
import base64
import concurrent.futures
import getpass
import hashlib
import hmac
import json
import os
import platform
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.environ.get("CLI_VPN_HOME") or SCRIPT_DIR)
RUNTIME_DIR = os.path.join(BASE_DIR, "runtime")
CONFIG_JSON_PATH = os.path.join(BASE_DIR, "config.json")
BUNDLE_PATH = os.path.join(BASE_DIR, "bundle.enc")
MIHOMO_CONFIG_PATH = os.path.join(RUNTIME_DIR, "config.yaml")
PROVIDER_SUB_PATH = os.path.join(RUNTIME_DIR, "provider_sub.txt")
PID_PATH = os.path.join(RUNTIME_DIR, "mihomo.pid")
LOG_PATH = os.path.join(RUNTIME_DIR, "mihomo.log")
CACHE_PATH = os.path.join(RUNTIME_DIR, "last_best.json")
PROXY_ADDR_PATH = os.path.join(RUNTIME_DIR, "proxy_addr")

PBKDF2_ITERATIONS = 600000
BUNDLE_MAGIC = b"CLIVPN1|"
AUTO_POOL_GROUP = "AUTO_POOL"
DEFAULT_PROVIDER = "default_sub"

DEFAULT_SETTINGS = {
    "sub_url": "",
    "proxy_port": 7890,
    "api_port": 9090,
    "sub_max_age_hours": 72,
    "best_cache_minutes": 60,
    "excluded_countries": ["CN", "HK", "TW"],
}

IGNORED_TYPES = {
    "Direct",
    "Reject",
    "RejectDrop",
    "Selector",
    "URLTest",
    "Fallback",
    "LoadBalance",
    "Relay",
    "Compatible",
    "Pass",
}
INFO_KEYWORDS = (
    "剩余",
    "流量",
    "到期",
    "过期",
    "官网",
    "套餐",
    "重置",
    "订阅",
    "网址",
    "失联",
    "免认证",
    "机上wifi",
    "expire",
    "traffic",
)
COUNTRY_NAME_HINTS = {
    "CN": ("中国", "国内", "回国", "china"),
    "HK": ("香港", "hongkong", "hong kong", "hk"),
    "TW": ("台湾", "台灣", "taiwan", "tw"),
}
PROXY_URI_PREFIXES = (
    "vmess://",
    "vless://",
    "ss://",
    "ssr://",
    "trojan://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "wireguard://",
    " socks://",
)

NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Authenticated Encryption (PBKDF2-HMAC-SHA256 + HMAC-SHA256-CTR + EtM HMAC)
# Pure Python 3 stdlib — zero external crypto/OpenSSL CLI incompatibilities
# ---------------------------------------------------------------------------
def _xor_keystream(data_bytes, k_enc, nonce):
    n = len(data_bytes)
    if n == 0:
        return b""
    blocks = (n + 31) // 32
    stream = b"".join(
        hmac.new(k_enc, nonce + struct.pack(">Q", i), hashlib.sha256).digest()
        for i in range(blocks)
    )[:n]
    a = int.from_bytes(data_bytes, "big")
    b = int.from_bytes(stream, "big")
    return (a ^ b).to_bytes(n, "big")


def encrypt_payload(payload_dict, password):
    if not password:
        raise RuntimeError("加密密码不能为空")
    raw_json = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    compressed = zlib.compress(raw_json, level=9)

    salt = os.urandom(16)
    nonce = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64)
    k_enc, k_mac = dk[:32], dk[32:]

    ciphertext = _xor_keystream(compressed, k_enc, nonce)
    tag = hmac.new(
        k_mac,
        BUNDLE_MAGIC + struct.pack(">I", PBKDF2_ITERATIONS) + salt + nonce + ciphertext,
        hashlib.sha256,
    ).digest()

    return {
        "v": 1,
        "iter": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_payload(envelope, password):
    if not isinstance(envelope, dict) or envelope.get("v") != 1:
        raise RuntimeError("加密包格式不受支持")
    iters = int(envelope.get("iter", PBKDF2_ITERATIONS))
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    expected_tag = base64.b64decode(envelope["tag"])
    ciphertext = base64.b64decode(envelope["ct"])

    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=64)
    k_enc, k_mac = dk[:32], dk[32:]

    actual_tag = hmac.new(
        k_mac,
        BUNDLE_MAGIC + struct.pack(">I", iters) + salt + nonce + ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise ValueError("解密密码错误")

    compressed = _xor_keystream(ciphertext, k_enc, nonce)
    raw_json = zlib.decompress(compressed).decode("utf-8")
    return json.loads(raw_json)


def find_bundle_file():
    for candidate in (BUNDLE_PATH, os.path.join(SCRIPT_DIR, "bundle.enc")):
        if os.path.isfile(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Settings Management
# ---------------------------------------------------------------------------
def load_settings():
    settings = dict(DEFAULT_SETTINGS)
    if os.path.isfile(CONFIG_JSON_PATH):
        try:
            with open(CONFIG_JSON_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                settings.update(saved)
        except Exception as e:
            print("警告: 读取配置文件失败 ({}): {}".format(CONFIG_JSON_PATH, e), file=sys.stderr)

    env_sub = os.environ.get("CLI_VPN_SUB_URL", "").strip()
    if env_sub:
        settings["sub_url"] = env_sub

    env_port = os.environ.get("CLI_VPN_PORT", "").strip()
    if env_port.isdigit():
        settings["proxy_port"] = int(env_port)

    env_api_port = os.environ.get("CLI_VPN_API_PORT", "").strip()
    if env_api_port.isdigit():
        settings["api_port"] = int(env_api_port)

    return settings


def save_settings(settings):
    ensure_dirs()
    persisted = {k: settings.get(k, v) for k, v in DEFAULT_SETTINGS.items()}
    tmp_path = CONFIG_JSON_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(persisted, f, ensure_ascii=False, indent=2)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, CONFIG_JSON_PATH)
    write_proxy_addr(persisted["proxy_port"])


def write_proxy_addr(proxy_port):
    ensure_dirs()
    with open(PROXY_ADDR_PATH, "w", encoding="utf-8") as f:
        f.write("127.0.0.1:{}\n".format(proxy_port))


def mask_url(url):
    if not url:
        return "(未配置)"
    if os.path.isfile(os.path.expanduser(url)):
        return url
    try:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or ""
        if len(path) > 10:
            masked_path = path[:6] + "***" + path[-4:]
        else:
            masked_path = "/***"
        return "{}://{}{}".format(parsed.scheme or "https", parsed.netloc, masked_path)
    except Exception:
        return "***"


# ---------------------------------------------------------------------------
# Mihomo Process & Network Helpers
# ---------------------------------------------------------------------------
def find_mihomo():
    candidates = [
        os.environ.get("CLI_VPN_MIHOMO", ""),
        os.path.join(BASE_DIR, "bin", "mihomo"),
        shutil.which("mihomo") or "",
        os.path.expanduser("~/.local/bin/mihomo"),
        "/opt/homebrew/bin/mihomo",
        "/usr/local/bin/mihomo",
        "/usr/bin/mihomo",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    sys_name = platform.system()
    hint = (
        "brew install mihomo 或重新运行 install.sh"
        if sys_name == "Darwin"
        else "重新运行 install.sh 自动下载 mihomo"
    )
    raise RuntimeError("未找到可执行文件 mihomo，请执行: {}".format(hint))


def is_mihomo_process(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

    proc_cmdline = "/proc/{}/cmdline".format(pid)
    if os.path.isfile(proc_cmdline):
        try:
            with open(proc_cmdline, "rb") as f:
                raw = f.read().decode("utf-8", errors="ignore").lower()
            if raw:
                return "mihomo" in raw
        except Exception:
            pass

    try:
        res = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if res.returncode == 0 and res.stdout.strip():
            return "mihomo" in res.stdout.strip().lower()
    except Exception:
        pass

    return True


def read_pid():
    if not os.path.isfile(PID_PATH):
        return None
    try:
        with open(PID_PATH, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
        return pid if is_mihomo_process(pid) else None
    except (ValueError, OSError):
        return None


def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", int(port))) == 0


def api_request(api_port, path, method="GET", data=None, timeout=5):
    url = "http://127.0.0.1:{}{}".format(api_port, path)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def clean_proxy_env():
    env = dict(os.environ)
    for k in (
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ):
        env.pop(k, None)
    return env


def http_get_url(url, timeout=15, user_agent="clash.meta/v1.19.34", proxy_url=None):
    if shutil.which("curl"):
        cmd = ["curl", "-fsSL", "-A", user_agent, "--max-time", str(timeout)]
        if proxy_url:
            cmd.extend(["-x", proxy_url])
        else:
            cmd.extend(["--noproxy", "*"])
        cmd.append(url)
        res = subprocess.run(cmd, capture_output=True, text=True, env=clean_proxy_env())
        if res.returncode == 0 and res.stdout:
            return res.stdout
        err_msg = res.stderr.strip()
    else:
        err_msg = "未安装 curl"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        ctx = ssl.create_default_context()
        handlers = [urllib.request.HTTPSHandler(context=ctx)]
        if proxy_url and proxy_url.startswith("http"):
            handlers.insert(0, urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        else:
            handlers.insert(0, urllib.request.ProxyHandler({}))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        raise RuntimeError("{} ({})".format(err_msg or "请求失败", e))


# ---------------------------------------------------------------------------
# Universal Subscription Parsing & Mihomo Config Generation
# ---------------------------------------------------------------------------
def looks_like_uri_list(text):
    sample = text.strip()
    if not sample:
        return False
    if any(sample.lower().startswith(p.strip()) for p in PROXY_URI_PREFIXES):
        return True
    # Try Base64 decode check
    compact = "".join(sample.split())
    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore").strip()
        if any(p.strip() in decoded.lower() for p in PROXY_URI_PREFIXES):
            return True
    except Exception:
        pass
    return False


def try_parse_clash_yaml(raw_text):
    try:
        cfg = yaml.safe_load(raw_text)
        if isinstance(cfg, dict) and isinstance(cfg.get("proxies"), list) and cfg["proxies"]:
            return cfg
    except Exception:
        pass
    return None


def append_clash_flag(url):
    parsed = urllib.parse.urlsplit(url)
    if not parsed.scheme.startswith("http"):
        return None
    q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    keys = {k.lower() for k, _ in q}
    if "flag" in keys:
        return None
    q.append(("flag", "clash"))
    new_query = urllib.parse.urlencode(q)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
    )


def candidate_proxies_for_fetch(settings):
    proxies = [None]  # Try direct first
    for env_key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(env_key, "").strip()
        if val and val not in proxies:
            proxies.append(val)
    if read_pid():
        local_px = "http://127.0.0.1:{}".format(int(settings["proxy_port"]))
        if local_px not in proxies:
            proxies.append(local_px)
    return proxies


def fetch_subscription_raw(sub_url, settings):
    expanded = os.path.expanduser(sub_url.strip())
    if os.path.isfile(expanded):
        with open(expanded, "r", encoding="utf-8") as f:
            return f.read()

    urls_to_try = [sub_url]
    flagged = append_clash_flag(sub_url)
    if flagged:
        urls_to_try.append(flagged)

    last_err = None
    best_non_yaml = None

    for proxy_url in candidate_proxies_for_fetch(settings):
        for candidate_url in urls_to_try:
            for ua in ("clash.meta/v1.19.34", "clash-verge/v2.5.10"):
                try:
                    text = http_get_url(
                        candidate_url,
                        timeout=12 if proxy_url is None else 18,
                        user_agent=ua,
                        proxy_url=proxy_url,
                    )
                except Exception as e:
                    last_err = e
                    continue

                if try_parse_clash_yaml(text) is not None:
                    return text
                if looks_like_uri_list(text) and best_non_yaml is None:
                    best_non_yaml = text

    if best_non_yaml is not None:
        return best_non_yaml

    raise RuntimeError("拉取订阅失败: {}".format(last_err or "订阅返回内容为空或格式无效"))


def clean_base_mihomo_fields(cfg, proxy_port, api_port):
    # Remove any conflicting listener/UI/rule keys from upstream subscription YAML
    for key in (
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "authentication",
        "secret",
        "external-ui",
        "external-ui-url",
        "external-ui-name",
        "rule-providers",
        "geox-url",
    ):
        cfg.pop(key, None)

    cfg["mixed-port"] = int(proxy_port)
    cfg["bind-address"] = "127.0.0.1"
    cfg["allow-lan"] = False
    cfg["mode"] = "global"
    cfg["ipv6"] = False
    cfg["log-level"] = "warning"
    cfg["unified-delay"] = True
    cfg["tcp-concurrent"] = True
    cfg["external-controller"] = "127.0.0.1:{}".format(int(api_port))
    cfg["tun"] = {"enable": False}
    cfg["rules"] = ["MATCH,GLOBAL"]
    cfg["geodata-mode"] = False
    cfg["dns"] = {
        "enable": True,
        "ipv6": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "nameserver": [
            "223.5.5.5",
            "119.29.29.29",
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query",
        ],
        "proxy-server-nameserver": [
            "223.5.5.5",
            "119.29.29.29",
            "https://doh.pub/dns-query",
        ],
    }
    return cfg


def apply_raw_subscription(raw_text, settings):
    ensure_dirs()
    proxy_port = int(settings["proxy_port"])
    api_port = int(settings["api_port"])

    parsed_yaml = try_parse_clash_yaml(raw_text)
    if parsed_yaml is not None:
        cfg = clean_base_mihomo_fields(parsed_yaml, proxy_port, api_port)
        if os.path.isfile(PROVIDER_SUB_PATH):
            os.remove(PROVIDER_SUB_PATH)
        with open(MIHOMO_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        os.chmod(MIHOMO_CONFIG_PATH, 0o600)
        write_proxy_addr(proxy_port)
        return len(cfg.get("proxies", [])), "yaml"

    if looks_like_uri_list(raw_text):
        with open(PROVIDER_SUB_PATH, "w", encoding="utf-8") as f:
            f.write(raw_text.strip() + "\n")
        os.chmod(PROVIDER_SUB_PATH, 0o600)

        cfg = clean_base_mihomo_fields({}, proxy_port, api_port)
        cfg["proxy-providers"] = {
            DEFAULT_PROVIDER: {
                "type": "file",
                "path": "./provider_sub.txt",
            }
        }
        cfg["proxy-groups"] = [
            {
                "name": AUTO_POOL_GROUP,
                "type": "select",
                "use": [DEFAULT_PROVIDER],
            }
        ]
        with open(MIHOMO_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        os.chmod(MIHOMO_CONFIG_PATH, 0o600)
        write_proxy_addr(proxy_port)
        return -1, "provider"

    raise RuntimeError("订阅内容既不是有效的 Clash YAML，也不是 Base64/URI 节点列表")


def fetch_and_patch_config(settings):
    print("[1/4] 正在拉取机场订阅配置...")
    raw_text = fetch_subscription_raw(settings["sub_url"], settings)
    count, mode = apply_raw_subscription(raw_text, settings)
    if mode == "yaml":
        print("      订阅已更新 (Clash YAML)，共 {} 个节点".format(count))
    else:
        print("      订阅已更新 (Base64/URI 订阅源)")


def sanitize_existing_config(settings):
    if not os.path.isfile(MIHOMO_CONFIG_PATH):
        return
    try:
        with open(MIHOMO_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        if not isinstance(cfg, dict):
            return
        proxy_port = int(settings["proxy_port"])
        api_port = int(settings["api_port"])
        expected_ctrl = "127.0.0.1:{}".format(api_port)
        needs_fix = (
            "port" in cfg
            or "socks-port" in cfg
            or cfg.get("mixed-port") != proxy_port
            or cfg.get("external-controller") != expected_ctrl
            or cfg.get("ipv6") is True
        )
        if needs_fix:
            clean_base_mihomo_fields(cfg, proxy_port, api_port)
            with open(MIHOMO_CONFIG_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
            os.chmod(MIHOMO_CONFIG_PATH, 0o600)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Bundle Unlock & Creation
# ---------------------------------------------------------------------------
def unlock_bundle(settings, password=None):
    bundle_file = find_bundle_file()
    if not bundle_file:
        raise RuntimeError("未找到内置加密机场包 (bundle.enc)")

    with open(bundle_file, "r", encoding="utf-8") as f:
        envelope = json.load(f)

    pw = password or os.environ.get("CLI_VPN_PASS", "").strip()
    if pw:
        try:
            payload = decrypt_payload(envelope, pw)
        except ValueError:
            raise RuntimeError("内置机场解密密码错误")
    elif sys.stdin.isatty():
        payload = None
        for attempt in range(1, 4):
            try:
                entered = getpass.getpass("请输入内置机场解密密码: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("", file=sys.stderr)
                break
            if not entered:
                continue
            try:
                payload = decrypt_payload(envelope, entered)
                break
            except ValueError:
                print("密码错误 ({}/3)，请重试。".format(attempt), file=sys.stderr)
        if payload is None:
            raise RuntimeError("未能解锁内置机场配置")
    else:
        raise RuntimeError(
            "检测到内置加密机场包，请提供解密密码:\n"
            "  vpn unlock -p <密码>   或   vpn on -p <密码>"
        )

    sub_url = (payload.get("sub_url") or "").strip()
    raw_content = payload.get("raw_content") or ""
    if not raw_content:
        raise RuntimeError("加密包内节点数据为空")

    if sub_url and not settings.get("sub_url"):
        settings["sub_url"] = sub_url
    elif sub_url and password is not None:
        settings["sub_url"] = sub_url
    save_settings(settings)

    count, mode = apply_raw_subscription(raw_content, settings)
    if os.path.isfile(CACHE_PATH):
        os.remove(CACHE_PATH)
    if mode == "yaml":
        print("已成功解锁内置机场配置（共 {} 个节点），免拉取直接可用！".format(count))
    else:
        print("已成功解锁内置机场配置，免拉取直接可用！")


def create_bundle(settings, password=None, out_path=None):
    pw = password or os.environ.get("CLI_VPN_PASS", "").strip()
    if not pw and sys.stdin.isatty():
        pw = getpass.getpass("请设置加密包解密密码: ").strip()
    if not pw:
        raise RuntimeError("请通过 `-p <密码>` 指定加密密码")

    sub_url = settings.get("sub_url", "").strip()
    raw_content = None
    if sub_url:
        try:
            print("正在拉取最新机场节点以打包...")
            raw_content = fetch_subscription_raw(sub_url, settings)
        except Exception as e:
            print("警告: 拉取最新订阅失败 ({})，尝试使用本地现有节点打包...".format(e))

    if not raw_content:
        if os.path.isfile(PROVIDER_SUB_PATH):
            with open(PROVIDER_SUB_PATH, "r", encoding="utf-8") as f:
                raw_content = f.read()
        elif os.path.isfile(MIHOMO_CONFIG_PATH):
            with open(MIHOMO_CONFIG_PATH, "r", encoding="utf-8") as f:
                raw_content = f.read()
        else:
            raise RuntimeError("本地无可用机场节点配置，请先配置 --sub-url")

    envelope = encrypt_payload({"sub_url": sub_url, "raw_content": raw_content}, pw)
    target = os.path.abspath(out_path or BUNDLE_PATH)
    with open(target, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
    print("已生成加密机场包: {} ({:.1f} KB)".format(target, os.path.getsize(target) / 1024.0))


def require_config_ready(settings, cli_sub_url=None, password=None):
    if cli_sub_url:
        settings["sub_url"] = cli_sub_url.strip()
        save_settings(settings)
        fetch_and_patch_config(settings)
        return True

    if password:
        unlock_bundle(settings, password=password)
        return True

    if os.path.isfile(MIHOMO_CONFIG_PATH):
        return False

    if settings.get("sub_url"):
        try:
            fetch_and_patch_config(settings)
            return True
        except Exception as e:
            if find_bundle_file():
                print("拉取订阅失败 ({})，尝试解锁内置加密机场包...".format(e))
                unlock_bundle(settings, password=password)
                return True
            raise

    if find_bundle_file():
        unlock_bundle(settings, password=password)
        return True

    if sys.stdin.isatty():
        try:
            entered = input("请输入 Clash/通用机场订阅链接 (SUB_URL): ").strip()
        except (EOFError, KeyboardInterrupt):
            entered = ""
        if entered:
            settings["sub_url"] = entered
            save_settings(settings)
            fetch_and_patch_config(settings)
            return True

    raise RuntimeError(
        "未找到可用节点配置，请解锁内置机场 (`vpn on -p <密码>`) 或设置订阅 (`vpn config --sub-url <链接>`)"
    )


# ---------------------------------------------------------------------------
# Start / Stop & Best Node Selection
# ---------------------------------------------------------------------------
def start_mihomo(settings):
    proxy_port = int(settings["proxy_port"])
    api_port = int(settings["api_port"])
    write_proxy_addr(proxy_port)

    sanitize_existing_config(settings)

    pid = read_pid()
    if pid:
        return pid

    for label, port in (("代理端口", proxy_port), ("控制端口", api_port)):
        if is_port_in_use(port):
            raise RuntimeError(
                "{} 127.0.0.1:{} 已被其他程序占用，可通过以下命令修改端口:\n"
                "  vpn config --port 7891 --api-port 9091".format(label, port)
            )

    mihomo_bin = find_mihomo()
    ensure_dirs()
    log_file = open(LOG_PATH, "a", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            [mihomo_bin, "-d", RUNTIME_DIR, "-f", MIHOMO_CONFIG_PATH],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=clean_proxy_env(),
        )
    finally:
        log_file.close()

    with open(PID_PATH, "w", encoding="utf-8") as f:
        f.write(str(proc.pid))

    for _ in range(35):
        if proc.poll() is not None:
            break
        try:
            api_request(api_port, "/version", timeout=1)
            return proc.pid
        except Exception:
            time.sleep(0.3)

    stop_mihomo(quiet=True)
    raise RuntimeError("mihomo 启动失败或超时，请执行 `vpn logs` 查看日志: {}".format(LOG_PATH))


def stop_mihomo(quiet=False):
    pid = read_pid()
    if not pid:
        if os.path.isfile(PID_PATH):
            os.remove(PID_PATH)
        if not quiet:
            print("mihomo 未在运行。")
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    for _ in range(20):
        if not is_mihomo_process(pid):
            break
        time.sleep(0.15)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    if os.path.isfile(PID_PATH):
        os.remove(PID_PATH)
    if not quiet:
        print("已停止 mihomo (PID {})。".format(pid))


def build_excluded_hints(excluded_countries):
    hints = []
    for cc in excluded_countries:
        hints.extend(COUNTRY_NAME_HINTS.get(cc.upper(), ()))
    return tuple(hints)


def is_candidate_node(name, info, excluded_hints):
    if info.get("type") in IGNORED_TYPES:
        return False
    lower = name.lower()
    if "ipv6" in lower:
        return False
    if any(kw in lower for kw in INFO_KEYWORDS):
        return False
    if excluded_hints and any(h in lower for h in excluded_hints):
        return False
    return True


def list_selectable_nodes(api_port):
    data = api_request(api_port, "/proxies", timeout=5)
    proxies = data.get("proxies", {})

    # Mode 1: provider-backed AUTO_POOL group (for Base64/URI subscriptions)
    if AUTO_POOL_GROUP in proxies:
        prov = api_request(api_port, "/providers/proxies/{}".format(DEFAULT_PROVIDER), timeout=5)
        node_map = {item["name"]: item for item in prov.get("proxies", []) if "name" in item}
        order = proxies[AUTO_POOL_GROUP].get("all", list(node_map.keys()))
        return AUTO_POOL_GROUP, order, node_map

    # Mode 2: standard Clash YAML proxies in GLOBAL
    global_group = proxies.get("GLOBAL", {})
    order = global_group.get("all", list(proxies.keys()))
    return "GLOBAL", order, proxies


def switch_active_node(api_port, group_name, node_name):
    if group_name == AUTO_POOL_GROUP:
        api_request(api_port, "/proxies/GLOBAL", method="PUT", data={"name": AUTO_POOL_GROUP}, timeout=3)
        encoded_grp = urllib.parse.quote(AUTO_POOL_GROUP, safe="")
        api_request(api_port, "/proxies/{}".format(encoded_grp), method="PUT", data={"name": node_name}, timeout=3)
    else:
        api_request(api_port, "/proxies/GLOBAL", method="PUT", data={"name": node_name}, timeout=3)


def get_active_node_name(api_port):
    g = api_request(api_port, "/proxies/GLOBAL", timeout=2)
    now = g.get("now", "未知")
    if now == AUTO_POOL_GROUP:
        pool = api_request(api_port, "/proxies/{}".format(AUTO_POOL_GROUP), timeout=2)
        return pool.get("now", now)
    return now


def test_node_delay(api_port, name):
    encoded = urllib.parse.quote(name, safe="")
    url = "/proxies/{}/delay?timeout=3000&url={}".format(
        encoded, urllib.parse.quote("https://cp.cloudflare.com/generate_204", safe="")
    )
    try:
        res = api_request(api_port, url, timeout=4)
        delay = res.get("delay", 0)
        return (name, delay) if delay > 0 else None
    except Exception:
        return None


def get_direct_cn_ip():
    """Return direct public IP only when direct network is in CN (to detect proxy leaks)."""
    for url, ip_key, cc_key in (
        ("https://ipinfo.io/json", "ip", "country"),
        ("https://api.ip.sb/geoip", "ip", "country_code"),
    ):
        try:
            raw = http_get_url(url, timeout=4, user_agent="curl/8.0", proxy_url=None)
            data = json.loads(raw)
            ip = data.get(ip_key)
            cc = (data.get(cc_key) or "").upper()
            if ip and cc == "CN":
                return ip
            if ip and cc:
                return None
        except Exception:
            continue
    return None


def check_exit_ip(proxy_url):
    endpoints = [
        ("https://ipinfo.io/json", "ip", "country"),
        ("https://api.ip.sb/geoip", "ip", "country_code"),
    ]
    for url, ip_key, cc_key in endpoints:
        try:
            raw = http_get_url(url, timeout=4, user_agent="curl/8.0", proxy_url=proxy_url)
            data = json.loads(raw)
            ip = data.get(ip_key)
            country = (data.get(cc_key) or "").upper()
            if ip and country:
                return ip, country
        except Exception:
            continue
    return None, None


def measure_download_speed(proxy_url):
    test_url = "https://speed.cloudflare.com/__down?bytes=1500000"
    if shutil.which("curl"):
        cmd = [
            "curl",
            "-fsSL",
            "-o",
            os.devnull,
            "--connect-timeout",
            "3",
            "--max-time",
            "4",
            "-x",
            proxy_url,
            "-w",
            "%{size_download} %{speed_download}",
            test_url,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, env=clean_proxy_env())
        # returncode 28 = max-time reached mid-download, still valid if real payload arrived
        if res.returncode not in (0, 28):
            return 0.0
        try:
            parts = res.stdout.strip().split()
            if len(parts) >= 2:
                size_b = float(parts[0])
                bps = float(parts[1])
                if size_b >= 16384:
                    return bps / (1024 * 1024)
            return 0.0
        except ValueError:
            return 0.0

    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        req = urllib.request.Request(test_url, headers={"User-Agent": "curl/8.0"})
        t0 = time.time()
        total = 0
        with opener.open(req, timeout=4) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if time.time() - t0 > 4.0:
                    break
        if total < 16384:
            return 0.0
        elapsed = max(time.time() - t0, 0.001)
        return (total / elapsed) / (1024 * 1024)
    except Exception:
        return 0.0


def load_cached_best(cache_seconds):
    if not os.path.isfile(CACHE_PATH):
        return None
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if time.time() - data.get("timestamp", 0) < cache_seconds:
            return data
    except Exception:
        pass
    return None


def save_cached_best(name, ip, country, delay, speed_mb):
    ensure_dirs()
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(
            {
                "node": name,
                "ip": ip,
                "country": country,
                "delay": delay,
                "speed_mb": round(speed_mb, 2),
                "timestamp": time.time(),
            },
            f,
            ensure_ascii=False,
        )


def select_best_node(settings, top_n=4, use_cache=False):
    api_port = int(settings["api_port"])
    proxy_port = int(settings["proxy_port"])
    proxy_url = "http://127.0.0.1:{}".format(proxy_port)
    cache_seconds = int(settings.get("best_cache_minutes", 60)) * 60
    excluded_countries = {
        c.upper() for c in settings.get("excluded_countries", ["CN", "HK", "TW"])
    }
    excluded_hints = build_excluded_hints(excluded_countries)

    group_name, all_names, node_map = list_selectable_nodes(api_port)

    if use_cache:
        cached = load_cached_best(cache_seconds)
        if cached and cached.get("node") in node_map:
            switch_active_node(api_port, group_name, cached["node"])
            mins = int((time.time() - cached["timestamp"]) // 60)
            print(
                "已复用 {} 分钟前缓存的最优节点: {} | 地区: {} ({}) | 延迟: {}ms | 速度: {:.2f} MB/s".format(
                    mins,
                    cached["node"],
                    cached["country"],
                    cached["ip"],
                    cached["delay"],
                    cached["speed_mb"],
                )
            )
            print("（{} 分钟内免重复测速；如需强制重测请执行 vpn best）".format(cache_seconds // 60))
            return

    excl_label = "/".join(sorted(excluded_countries)) if excluded_countries else "无"
    print("[2/4] 正在并发测延迟筛选候选节点 (排除地区: {})...".format(excl_label))
    candidates = [
        name
        for name in all_names
        if name in node_map and is_candidate_node(name, node_map[name], excluded_hints)
    ]
    if not candidates:
        raise RuntimeError("未找到可用代理节点（若节点全为港台节点，可执行 `vpn config --exclude CN` 放开限制）")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(test_node_delay, api_port, name) for name in candidates]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is not None:
                results.append(res)

    if not results:
        raise RuntimeError("所有节点延迟测试均超时，请检查网络连接或执行 `vpn update` 更新节点")

    results.sort(key=lambda x: x[1])
    print(
        "      延迟测试完成（共 {} 个可用节点），开始校验出口 IP 并测速（最多取 {} 个）...".format(
            len(results), top_n
        )
    )

    print("[3/4] 逐个校验出口 IP 归属地与实测带宽:")
    direct_ip = get_direct_cn_ip()
    bad_ips = {direct_ip} if direct_ip else set()
    verified = []
    for name, delay in results:
        if len(verified) >= top_n:
            break
        switch_active_node(api_port, group_name, name)
        ip, country = check_exit_ip(proxy_url)
        if not ip or not country:
            print("      - {} ({}ms): 无法获取出口 IP，跳过".format(name, delay))
            continue
        if ip in bad_ips:
            print("      - {} ({}ms): 出口 IP {} 属于直连/已排除 IP，跳过".format(name, delay, ip))
            continue
        if country in excluded_countries:
            bad_ips.add(ip)
            print(
                "      - {} ({}ms): 出口 IP {} 位于 {} (排除地区)，跳过".format(
                    name, delay, ip, country
                )
            )
            continue

        speed_mb = measure_download_speed(proxy_url)
        if speed_mb <= 0.0:
            print(
                "      - {} ({}ms): IP={} [{}] | 下载测速失败/断流，跳过".format(
                    name, delay, ip, country
                )
            )
            continue
        print(
            "      - {} ({}ms): IP={} [{}] | 速度={:.2f} MB/s".format(
                name, delay, ip, country, speed_mb
            )
        )
        verified.append((speed_mb, -delay, name, ip, country, delay))

    if not verified:
        raise RuntimeError("候选节点均未通过目标地区出口 IP 校验")

    verified.sort(reverse=True)
    best_speed, _, best_name, best_ip, best_country, best_delay = verified[0]
    switch_active_node(api_port, group_name, best_name)
    save_cached_best(best_name, best_ip, best_country, best_delay, best_speed)

    print("[4/4] 已自动切换至最优节点:")
    print(
        "      节点: {} | 地区: {} ({}) | 延迟: {}ms | 速度: {:.2f} MB/s".format(
            best_name, best_country, best_ip, best_delay, best_speed
        )
    )


def show_status(settings):
    proxy_port = int(settings["proxy_port"])
    api_port = int(settings["api_port"])
    proxy_url = "http://127.0.0.1:{}".format(proxy_port)
    pid = read_pid()
    bundle_state = "已内置 (bundle.enc)" if find_bundle_file() else "无"
    print("运行目录: {} ({} {})".format(BASE_DIR, platform.system(), platform.machine()))
    print("订阅配置: {} | 内置加密包: {}".format(mask_url(settings.get("sub_url", "")), bundle_state))
    print("本地端口: HTTP/SOCKS5 127.0.0.1:{} | API 127.0.0.1:{}".format(proxy_port, api_port))

    if not pid:
        print("mihomo 状态: 未运行")
        return

    try:
        now = get_active_node_name(api_port)
        ip, country = check_exit_ip(proxy_url)
        print("mihomo 状态: 运行中 (PID {})".format(pid))
        print("当前节点: {}".format(now))
        print("当前出口: {} [{}]".format(ip or "未知", country or "未知"))
    except Exception as e:
        print("mihomo 状态: 运行中 (PID {})，但 API 查询失败: {}".format(pid, e))


def maybe_refresh_old_config(settings):
    if not os.path.isfile(MIHOMO_CONFIG_PATH) or not settings.get("sub_url"):
        return False
    max_age_sec = int(settings.get("sub_max_age_hours", 72)) * 3600
    age = time.time() - os.path.getmtime(MIHOMO_CONFIG_PATH)
    if age > max_age_sec:
        print("本地节点配置已超过 {} 小时，尝试后台静默刷新订阅...".format(max_age_sec // 3600))
        try:
            fetch_and_patch_config(settings)
            return True
        except Exception as e:
            print("自动刷新订阅跳过（{}），继续使用本地已有节点。".format(e))
    return False


def handle_config(args, settings):
    changed = False
    sub_updated = False
    if args.sub_url is not None:
        settings["sub_url"] = args.sub_url.strip()
        changed = True
        sub_updated = True
    if args.port is not None:
        if not (1 <= args.port <= 65535):
            raise RuntimeError("代理端口范围必须在 1-65535 之间")
        settings["proxy_port"] = args.port
        changed = True
    if args.api_port is not None:
        if not (1 <= args.api_port <= 65535):
            raise RuntimeError("API 端口范围必须在 1-65535 之间")
        settings["api_port"] = args.api_port
        changed = True
    if args.exclude is not None:
        items = [x.strip().upper() for x in args.exclude.split(",") if x.strip()]
        settings["excluded_countries"] = items
        changed = True

    if settings["proxy_port"] == settings["api_port"]:
        raise RuntimeError("代理端口与 API 控制端口不能相同")

    if changed:
        save_settings(settings)
        print("配置已保存至: {}".format(CONFIG_JSON_PATH))
        if sub_updated and settings["sub_url"] and not args.no_fetch:
            fetch_and_patch_config(settings)
            if os.path.isfile(CACHE_PATH):
                os.remove(CACHE_PATH)
            if read_pid():
                print("正在重启 mihomo 以加载新机场节点...")
                stop_mihomo(quiet=True)
                start_mihomo(settings)
                select_best_node(settings, top_n=4, use_cache=False)
        elif read_pid() and (args.port is not None or args.api_port is not None):
            print("提示: 端口已变更，请重新执行 `vpn off && vpn on` 生效。")

    sub_display = settings.get("sub_url") or "(未配置)"
    if not args.show_raw:
        sub_display = mask_url(settings.get("sub_url", ""))

    print("当前配置:")
    print("  sub_url            : {}".format(sub_display))
    print("  proxy_port         : {}".format(settings["proxy_port"]))
    print("  api_port           : {}".format(settings["api_port"]))
    print("  excluded_countries : {}".format(",".join(settings["excluded_countries"]) or "(无)"))


def show_logs(lines=40):
    if not os.path.isfile(LOG_PATH):
        print("暂无日志文件: {}".format(LOG_PATH))
        return
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    for line in all_lines[-lines:]:
        sys.stdout.write(line)


def build_parser():
    parser = argparse.ArgumentParser(description="跨平台 CLI VPN 自动化控制 (macOS & Linux)")
    sub = parser.add_subparsers(dest="action")

    p_on = sub.add_parser("on", help="启动服务并自动选择最快海外节点")
    p_on.add_argument("-p", "--pass", dest="password", help="内置加密机场包 (bundle.enc) 的解密密码")
    p_on.add_argument("--top", type=int, default=4, help="测速候选节点数量 (默认 4)")
    p_on.add_argument("--force", action="store_true", help="忽略缓存，强制重新测速")
    p_on.add_argument("--sub-url", help="设置并保存机场订阅链接（支持 Clash YAML / Base64 / 本地文件）")

    sub.add_parser("off", help="停止后台 mihomo 服务")

    p_best = sub.add_parser("best", help="重新测速并切换至当前最快节点")
    p_best.add_argument("--top", type=int, default=4, help="测速候选节点数量 (默认 4)")

    p_update = sub.add_parser("update", help="强制拉取最新机场订阅并重新测速选节点")
    p_update.add_argument("--top", type=int, default=4, help="测速候选节点数量 (默认 4)")
    p_update.add_argument("--sub-url", help="更新并保存机场订阅链接")

    sub.add_parser("status", help="查看当前运行状态与出口 IP")

    p_unlock = sub.add_parser("unlock", help="使用密码解锁内置加密机场包 (bundle.enc)")
    p_unlock.add_argument("-p", "--pass", dest="password", help="解密密码")

    p_bundle = sub.add_parser("bundle", help="将当前机场节点加密打包为 bundle.enc")
    p_bundle.add_argument("-p", "--pass", dest="password", help="设置加密密码")
    p_bundle.add_argument("-o", "--output", help="输出文件路径 (默认: ~/.cli-vpn/bundle.enc)")

    p_cfg = sub.add_parser("config", help="查看或修改本地配置（订阅链接、端口、排除地区）")
    p_cfg.add_argument("--sub-url", help="设置并立即拉取新机场订阅链接")
    p_cfg.add_argument("--no-fetch", action="store_true", help="仅保存订阅链接，暂不拉取")
    p_cfg.add_argument("--port", type=int, help="设置本地 HTTP/SOCKS5 混合代理端口 (默认 7890)")
    p_cfg.add_argument("--api-port", type=int, help="设置 mihomo 控制 API 端口 (默认 9090)")
    p_cfg.add_argument("--exclude", help="排除国家/地区代码，逗号分隔 (默认 CN,HK,TW；传空字符串不排除)")
    p_cfg.add_argument("--show-raw", action="store_true", help="显示完整未脱敏的订阅链接")

    p_logs = sub.add_parser("logs", help="查看 mihomo 运行日志")
    p_logs.add_argument("-n", "--lines", type=int, default=40, help="显示最后 N 行 (默认 40)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    action = args.action or "status"
    settings = load_settings()

    try:
        if action == "on":
            freshly_loaded = require_config_ready(
                settings,
                cli_sub_url=getattr(args, "sub_url", None),
                password=getattr(args, "password", None),
            )
            refreshed = False if freshly_loaded else maybe_refresh_old_config(settings)
            if (freshly_loaded or refreshed) and read_pid():
                stop_mihomo(quiet=True)
            start_mihomo(settings)
            select_best_node(
                settings,
                top_n=args.top,
                use_cache=not (args.force or freshly_loaded or refreshed),
            )
        elif action == "update":
            if getattr(args, "sub_url", None):
                settings["sub_url"] = args.sub_url.strip()
                save_settings(settings)
            if not settings.get("sub_url"):
                raise RuntimeError("未配置订阅链接，请执行: vpn update --sub-url \"https://你的订阅链接\"")
            fetch_and_patch_config(settings)
            if read_pid():
                stop_mihomo(quiet=True)
            start_mihomo(settings)
            select_best_node(settings, top_n=args.top, use_cache=False)
        elif action == "best":
            require_config_ready(settings)
            start_mihomo(settings)
            select_best_node(settings, top_n=args.top, use_cache=False)
        elif action == "unlock":
            unlock_bundle(settings, password=getattr(args, "password", None))
            if read_pid():
                stop_mihomo(quiet=True)
        elif action == "bundle":
            create_bundle(
                settings,
                password=getattr(args, "password", None),
                out_path=getattr(args, "output", None),
            )
        elif action == "off":
            stop_mihomo()
        elif action == "status":
            show_status(settings)
        elif action == "config":
            handle_config(args, settings)
        elif action == "logs":
            show_logs(lines=args.lines)
        else:
            parser.print_help()
    except Exception as e:
        print("错误: {}".format(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
