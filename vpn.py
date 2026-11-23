#!/usr/bin/env python3
"""Cross-platform CLI VPN controller (macOS & Linux) powered by mihomo.

Fetches Clash subscription, runs mihomo in localhost-only global mode,
verifies non-CN/HK/TW exit IP, benchmarks download speed, and switches to the fastest node.
"""

import argparse
import concurrent.futures
import json
import os
import platform
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

BASE_DIR = os.path.abspath(
    os.environ.get("CLI_VPN_HOME") or os.path.dirname(os.path.abspath(__file__))
)
RUNTIME_DIR = os.path.join(BASE_DIR, "runtime")
CONFIG_JSON_PATH = os.path.join(BASE_DIR, "config.json")
MIHOMO_CONFIG_PATH = os.path.join(RUNTIME_DIR, "config.yaml")
PID_PATH = os.path.join(RUNTIME_DIR, "mihomo.pid")
LOG_PATH = os.path.join(RUNTIME_DIR, "mihomo.log")
CACHE_PATH = os.path.join(RUNTIME_DIR, "last_best.json")
PROXY_ADDR_PATH = os.path.join(RUNTIME_DIR, "proxy_addr")

DEFAULT_SETTINGS = {
    "sub_url": "",
    "proxy_port": 7890,
    "api_port": 9090,
    "sub_max_age_hours": 12,
    "best_cache_minutes": 60,
    "excluded_countries": ["CN", "HK", "TW"],
}

IGNORED_TYPES = {
    "Direct",
    "Reject",
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
    "expire",
    "traffic",
)
COUNTRY_NAME_HINTS = {
    "CN": ("中国", "国内", "回国", "china"),
    "HK": ("香港", "hongkong", "hong kong", "hk"),
    "TW": ("台湾", "台灣", "taiwan", "tw"),
}

NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def ensure_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


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


def require_sub_url(settings, cli_sub_url=None):
    if cli_sub_url:
        settings["sub_url"] = cli_sub_url.strip()
        save_settings(settings)
        return settings["sub_url"]

    if settings.get("sub_url"):
        return settings["sub_url"]

    if sys.stdin.isatty():
        try:
            entered = input("请输入 Clash 订阅链接 (SUB_URL): ").strip()
        except (EOFError, KeyboardInterrupt):
            entered = ""
        if entered:
            settings["sub_url"] = entered
            save_settings(settings)
            print("已保存订阅链接到 {}".format(CONFIG_JSON_PATH))
            return entered

    raise RuntimeError(
        "未配置订阅链接，请先运行:\n  vpn config --sub-url \"https://你的订阅地址\""
    )


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
    hint = "brew install mihomo 或重新运行 install.sh" if sys_name == "Darwin" else "重新运行 install.sh 自动下载 mihomo"
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


def http_get_direct(url, timeout=20, user_agent="clash-verge/v2.5.10"):
    if shutil.which("curl"):
        cmd = [
            "curl",
            "-fsSL",
            "--noproxy",
            "*",
            "-A",
            user_agent,
            "--max-time",
            str(timeout),
            url,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, env=clean_proxy_env())
        if res.returncode == 0 and res.stdout:
            return res.stdout
        err_msg = res.stderr.strip()
    else:
        err_msg = "未安装 curl"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        ctx = ssl.create_default_context()
        https_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),
        )
        with https_opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        raise RuntimeError("直连请求失败 ({}): {}".format(err_msg or "urllib", e))


def fetch_and_patch_config(settings):
    ensure_dirs()
    sub_url = settings["sub_url"]
    proxy_port = int(settings["proxy_port"])
    api_port = int(settings["api_port"])

    print("[1/4] 正在拉取订阅配置...")
    raw_yaml = http_get_direct(sub_url, timeout=20)

    try:
        cfg = yaml.safe_load(raw_yaml)
    except Exception as e:
        raise RuntimeError("解析订阅 YAML 失败: {}".format(e))

    if not isinstance(cfg, dict) or "proxies" not in cfg:
        raise RuntimeError(
            "订阅返回内容不是有效的 Clash YAML 配置（请确认提供的是 Clash/Mihomo 订阅链接）"
        )

    # Force clean localhost-only global mode for CLI proxy usage
    cfg["mode"] = "global"
    cfg["mixed-port"] = proxy_port
    cfg["allow-lan"] = False
    cfg["external-controller"] = "127.0.0.1:{}".format(api_port)
    cfg["log-level"] = "warning"
    cfg.pop("secret", None)
    cfg["tun"] = {"enable": False}
    # Global mode does not use rules; clearing them avoids slow GeoSite/GeoIP downloads on first start
    cfg["rules"] = []
    cfg.pop("rule-providers", None)
    cfg.pop("geox-url", None)
    cfg["geodata-mode"] = False

    with open(MIHOMO_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
    os.chmod(MIHOMO_CONFIG_PATH, 0o600)
    write_proxy_addr(proxy_port)
    print("      订阅已更新，共 {} 个节点".format(len(cfg.get("proxies", []))))


def patch_ports_in_existing_config(settings):
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
        if cfg.get("mixed-port") != proxy_port or cfg.get("external-controller") != expected_ctrl:
            cfg["mixed-port"] = proxy_port
            cfg["external-controller"] = expected_ctrl
            with open(MIHOMO_CONFIG_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
            os.chmod(MIHOMO_CONFIG_PATH, 0o600)
    except Exception:
        pass


def start_mihomo(settings):
    proxy_port = int(settings["proxy_port"])
    api_port = int(settings["api_port"])
    write_proxy_addr(proxy_port)

    pid = read_pid()
    if pid:
        return pid

    if not os.path.isfile(MIHOMO_CONFIG_PATH):
        fetch_and_patch_config(settings)
    else:
        patch_ports_in_existing_config(settings)

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
    if any(kw in lower for kw in INFO_KEYWORDS):
        return False
    if excluded_hints and any(h in lower for h in excluded_hints):
        return False
    return True


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


def switch_global(api_port, name):
    api_request(api_port, "/proxies/GLOBAL", method="PUT", data={"name": name}, timeout=3)


def get_direct_ip():
    for url in ("https://ipinfo.io/ip", "https://api.ip.sb/ip"):
        try:
            out = http_get_direct(url, timeout=4, user_agent="curl/8.0").strip()
            if out and len(out) < 64:
                return out
        except Exception:
            continue
    return None


def proxy_http_get(proxy_url, url, timeout=4):
    if shutil.which("curl"):
        cmd = [
            "curl",
            "-fsSL",
            "--max-time",
            str(timeout),
            "-x",
            proxy_url,
            url,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, env=clean_proxy_env())
        if res.returncode == 0 and res.stdout:
            return res.stdout
        return None

    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception:
        return None


def check_exit_ip(proxy_url):
    endpoints = [
        ("https://ipinfo.io/json", "ip", "country"),
        ("https://api.ip.sb/geoip", "ip", "country_code"),
    ]
    for url, ip_key, cc_key in endpoints:
        raw = proxy_http_get(proxy_url, url, timeout=3)
        if not raw:
            continue
        try:
            data = json.loads(raw)
            ip = data.get(ip_key)
            country = (data.get(cc_key) or "").upper()
            if ip and country:
                return ip, country
        except json.JSONDecodeError:
            continue
    return None, None


def measure_download_speed(proxy_url):
    test_url = "https://speed.cloudflare.com/__down?bytes=2000000"
    if shutil.which("curl"):
        cmd = [
            "curl",
            "-s",
            "-o",
            os.devnull,
            "--max-time",
            "4",
            "-x",
            proxy_url,
            "-w",
            "%{speed_download}",
            test_url,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, env=clean_proxy_env())
        if res.returncode != 0:
            return 0.0
        try:
            bps = float(res.stdout.strip())
            return bps / (1024 * 1024)
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
    excluded_countries = {c.upper() for c in settings.get("excluded_countries", ["CN", "HK", "TW"])}
    excluded_hints = build_excluded_hints(excluded_countries)

    data = api_request(api_port, "/proxies", timeout=5)
    proxies = data.get("proxies", {})
    global_group = proxies.get("GLOBAL", {})
    all_names = global_group.get("all", list(proxies.keys()))

    if use_cache:
        cached = load_cached_best(cache_seconds)
        if cached and cached.get("node") in proxies:
            switch_global(api_port, cached["node"])
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
        if name in proxies and is_candidate_node(name, proxies[name], excluded_hints)
    ]
    if not candidates:
        raise RuntimeError("未找到可用代理节点")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(test_node_delay, api_port, name) for name in candidates]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res is not None:
                results.append(res)

    if not results:
        raise RuntimeError("所有节点延迟测试均超时，请检查网络连接")

    results.sort(key=lambda x: x[1])
    print(
        "      延迟测试完成（共 {} 个可用节点），开始校验出口 IP 并测速（最多取 {} 个）...".format(
            len(results), top_n
        )
    )

    print("[3/4] 逐个校验出口 IP 归属地与实测带宽:")
    direct_ip = get_direct_ip()
    bad_ips = {direct_ip} if direct_ip else set()
    verified = []
    for name, delay in results:
        if len(verified) >= top_n:
            break
        switch_global(api_port, name)
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
    switch_global(api_port, best_name)
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
    print("运行目录: {} ({} {})".format(BASE_DIR, platform.system(), platform.machine()))
    print("订阅配置: {}".format(mask_url(settings.get("sub_url", ""))))
    print("本地端口: HTTP/SOCKS5 127.0.0.1:{} | API 127.0.0.1:{}".format(proxy_port, api_port))

    if not pid:
        print("mihomo 状态: 未运行")
        return

    try:
        g = api_request(api_port, "/proxies/GLOBAL", timeout=2)
        now = g.get("now", "未知")
        ip, country = check_exit_ip(proxy_url)
        print("mihomo 状态: 运行中 (PID {})".format(pid))
        print("当前节点: {}".format(now))
        print("当前出口: {} [{}]".format(ip or "未知", country or "未知"))
    except Exception as e:
        print("mihomo 状态: 运行中 (PID {})，但 API 查询失败: {}".format(pid, e))


def ensure_fresh_config(settings):
    max_age_sec = int(settings.get("sub_max_age_hours", 12)) * 3600
    if not os.path.isfile(MIHOMO_CONFIG_PATH):
        require_sub_url(settings)
        fetch_and_patch_config(settings)
        return True

    age = time.time() - os.path.getmtime(MIHOMO_CONFIG_PATH)
    if age > max_age_sec and settings.get("sub_url"):
        print("订阅配置已超过 {} 小时，尝试自动更新...".format(max_age_sec // 3600))
        try:
            fetch_and_patch_config(settings)
            return True
        except Exception as e:
            print("自动更新订阅失败（{}），将继续使用现有配置。".format(e))
    return False


def handle_config(args, settings):
    changed = False
    if args.sub_url is not None:
        settings["sub_url"] = args.sub_url.strip()
        changed = True
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
        if read_pid() and (args.port is not None or args.api_port is not None):
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
    p_on.add_argument("--top", type=int, default=4, help="测速候选节点数量 (默认 4)")
    p_on.add_argument("--force", action="store_true", help="忽略缓存，强制重新测速")
    p_on.add_argument("--sub-url", help="设置并保存 Clash 订阅链接")

    sub.add_parser("off", help="停止后台 mihomo 服务")

    p_best = sub.add_parser("best", help="重新测速并切换至当前最快节点")
    p_best.add_argument("--top", type=int, default=4, help="测速候选节点数量 (默认 4)")

    p_update = sub.add_parser("update", help="强制拉取最新订阅并重新测速选节点")
    p_update.add_argument("--top", type=int, default=4, help="测速候选节点数量 (默认 4)")
    p_update.add_argument("--sub-url", help="更新并保存 Clash 订阅链接")

    sub.add_parser("status", help="查看当前运行状态与出口 IP")

    p_cfg = sub.add_parser("config", help="查看或修改本地配置（订阅链接、端口、排除地区）")
    p_cfg.add_argument("--sub-url", help="设置 Clash 订阅链接")
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
            if getattr(args, "sub_url", None):
                require_sub_url(settings, args.sub_url)
            elif not os.path.isfile(MIHOMO_CONFIG_PATH):
                require_sub_url(settings)
            updated = ensure_fresh_config(settings)
            if updated and read_pid():
                stop_mihomo(quiet=True)
            start_mihomo(settings)
            select_best_node(settings, top_n=args.top, use_cache=not (args.force or updated))
        elif action == "update":
            require_sub_url(settings, getattr(args, "sub_url", None))
            fetch_and_patch_config(settings)
            if read_pid():
                stop_mihomo(quiet=True)
            start_mihomo(settings)
            select_best_node(settings, top_n=args.top, use_cache=False)
        elif action == "best":
            start_mihomo(settings)
            select_best_node(settings, top_n=args.top, use_cache=False)
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
