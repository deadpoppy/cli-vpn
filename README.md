# cli-vpn

轻量、无 GUI 依赖的命令行自动代理工具，同时支持 **macOS**（Apple Silicon / Intel）与 **Linux**（`x86_64` / `arm64` / `armv7`），支持 `bash` 与 `zsh`。

底层基于 [mihomo](https://github.com/MetaCubeX/mihomo) 仅监听本机回环地址，自动完成：
1. 拉取并定期自动刷新 Clash 订阅（仅在本地保存，不上传仓库）
2. 并发测试全部候选节点延迟（默认预排除 `CN` / `HK` / `TW`）
3. 逐个校验真实海外出口 IP 归属地（防止直连泄露或假节点）并实测下载带宽
4. 自动切换到实测速度最快的节点，并在当前终端设置 `http_proxy` / `https_proxy` / `all_proxy`

---

## 一键安装

### 交互式安装（安装过程中输入订阅链接）
```bash
curl -fsSL https://raw.githubusercontent.com/deadpoppy/cli-vpn/main/install.sh | bash
```

### 非交互式一键安装（直接附带订阅链接，适合远程服务器）
```bash
curl -fsSL https://raw.githubusercontent.com/deadpoppy/cli-vpn/main/install.sh | bash -s -- --sub-url "https://你的Clash订阅链接"
```

> 安装脚本会自动检测系统与架构，按需安装 `mihomo` 二进制（`~/.cli-vpn/bin/mihomo`）与 Python `PyYAML` 依赖，并自动写入 `~/.zshrc` / `~/.bashrc`。无需 root 权限即可在普通用户目录下运行。

安装完成后让当前终端立即生效：
```bash
source ~/.cli-vpn/vpn_env.sh
```

---

## 日常使用

```bash
vpn on          # 启动后台服务，自动优选最快海外节点并开启当前终端代理（1 小时内复用最优缓存）
vpn off         # 关闭当前终端代理并停止后台 mihomo 服务
vpn best        # 忽略缓存，立即重新测延迟 + 校验出口 IP + 测带宽并切换最快节点
vpn update      # 强制拉取最新订阅配置并重选最快节点
vpn status      # 查看服务状态、当前节点、真实出口 IP 与当前终端环境变量状态
vpn env-on      # 仅在当前新开的终端开启代理环境变量（后台服务已运行时使用）
vpn env-off     # 仅在当前终端关闭代理环境变量（保持后台服务继续给其他终端用）
vpn logs        # 查看 mihomo 运行日志
```

### 修改配置（订阅链接 / 端口 / 排除地区）

本地配置保存在 `~/.cli-vpn/config.json`（权限 `600`）：

```bash
# 更新订阅链接
vpn config --sub-url "https://新的Clash订阅链接"

# 当默认端口 7890 / 9090 被其他程序占用时修改端口
vpn config --port 7891 --api-port 9091

# 自定义排除的国家/地区代码（默认 CN,HK,TW；比如允许香港节点只排除中国大陆）
vpn config --exclude "CN"

# 查看当前配置（默认对订阅链接脱敏，加 --show-raw 显示完整链接）
vpn config
```

---

## 一键卸载

```bash
vpn uninstall
# 或保留本地订阅配置仅卸载程序：
vpn uninstall --keep-config
```
