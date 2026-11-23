# cli-vpn

轻量、无 GUI 依赖的命令行自动代理工具，同时支持 **macOS**（Apple Silicon / Intel）与 **Linux**（`x86_64` / `arm64` / `armv7`），支持 `bash` 与 `zsh`。

内置经 PBKDF2 + HMAC-SHA256 认证加密的机场节点包（`bundle.enc`），新机器安装时只需输入简短解密密码即可直接解锁全部节点，**无需在新机器上拉取机场订阅链接**，同时防止公开仓库被爬虫盗刷流量。

---

## 一键安装

### 方式一：一行命令带密码直接解锁（推荐，全程免交互）
```bash
curl -fsSL https://raw.githubusercontent.com/deadpoppy/cli-vpn/main/install.sh | bash -s -- -p <解密密码>
```

### 方式二：交互式安装（按提示输入解密密码）
```bash
curl -fsSL https://raw.githubusercontent.com/deadpoppy/cli-vpn/main/install.sh | bash
```

安装完成后让当前终端立即生效并启动：
```bash
source ~/.cli-vpn/vpn_env.sh && vpn on
```

---

## 日常使用

```bash
vpn on          # 启动后台服务，自动优选最快海外节点并开启当前终端代理（1 小时内复用最优缓存）
vpn off         # 关闭当前终端代理并停止后台 mihomo 服务
vpn best        # 忽略缓存，立即重新测延迟 + 校验出口 IP + 测带宽并切换最快节点
vpn status      # 查看服务状态、当前节点、真实出口 IP 与当前终端环境变量状态
vpn env-on      # 仅在当前新开的终端开启代理环境变量（后台服务已运行时使用）
vpn env-off     # 仅在当前终端关闭代理环境变量（保持后台服务继续给其他终端用）
vpn update      # 强制拉取最新订阅配置并重选最快节点
vpn logs        # 查看 mihomo 运行日志
```

---

## 更换其他机场 / 修改配置

同时支持 **Clash YAML 订阅**、通用面板订阅（自动补全 `?flag=clash`）、**Base64 / V2Ray / SS / Trojan / Hysteria2 URI 订阅**以及本地 `.yaml` 文件（若新机场域名被墙，会自动尝试通过已有代理拉取）：

```bash
# 切换并立即拉取新机场订阅
vpn update --sub-url "https://新的机场订阅链接"

# 当默认端口 7890 / 9090 被其他程序占用时修改端口
vpn config --port 7891 --api-port 9091

# 自定义排除的国家/地区代码（默认 CN,HK,TW；例如允许香港节点只排除中国大陆）
vpn config --exclude "CN"

# 重新把当前机场最新节点加密打包为 bundle.enc（方便更新回仓库）
vpn bundle -p <解密密码> -o ./bundle.enc
```

---

## 一键卸载

```bash
vpn uninstall
```
