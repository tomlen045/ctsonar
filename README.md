# ctsonar

[简体中文](README.md) | [English](README_EN.md)

> **暴露面声呐** — 一条命令摸清单台主机的对外暴露面：监听盘点 + 四档暴露分类 + P0-P3 风险分层 + 可 diff 的签名状态。零依赖单文件。
> 门口变多了，你该第一个知道。

[![release](https://img.shields.io/badge/release-v1.0.0-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![python](https://img.shields.io/badge/python-3.7%2B-informational)]()

## 为什么有这个工具

每台机器都有「门口」：监听着全网卡的端口。但绝大多数机器没有「门口清单」——

服务谁起谁知道，起完就忘。三个月后没人说得清这台机器开着哪些口子、
哪些是当初计划内的、哪些是某个调试会话留下的 `--bind 0.0.0.0`。

`netstat`/`lsof` 只给你事实清单，不给你判断：
哪些口子在公网档？哪些是数据库？跟上周比变了什么？

`ctsonar` 把「看一眼门口」变成一个可以进 cron 的动作：

```bash
python3 ctsonar.py scan --out /var/lib/ctsonar/state.json
python3 ctsonar.py diff /var/lib/ctsonar/state.json.old /var/lib/ctsonar/state.json
echo exit=$?    # 1 = 高危变化
```

## 快速开始

```bash
# 直接跑（零依赖，Python 3.7+ 标准库；macOS 需 lsof，Linux 需 ss 或 netstat）
python3 ctsonar.py scan

# 或一键安装到 /usr/local/bin
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen/ctsonar@main/install.sh | bash
```

## 用法

```bash
# 盘点当前监听面，写状态文件（默认 ./ctsonar-state.json，权限 0600）
ctsonar.py scan [--out 状态文件] [--include-local] [--no-packages]

# 比较两份状态，裁决变化（crontab 友好：退出码 0/1/2/3）
ctsonar.py diff 旧状态 新状态 [--machine]

# 校验状态文件没被手改（SHA256 边车 + 分层重算）
ctsonar.py verify 状态文件

# 离线自测（不 bind、不发网络包）
ctsonar.py selftest
```

输出长这样（真机实录，主机名已脱敏）：

```
ctsonar v1.0.0 · demo-mac.local · 2026-10-31T10:29:43
监听 80 个：P0/P1 高危 22 · P2 中危 10 · P3 本机 48
------------------------------------------------------------------------
!! *:8091  [全网卡] P0 java · 管理台特征「keycloak」
!! *:10050 [全网卡] P0 unified-zabbix-agent · 管理台特征「zabbix」
!! *:5001  [全网卡] P1 python3.1 · 未识别服务（进程不在常见名单）
!! *:61856 [全网卡] P2 rapportd · macOS 系统自带服务
（另有 48 个仅本机回环监听，加 --include-local 查看）
------------------------------------------------------------------------
❌ 高危 22 个（详见上表）—— 状态已写 ctsonar-state.json（+sha256 边车）
```

## 四档暴露分类

| 档 | 监听地址 | 一句话 |
|---|---|---|
| 本机 | 127.0.0.1 / ::1 / localhost | 只有本机能摸，默认最放心的档 |
| 内网 | 10.x / 192.168.x / 172.16-31.x / ULA | 同网段的人都能摸 |
| 全网卡 | `*` / `0.0.0.0` / `::` | 路由器和防火墙之外还有谁在拦，工具不知道 |
| 公网 | 其他具体地址 | 直接当门口处理 |

## P0-P3 分层

| 级别 | 判定 | 典型 |
|---|---|---|
| P0 | 敏感服务（数据库/管理台/文件分享/远控）在全网卡或公网档 | wildcard 上的 redis、grafana、`python -m http.server` |
| P1 | 敏感服务在内网档；陌生进程在全网卡档；公网档一切 | 192.168.x 上的 postgres；不认识的程序在 `*` 上听 |
| P2 | 已知常规服务在全网卡档；系统自带服务；未知地址 | nginx `*:443`（常态，不稀释高危） |
| P3 | 一切只听本机回环的 | 127.0.0.1:xxxx |

分层是纯函数：同输入必同输出。特征库命中（进程名/命令行/容器镜像/端口 hints）
决定「是什么」，暴露档决定「多危险」，两者查表得出 P 级。

## diff 裁决（退出码即告警开关）

| 退出码 | 含义 |
|---|---|
| 0 | 无变化 / 只有收紧类好事 / 高危面消失 |
| 1 | 高危变化：新增 P0/P1 监听、暴露面升级（同服务换了张卡听） |
| 2 | 中危变化：新增 P2 监听 |
| 3 | 状态文件被篡改（SHA256 不符或分层与算法不符），拒判 |
| 4 | 平台不支持 |

重绑识别：同一个 (协议, 端口, 进程) 从 `127.0.0.1` 换到 `*`，
报一条「暴露面升级」，绝不误报成「删一个 + 增一个」。

## 七条不变量

| 不变量 | 承诺 |
|---|---|
| I1 只读侦察 | 不 bind 端口、不发网络包、不杀进程、不改配置 |
| I2 纯函数分层 | 分类与分层同输入必同输出，selftest 离线全量覆盖 |
| I3 签名状态 | 状态文件附 SHA256 边车，verify 重算比对，篡改即拒判 |
| I4 重绑不误报 | 同端口同服务的地址变化是一条升级/收紧事件，不是删+增 |
| I5 机密零落盘 | 状态只记 进程名/端口/地址/暴露档，不记参数里的密钥与 token |
| I6 退出码裁决 | 0/1/2/3/4 语义固定，crontab 直接接告警 |
| I7 未知不拍脑袋 | 无特征的进程归「未知服务」，按暴露档保守分层 |

## 接入 cron

```cron
# 每天早 8 点盘点 + 与昨天对比，有高危变化退出码 1 → 告警链自己接
0 8 * * * cd /var/lib/ctsonar && cp state.json state.json.old && python3 /opt/ctsonar/ctsonar.py scan --out state.json --no-packages; python3 /opt/ctsonar/ctsonar.py diff state.json.old state.json >> ctsonar.log 2>&1
```

## 自测

```bash
python3 ctsonar.py selftest    # 35 项，离线纯函数测试，不碰真实网络
```

## 一句大实话

ctsonar 看的是「谁在本机监听」。它不扫描远程主机（不是 nmap）、不验证服务
漏洞、不判断防火墙外还有没有一层 NAT——「全网卡」档的真实风险取决于你的
网络环境，工具只负责告诉你门口开着，拦不拦得住是防火墙的事。

## 为什么不是另一个工具

- `ss -tlnp` / `lsof -i`：只给事实清单，没有分层、没有画像、没有 diff
- `nmap localhost`：主动发包探测服务指纹，ctsonar 纯读本机内核表，零流量
- lynis / auditd 类主机审计：全家桶，装完一大堆；ctsonar 单文件即走

ctsonar 把「监听事实」变成「分层判断」和「可 diff 的签名状态」。

## License

MIT
