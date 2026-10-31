#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ctsonar 文章证据图 x6 (1200x675) — 内容来自真实输出, 主机名已脱敏
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·✅❌①②③④⑤⑥⑦⑧⑨⑩' for ch in t)

def shot(name, lines, title="dev — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57"); d.ellipse([44, 15, 56, 27], fill="#febc2e"); d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 74
    for text, color, size, mono in lines:
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.72)
    img.save(os.path.join(OUT, name + ".png"))
    print(name, "OK")

# 1. 真机盘点 (真实 scan 输出, 主机名脱敏, 行有取舍)
shot("ct-shot-1-scan", [
    ("$ python3 ctsonar.py scan --include-local", WHITE, 24, True),
    ("ctsonar v1.0.0 · demo-mac.local · 2026-10-31T10:29:43", GREEN, 22, True),
    ("监听 80 个：P0/P1 高危 22 · P2 中危 10 · P3 本机 48", WHITE, 22, False),
    ("------------------------------------------------------------------------", GREY, 18, True),
    ("!! *:8091  [全网卡] P0 java · 管理台特征「keycloak」", RED, 21, False),
    ("!! *:10050 [全网卡] P0 unified-zabbix-agent · 管理台特征「zabbix」", RED, 21, False),
    ("!! *:5001  [全网卡] P1 python3.1 · 未识别服务（进程不在常见名单）", GOLD, 21, False),
    ("!! *:61856 [全网卡] P2 rapportd · macOS 系统自带服务", GREY, 21, False),
    ("   127.0.0.1:62160 [本机] P3 java · 管理台特征「keycloak」", GREY, 21, False),
    ("------------------------------------------------------------------------", GREY, 18, True),
    ("!! 高危 22 个（详见上表）—— 状态已写 ctsonar-state.json（+sha256 边车）", RED, 21, False),
    ("", None, 0, True),
    ("# 80 个监听一次盘点，每一行都带暴露档和 P 级，不再是一屏裸端口", GREY, 21, False),
])

# 2. 分类分层规则 (真实 classify 输出: 同一服务换卡听, P 级完全不同)
shot("ct-shot-2-tiers", [
    ("127.0.0.1:6379  [本机] P3 redis-server", GREEN, 22, False),
    ("*:6379          [全网卡] P0 redis-server   # 数据库特征", RED, 22, False),
    ("", None, 0, True),
    ("*:443           [全网卡] P2 nginx          # 常态，不稀释高危", WHITE, 22, False),
    ("*:9418          [全网卡] P1 mystery        # 未识别服务（进程不在常见名单）", GOLD, 21, False),
    ("", None, 0, True),
    ("192.168.1.5:5432 [内网] P1 postgres       # 内网档的数据库=经典内渗入口", GOLD, 21, False),
    ("", None, 0, True),
    ("# 四档暴露 × 服务画像 = P0-P3，纯函数查表，同输入必同输出", GREY, 21, False),
    ("# 陌生进程全网卡监听=P1：不认识的程序开着门，最该看一眼", GREY, 21, False),
])

# 3. diff 抓重绑升级 (e2e STEP7 实弹真实输出)
shot("ct-shot-3-rebind", [
    ("# 昨晚: python3 -m http.server 8631 --bind 127.0.0.1   今天: 忘了 --bind", GREY, 20, False),
    ("", None, 0, True),
    ("$ ctsonar.py diff baseline.json rebind.json; echo exit=$?", WHITE, 22, True),
    ("------------------------------------------------------------------------", GREY, 18, True),
    ("[~] 暴露面升级：127.0.0.1:8631 [本机] P3 Python", RED, 21, False),
    ("    -> *:8631 [全网卡] P0 Python（同服务同端口，换了张卡听）", RED, 21, False),
    ("------------------------------------------------------------------------", GREY, 18, True),
    ("!! 裁决：高危变化 x1 —— 这台机器的门口变多了，先弄清是谁开的。", RED, 21, False),
    ("exit=1", WHITE, 26, True),
    ("", None, 0, True),
    ("# 同端口的「删+增」会配成一条升级事件，绝不误报", GREY, 21, False),
])

# 4. diff 计划内下线 (e2e STEP5 真实输出)
shot("ct-shot-4-removal", [
    ("$ ctsonar.py diff baseline.json after.json --machine | python3 -m json.tool", WHITE, 21, True),
    ("{", GREY, 20, True),
    ('  \"verdict\": \"无高危变化\",', GREEN, 20, True),
    ('  \"added\": [],', GREY, 20, True),
    ('  \"removed\": [', GREY, 20, True),
    ('    \"已下线：127.0.0.1:8631 [本机] P3 Python\"', WHITE, 20, True),
    ("  ],", GREY, 20, True),
    ('  \"rebind\": []', GREY, 20, True),
    ("}", GREY, 20, True),
    ("exit=0", GREEN, 24, True),
    ("", None, 0, True),
    ("# 计划内下线只记录不定罪；退出码 0/1/2/3/4 直接接告警链", GREY, 21, False),
])

# 5. selftest 全绿 (真实输出)
shot("ct-shot-5-selftest", [
    ("$ python3 ctsonar.py selftest", WHITE, 24, True),
    ("PASS redis_wildcard_P0", GREEN, 20, True),
    ("PASS diff_rebind_not_add_rm", GREEN, 20, True),
    ("PASS diff_add_lan_db_HIGH", GREEN, 20, True),
    ("PASS tamper_detected", GREEN, 20, True),
    ("PASS macos_benign_dynamic_port", GREEN, 20, True),
    ("PASS snapshot_keys_whitelist", GREEN, 20, True),
    ("------------------------------------------------------------", GREY, 18, True),
    ("selftest: 35/35 绿", WHITE, 26, True),
    ("", None, 0, True),
    ("# 离线纯函数自测：不 bind 端口、不发网络包，CI 可直接跑", GREY, 21, False),
])

# 6. cron + 防篡改 (README 真实可跑命令 + verify/篡改行为)
shot("ct-shot-6-cron", [
    ("$ crontab -l", GREY, 22, True),
    ("# 每天早 8 点盘点 + 和昨天对比，高危变化退出码 1 触发告警", GREY, 20, False),
    ("0 8 * * * cd /var/lib/ctsonar && cp state.json state.json.old && \\", WHITE, 20, True),
    ("  python3 /opt/ctsonar/ctsonar.py scan --out state.json --no-packages && \\", WHITE, 20, True),
    ("  python3 /opt/ctsonar/ctsonar.py diff state.json.old state.json", WHITE, 20, True),
    ("", None, 0, True),
    ("$ ctsonar.py verify state.json", WHITE, 22, True),
    ("OK state.json 完整性与分层均通过（生成于 2026-10-31，监听 80 个）", GREEN, 20, False),
    ("", None, 0, True),
    ("# 手改状态文件再 diff？SHA256 边车对不上，exit 3 拒判", GREY, 21, False),
])

print("ALL DONE")
