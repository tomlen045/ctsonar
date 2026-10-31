#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ctsonar 公众号封面 900x383 — 对话钩子形态（A线，不晒星数）
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 900, 383
BG_TOP, BG_BOT = (11, 14, 26), (26, 15, 46)
GOLD = (240, 180, 41)
WHITE = (255, 255, 255)
GREY = (139, 148, 158)
RED = (248, 81, 73)

CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
MONO = "/System/Library/Fonts/Menlo.ttc"

img = Image.new("RGB", (W, H))
d = ImageDraw.Draw(img)
for y in range(H):
    t = y / H
    d.line([(0, y), (W, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOT)))

F = lambda size, mono=False: ImageFont.truetype(MONO if mono else CJK, size)

# 左金竖条锚
d.rectangle([42, 64, 50, 318], fill=GOLD)

# 栏目标签（金）
d.text((72, 62), "我是小薅薅 · 自研工具", font=F(19), fill=GOLD)

# 主钩子两行（白大字）
d.text((72, 108), "你的服务器开了哪些口子", font=F(46), fill=WHITE)
d.text((72, 172), "——现在谁能说得清？", font=F(46), fill=WHITE)

# 金句反驳（金，小字）
d.text((72, 248), "门口变多了，你该第一个知道", font=F(23), fill=GOLD)

# 底部信息条（重点行黑衬底）
d.rectangle([72, 296, 700, 318], fill=(0, 0, 0))
d.text((80, 297), "ctsonar · 四档暴露分类 · P0-P3 分层 · 35 项自测全绿", font=F(17), fill=WHITE)
d.text((72, 336), "本篇命令全部真机实测 · Gitee / GitHub 双仓开源", font=F(16), fill=GREY)

# 右侧数据区（硬指标）
d.text((668, 108), "4", font=F(74, mono=True), fill=GOLD)
d.text((668, 190), "档暴露分类", font=F(22), fill=WHITE)
d.text((790, 108), "35", font=F(74, mono=True), fill=GOLD)
d.text((790, 190), "项自测", font=F(22), fill=WHITE)

here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cover-900x383.png")
img.save(here)
desk = os.path.join(os.path.expanduser("~"), "Desktop", "ctsonar-cover.png")
img.save(desk)
print("saved:", here)
print("saved:", desk)
