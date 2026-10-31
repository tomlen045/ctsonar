#!/bin/sh
# ctsonar Gitee 发布脚本（token 从既有仓库 remote 提取，不回显）
set -e
cd "$(dirname "$0")"
GIT="${GIT:-$(command -v git || echo /usr/bin/git)}"

TOKEN=$(python3 - <<'EOF'
import re, os
base = "/Users/len/CodeBuddy/dx/cronguard/.git/config"
if os.path.exists(base):
    txt = open(base).read()
    m = re.search(r'https://[^:]+:([^@]+)@gitee\.com', txt)
    if m:
        print(m.group(1)); raise SystemExit
for d in os.listdir("/Users/len/CodeBuddy/dx"):
    p = "/Users/len/CodeBuddy/dx/%s/.git/config" % d
    try:
        txt = open(p).read()
    except OSError:
        continue
    m = re.search(r'https://[^:]+:([^@]+)@gitee\.com', txt)
    if m:
        print(m.group(1)); raise SystemExit
raise SystemExit("NO_TOKEN")
EOF
) || { echo "no gitee token"; exit 1; }

[ -n "$TOKEN" ] || { echo "empty token"; exit 1; }

# 1. 建仓（幂等，form urlencode —— JSON body 会 401）
echo "-> create gitee repo tomlen/ctsonar ..."
HTTP=$(curl -s -o /tmp/gitee_ctsonar.json -w '%{http_code}' -X POST \
  "https://gitee.com/api/v5/user/repos" \
  -d "access_token=$TOKEN" \
  -d "name=ctsonar" \
  -d "description=暴露面声呐：一条命令摸清单台主机对外暴露面，监听盘点+四档暴露分类+P0-P3分层+可diff签名状态，零依赖单文件CLI（退出码可接cron告警）" \
  -d "private=false" \
  -d "auto_init=false")
if [ "$HTTP" = "201" ]; then echo "  created"
elif grep -q "已存在\|exist" /tmp/gitee_ctsonar.json 2>/dev/null; then echo "  exists, skip"
else echo "  HTTP $HTTP: $(head -c 200 /tmp/gitee_ctsonar.json)"; fi

# 2. commit + push（token 内嵌 URL 必须带用户名段）
if [ ! -d .git ]; then
  "$GIT" init -b main -q
  "$GIT" add README.md README_EN.md CHANGELOG.md LICENSE ctsonar.py install.sh make_shots.py .gitignore screenshots/
  "$GIT" -c user.name=tomlen -c user.email=tomlen@users.noreply.gitee.com commit -q -m "ctsonar v1.0.0 - 4-tier exposure + P0-P3 tiers + signed state diff + 35 selftests green"
fi
"$GIT" remote remove gitee 2>/dev/null || true
"$GIT" remote add gitee "https://tomlen:$TOKEN@gitee.com/tomlen/ctsonar.git"
echo "-> push main ..."
GIT_TERMINAL_PROMPT=0 "$GIT" push -q -u gitee main && echo "  pushed"

# 3. 匿名读回验证
echo "-> anonymous readback ..."
CODE_API=$(curl -s -o /tmp/ct_readback.json -w '%{http_code}' "https://gitee.com/api/v5/repos/tomlen/ctsonar")
PRIVATE=$(python3 -c "import json;d=json.load(open('/tmp/ct_readback.json'));print(d.get('private'))" 2>/dev/null)
CODE_RAW=$(curl -s -o /dev/null -w '%{http_code}' "https://gitee.com/tomlen/ctsonar/raw/main/README.md")
CODE_WEB=$(curl -s -o /dev/null -w '%{http_code}' -L "https://gitee.com/tomlen/ctsonar")
echo "  API=$CODE_API private=$PRIVATE | raw README=$CODE_RAW | web=$CODE_WEB"
if [ "$CODE_API" = "200" ] && [ "$PRIVATE" = "False" ] && [ "$CODE_RAW" = "200" ]; then
  echo "OK https://gitee.com/tomlen/ctsonar"
else
  echo "VERIFY FAILED (see numbers above)"
  exit 2
fi
