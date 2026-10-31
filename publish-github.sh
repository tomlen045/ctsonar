#!/bin/sh
# ctsonar GitHub 镜像发布（token 从钥匙串读，不回显）
set -e
cd "$(dirname "$0")"
GIT=/Applications/Xcode.app/Contents/Developer/usr/bin/git

GH_TOKEN=$(security find-generic-password -s GH_TOKEN -w 2>/dev/null)
[ -n "$GH_TOKEN" ] || { echo "no GH_TOKEN in keychain"; exit 1; }

# 1. 建仓（幂等）
echo "-> create github repo tomlen045/ctsonar ..."
HTTP=$(curl -s -o /tmp/gh_ctsonar.json -w '%{http_code}' \
  -H "Authorization: token $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d '{"name":"ctsonar","description":"ctsonar - exposure sonar in one file: inventory listening sockets, 4-tier exposure classes, P0-P3 risk tiers, signed state diff for cron. Zero dependencies.","has_wiki":false,"private":false}')
if [ "$HTTP" = "201" ]; then echo "  created"
elif [ "$HTTP" = "422" ]; then echo "  exists, skip"
else echo "  HTTP $HTTP: $(head -c 200 /tmp/gh_ctsonar.json)"; exit 1; fi

# 2. 推送（SSH 443 绕墙）
if ! "$GIT" remote get-url github >/dev/null 2>&1; then
  "$GIT" remote add github git@ssh.github.com:tomlen045/ctsonar.git
fi
echo "-> push main ..."
GIT_SSH_COMMAND="ssh -p 443 -i $HOME/.ssh/id_ed25519_github -o StrictHostKeyChecking=accept-new" \
  "$GIT" push -u github main && echo "  pushed"

# 3. About 描述
curl -s -o /dev/null -X PATCH \
  -H "Authorization: token $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/tomlen045/ctsonar \
  -d '{"description":"ctsonar - exposure sonar in one file: inventory listening sockets, 4-tier exposure classes, P0-P3 risk tiers, signed state diff for cron. Zero dependencies.","homepage":""}'

# 4. 验证
sleep 3
CODE_API=$(curl -s -o /tmp/gh_ct_read.json -w '%{http_code}' \
  -H "Authorization: token $GH_TOKEN" https://api.github.com/repos/tomlen045/ctsonar)
CODE_RAW=$(curl -s -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/tomlen045/ctsonar/main/README.md)
CODE_CDN=$(curl -s -o /dev/null -w '%{http_code}' https://gcore.jsdelivr.net/gh/tomlen045/ctsonar@main/README.md)
echo "  API=$CODE_API | raw README=$CODE_RAW | gcore CDN=$CODE_CDN"
if [ "$CODE_API" = "200" ] && [ "$CODE_RAW" = "200" ]; then
  echo "OK https://github.com/tomlen045/ctsonar"
else
  echo "VERIFY FAILED"
  exit 2
fi
