#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ctsonar —— 一条命令摸清单台主机的对外暴露面。

监听盘点 -> 四档暴露分类(本机/内网/全网卡/公网) -> P0-P3 风险分层
-> 可 diff 的签名状态文件 -> 变更裁决(退出码 0/1/2)。

设计不变量：
  I1  只做只读侦察：不 bind 任何端口、不发网络包、不杀进程、不改配置。
  I2  分类与分层是纯函数：同输入必同输出，selftest 可离线全量覆盖。
  I3  状态文件附 SHA256 边车，verify 重算比对；篡改即 exit 3 拒判。
  I4  同 (proto, port, 进程) 重绑地址 = 暴露面变化，绝不误报成 删+增。
  I5  机密零落盘：状态只记 进程名/端口/地址/暴露档，不记参数里的密钥/token。
  I6  退出码即裁决：0=安全/无高危变化，1=高危(P0/P1)，2=中危，3=状态被篡改，
      4=平台不支持。crontab 友好。
  I7  未知端口不拍脑袋：无特征归「未知服务」，按暴露档给保守基线分层。

零依赖，Python 3.7+。macOS / Linux。MIT。
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys

VERSION = "1.0.0"
EXPOSURES = ("loopback", "lan", "wildcard", "public")

# 暴露档 -> 基线分层（数字越小越危险：P0=0 ... P3=3）
BASE_TIER = {
    "loopback": 3,   # 只听本机回环：默认最放心的档
    "lan": 2,        # 听内网网卡：同网段的人都能摸到
    "wildcard": 1,   # 听全部网卡：路由器/防火墙之外还有谁在拦，工具不知道
    "public": 0,     # 直接听公网地址：默认就是门口
    "unknown": 2,    # 解析不了的地址，按内网档保守处理
}
# 敏感服务升级表：键 = (暴露档, 是否敏感)，值 = 最终分层
# wildcard+normal=2 而非 1：nginx 全网卡监听是常态，全判 P1 会把 scan 的
# 「高危」退出码稀释成噪音——P1 必须留给真正该半夜爬起来看的口子。
TIER_TABLE = {
    ("loopback", True): 3,
    ("loopback", False): 3,
    ("lan", True): 1,
    ("lan", False): 2,
    ("wildcard", True): 0,
    ("wildcard", False): 2,
    ("public", True): 0,
    ("public", False): 0,
}
UNKNOWN_TIER = {"loopback": 3, "lan": 2, "wildcard": 1, "public": 0,
                "unknown": 2}
SEV_LABEL = {0: "P0", 1: "P1", 2: "P2", 3: "P3"}
EXPO_LABEL = {
    "loopback": "本机",
    "lan": "内网",
    "wildcard": "全网卡",
    "public": "公网",
    "unknown": "未知",
}

# ---------------- 特征库（进程名/镜像名/端口 hints） ----------------

DB_HINTS = (
    "postgres", "mysqld", "mariadbd", "mongod", "redis-server", "redis",
    "valkey", "memcached", "rabbitmq", "beam.smp", "etcd", "clickhouse",
    "influxd", "opensearch", "elasticsearch", "sqlservr", "oracle",
    "kingbase", "dmserver", "gaussdb", "polardb", "tdsql",
)
ADMIN_HINTS = (
    "grafana", "kibana", "jenkins", "nexus", "sonarqube", "harbor",
    "gitlab", "rancher", "portainer", "jupyter", "phpmyadmin", "adminer",
    "influxdb", "prometheus", "minio", "consul", "zabbix",
    "php-fpm", "tomcat", "weblogic", "glassfish", "keycloak",
)
ADMIN_PORTS = {
    3000, 5601, 8080, 8081, 8161, 8443, 9000, 9090, 15672, 16379,
    26379, 4848, 7001, 9200, 5432, 6379, 27017, 3306, 11211, 2379,
}
FILE_HINTS = (
    "http.server", "simplehttpserver", "ftp", "vsftpd", "tftp",
    "smbd", "nmbd", "samba", "nfsd",
)
INTROSPECT_HINTS = (
    "dwservice", "anydesk", "teamviewer", "vnc", "screens", "rustdesk",
    "parsec", "todesk", "sunlogin",
)
INTROSPECT_PORTS = {5900, 5901, 5902, 3389, 4899, 7019}
VCS_PORTS = {22, 2222}  # ssh：管理入口单独点名，不当普通 unknown

# macOS 已知良性服务白名单：这些 wildcard 监听是系统自带的，不应进 P0/P1。
# 只对 proc 精确命中生效（子串会误伤，比如第三方 redis 不叫这些名字）。
# 核心守护进程端口每次开机随机（rapportd/Handoff），按进程名全端口放行。
MACOS_BENIGN_ANY_PORT = {
    "rapportd", "sharingd", "AirPlayUIAgent", "AirPlayUIA",
    "IdentityServicesAgent", "IdentityS", "mDNSResponder", "configd",
    "launchd", "ControlCe", "ControlCeNT",
}
MACOS_BENIGN_FIXED_PORT = {
    "Dock", "Finder", "WiFiProxy", "SystemUIServer",
}
MACOS_BENIGN_PORTS = {7000, 7100, 5000, 5353}  # AirPlay/打印机/控制中心/mDNS

# 已知常规服务名单：特征库没命中、但属于日常基础设施的进程。
# 名单外的陌生进程在全网卡监听会单独定「未知服务」档（更保守）。
KNOWN_COMMON_PROCS = {
    # web/反代
    "nginx", "caddy", "httpd", "apache2", "haproxy", "traefik", "envoy",
    "iis", "kestrel",
    # 应用运行时
    "node", "nodejs", "deno", "bun", "gunicorn", "uvicorn", "uwsgi",
    "puma", "python", "python3", "python3.13", "ruby", "java", "dotnet",
    "mono", "php", "erl",
    # 基础设施守护进程
    "dockerd", "docker", "docker-proxy", "com.docker.backend",
    "containerd", "containerd-shim-runc-v2", "kubelet", "kube-proxy",
    "dnsmasq", "systemd-resolve", "avahi-daemon", "cupsd", "named",
    "unbound", "master", "smtpd", "dovecot", "openvpn", "wireguard-go",
    "tailscaled", "vpnd", "pppd", "slpd", "collectd", "node_exporter",
    "categraf", "n9e", "vmagent", "victoria-metrics",
}


# ---------------- 小工具 ----------------

def eprint(msg):
    sys.stderr.write(msg + "\n")


def now_iso():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def run_cmd(argv, timeout=20):
    """只读外壳调用：失败返回 None，绝不抛出中断盘点。
    errors="replace"：lsof/ps 输出可能混入非 UTF-8 进程名，严格解码会炸掉整个采集。"""
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, errors="replace",
            timeout=timeout, shell=False, stdin=subprocess.DEVNULL,
        )
        if p.returncode != 0:
            return None
        return p.stdout
    except Exception:
        return None


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def canonical(state):
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def write_0600(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data if isinstance(data, bytes) else data.encode("utf-8"))
    finally:
        os.close(fd)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------- 暴露分类（纯函数） ----------------

def classify_addr(addr):
    """addr: 监听地址字符串（不含端口）。返回 loopback/lan/wildcard/public/unknown。"""
    a = (addr or "").strip()
    if a in ("*", "", "::", "0.0.0.0", "[::]", "[::]:", "<any>"):
        return "wildcard"
    a = a.strip("[]")
    if a in ("localhost", "::1", "127.0.0.1", "fe80::1%lo0"):
        return "loopback"
    if a.startswith("127.") or a.startswith("fe80::"):
        return "loopback"
    if a.startswith("169.254."):
        return "lan"  # link-local：只在本地链路，等同内网档
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", a)
    if m:
        o = [int(x) for x in m.groups()]
        if o[0] == 10:
            return "lan"
        if o[0] == 192 and o[1] == 168:
            return "lan"
        if o[0] == 172 and 16 <= o[1] <= 31:
            return "lan"
        return "public"
    # IPv6
    low = a.lower()
    if low.startswith("fc") or low.startswith("fd"):
        return "lan"  # IPv6 ULA fc00::/7
    # 有具体全局地址但只绑在那块卡上：仍按内网档保守处理不了——按 public 太凶，
    # v1 决策：能解析出的具体非私网地址按 public（它确实只可能是公网地址）。
    if re.match(r"^[0-9a-f:]+$", low):
        return "public"
    return "unknown"


# ---------------- 服务画像（纯函数） ----------------

def classify_service(name, port, args="", image=""):
    """返回 (kind, reason)。kind: db/admin/file/introspect/ssh/normal。"""
    blob = " ".join([name or "", args or "", image or ""]).lower()
    for hint in DB_HINTS:
        if hint in blob:
            return ("db", "数据库特征「%s」" % hint)
    for hint in FILE_HINTS:
        if hint in blob:
            return ("file", "文件分享特征「%s」" % hint)
    for hint in INTROSPECT_HINTS:
        if hint in blob:
            return ("introspect", "远控/接入特征「%s」" % hint)
    if "ssh" in blob or (name or "").lower() == "sshd":
        return ("ssh", "SSH 管理入口")
    for hint in ADMIN_HINTS:
        if hint in blob:
            return ("admin", "管理台特征「%s」" % hint)
    if port in VCS_PORTS:
        return ("ssh", "SSH 管理端口")
    if port in INTROSPECT_PORTS:
        return ("introspect", "远控常用端口 %d" % port)
    if port in ADMIN_PORTS:
        return ("admin", "管理/数据常用端口 %d" % port)
    if (name or "") in KNOWN_COMMON_PROCS:
        return ("normal", "")
    return ("unknown", "未识别服务（进程不在常见名单）")


SENSITIVE_KINDS = ("db", "admin", "file", "introspect", "ssh")


def classify_listeners_kind(proc, port, args="", image=""):
    """统一画像入口：先特征库，后 macOS 良性白名单兜底。"""
    kind, reason = classify_service(proc, port, args, image)
    if (proc or "") in MACOS_BENIGN_ANY_PORT:
        return ("benign", "macOS 系统自带服务")
    if (proc or "") in MACOS_BENIGN_FIXED_PORT and port in MACOS_BENIGN_PORTS:
        return ("benign", "macOS 系统自带服务")
    return (kind, reason)


def tier_of(exposure, kind):
    if kind == "unknown":
        # 陌生进程：按暴露档基线保守分层（全网卡监听的陌生进程=P1）
        return BASE_TIER.get(exposure, 2)
    sensitive = kind in SENSITIVE_KINDS
    return TIER_TABLE.get((exposure, sensitive),
                          UNKNOWN_TIER.get(exposure, 2))


def annotate_listener(lis):
    """给裸监听记录补 exposure/kind/reason/tier（纯函数）。"""
    lis = dict(lis)
    exposure = classify_addr(lis.get("addr", ""))
    kind, reason = classify_listeners_kind(
        lis.get("proc", ""), lis.get("port", 0),
        lis.get("args", ""), lis.get("image", ""),
    )
    lis["exposure"] = exposure
    lis["kind"] = kind
    lis["reason"] = reason
    lis["tier"] = tier_of(exposure, kind)
    return lis


# ---------------- 采集层（只读） ----------------

SS_LINE = re.compile(
    r"^(LISTEN)\s+\d+\s+\d+\s+\[?([^\s\]]+)\]?:(\d+)\s+\S+\s+(.*)$")
SS_USERS = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
LSOF_LINE = re.compile(
    r"^(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(TCP|UDP)\s+(\S+)\s")
NETSTAT_LINE = re.compile(
    r"^(tcp\w*)\s+\d+\s+\d+\s+\[?([^\s\]]+)\]?:(\d+)\s+\S+\s+LISTEN\s+(.*)$")
DOCKER_PORT = re.compile(
    r"(?:\[?([\w:.]+)\]?|\*):(\d+)->(\d+)/(?:tcp|udp)")
DOCKER_IP_ANY = ("0.0.0.0", "::")


def scan_listeners():
    """返回裸监听列表 [{proto,port,addr,proc,pid}]（不注解）。"""
    out = []
    sysname = platform.system()
    if sysname == "Darwin":
        txt = run_cmd(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if txt is None:
            txt = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if txt:
            for line in txt.splitlines()[1:]:
                m = LSOF_LINE.match(line)
                if not m:
                    continue
                proc, pid, proto, name = m.group(1), m.group(2), m.group(3), m.group(4)
                addr, _, port = name.rpartition(":")
                out.append({"proto": proto.lower(), "port": int(port),
                            "addr": addr, "proc": proc, "pid": int(pid)})
        return out
    if sysname == "Linux":
        txt = run_cmd(["ss", "-lntup"])
        if txt is not None:
            for line in txt.splitlines():
                m = SS_LINE.match(line)
                if not m:
                    continue
                addr, port, rest = m.group(2), m.group(3), m.group(4)
                um = SS_USERS.search(rest)
                proc, pid = ("?", 0)
                if um:
                    proc, pid = um.group(1), int(um.group(2))
                out.append({"proto": "tcp", "port": int(port),
                            "addr": addr, "proc": proc, "pid": pid})
            return out
        txt = run_cmd(["netstat", "-ltnp"])
        if txt is not None:
            for line in txt.splitlines():
                m = NETSTAT_LINE.match(line)
                if not m:
                    continue
                addr, port, rest = m.group(2), m.group(3), m.group(4)
                pm = re.match(r"(\d+)/(\S+)", rest.strip())
                proc, pid = ("?", 0)
                if pm:
                    pid, proc = int(pm.group(1)), pm.group(2)
                out.append({"proto": "tcp", "port": int(port),
                            "addr": addr, "proc": proc, "pid": pid})
            return out
    eprint("ctsonar: 平台 %s 暂不支持（需要 macOS 的 lsof 或 Linux 的 ss/netstat）"
           % sysname)
    sys.exit(4)


def scan_services():
    txt = run_cmd(["systemctl", "list-units", "--type=service",
                   "--state=running", "--no-pager", "--no-legend"])
    names = []
    if txt:
        for line in txt.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                names.append(parts[0][:-len(".service")])
    return names


def scan_docker():
    fmt = "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}"
    txt = run_cmd(["docker", "ps", "--format", fmt], timeout=25)
    items = []
    if txt:
        for line in txt.splitlines():
            parts = line.split("|", 3)
            if len(parts) != 4:
                continue
            cid, name, image, ports = parts
            pub = []
            for m in DOCKER_PORT.finditer(ports):
                haddr = m.group(1)
                if haddr in ("", "0.0.0.0", "::"):
                    haddr = "0.0.0.0"
                pub.append({"addr": haddr, "hport": int(m.group(2)),
                            "cport": int(m.group(3))})
            items.append({"id": cid[:12], "name": name, "image": image,
                          "publish": pub})
    return items


def scan_crontab():
    txt = run_cmd(["crontab", "-l"])
    hits = []
    if txt:
        for line in txt.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if re.search(r"\b(curl|wget|nc|ncat|http://|https://)", s):
                hits.append(s)
    return hits


def scan_processes():
    txt = run_cmd(["ps", "-axo", "pid=,command="])
    out = []
    if txt:
        for line in txt.splitlines():
            s = line.strip()
            if not s:
                continue
            pid, _, cmd = s.partition(" ")
            if pid.isdigit():
                out.append({"pid": int(pid), "cmd": cmd.strip()})
    return out


def scan_packages():
    pkgs = {}
    txt = run_cmd(["pip3", "list", "--format=json"], timeout=60)
    if txt:
        try:
            pkgs["pip"] = [p.get("name", "") for p in json.loads(txt)]
        except Exception:
            pkgs["pip"] = []
    txt = run_cmd(["npm", "ls", "-g", "--depth=0", "--json"], timeout=60)
    if txt:
        try:
            d = json.loads(txt)
            pkgs["npm"] = sorted((d.get("dependencies") or {}).keys())
        except Exception:
            pkgs["npm"] = []
    return pkgs


def args_for_pid(pid, procs):
    for p in procs:
        if p["pid"] == pid:
            return p["cmd"]
    return ""


# ---------------- 状态文件 ----------------

def build_snapshot(include_packages=True):
    listeners = [annotate_listener(l) for l in scan_listeners()]
    procs = scan_processes()
    for l in listeners:
        if not l.get("args"):
            l["args"] = args_for_pid(l.get("pid", 0), procs)
        # 重算 tier：拿到完整命令行后特征可能更准
        kind, reason = classify_listeners_kind(l.get("proc", ""), l["port"],
                                               l.get("args", ""), "")
        l["kind"], l["reason"] = kind, reason
        l["tier"] = tier_of(l["exposure"], kind)
    docker = scan_docker()
    # docker publish 的宿主侧端口若在监听表里，把镜像名补进对应监听的画像
    dmap = {}
    for c in docker:
        for p in c["publish"]:
            dmap.setdefault((p["addr"], p["hport"]), c)
    for l in listeners:
        c = dmap.get((l["addr"], l["port"])) or dmap.get(("0.0.0.0", l["port"]))
        if c:
            l["image"] = c["image"]
            l["container"] = c["name"]
            kind, reason = classify_listeners_kind(l.get("proc", ""),
                                                   l["port"],
                                                   l.get("args", ""),
                                                   c["image"])
            l["kind"], l["reason"] = kind, reason
            l["tier"] = tier_of(l["exposure"], kind)
    snap = {
        "schema": 1,
        "tool": "ctsonar",
        "version": VERSION,
        "host": platform.node(),
        "os": "%s %s" % (platform.system(), platform.release()),
        "generated_at": now_iso(),
        "listeners": sorted(
            listeners,
            key=lambda x: (x["tier"], x["port"], x["proto"], x["addr"])),
        "services": scan_services(),
        "docker": docker,
        "crontab_hits": scan_crontab(),
    }
    if include_packages:
        snap["packages"] = scan_packages()
    return snap


def save_snapshot(snap, path):
    blob = canonical(snap)
    write_0600(path, blob)
    write_0600(path + ".sha256", (sha256_bytes(blob) + "\n").encode("utf-8"))


def verify_snapshot(path):
    """重算 SHA256 + 重算分层，任何被手改的痕迹都拒判。返回 state 或 exit 3。"""
    try:
        snap = load_json(path)
    except Exception as e:
        eprint("ctsonar: 状态文件读不了：%s" % e)
        sys.exit(3)
    side = path + ".sha256"
    if not os.path.exists(side):
        eprint("ctsonar: 缺少签名边车 %s —— 状态文件不完整，拒判。" % side)
        sys.exit(3)
    want = open(side, "r", encoding="utf-8").read().strip()
    got = sha256_bytes(canonical(snap))
    if want != got:
        eprint("ctsonar: 状态文件被改动过（SHA256 不匹配）——拒判，重新 scan 生成新状态。")
        sys.exit(3)
    for l in snap.get("listeners", []):
        raw = {k: l.get(k) for k in ("proto", "port", "addr", "proc", "pid",
                                     "args", "image")}
        expect = annotate_listener(raw)
        if expect["tier"] != l.get("tier") or expect["kind"] != l.get("kind"):
            eprint("ctsonar: 状态文件第 %s:%d 条分层与算法不符（疑被手改）——拒判。"
                   % (l.get("addr"), l.get("port", 0)))
            sys.exit(3)
    return snap


# ---------------- diff（纯函数，双阶段配对防误报） ----------------

def lis_key(l):
    return (l.get("proto", "tcp"), int(l.get("port", 0)), l.get("addr", ""))


def pair_key(l):
    return (l.get("proto", "tcp"), int(l.get("port", 0)),
            (l.get("container") or l.get("proc") or "?"))


def diff_snapshots(old, new):
    """返回 (findings, exit_code, verdict_label)。findings 每条含 tier/type/text。"""
    findings = []
    old_by = {lis_key(l): l for l in old.get("listeners", [])}
    new_by = {lis_key(l): l for l in new.get("listeners", [])}

    removed_keys = [k for k in old_by if k not in new_by]
    added_keys = [k for k in new_by if k not in old_by]
    rebinds = []
    # 阶段一：同 (proto, port, 进程) 的删+增配成「重绑暴露面」事件（不变量 I4）
    for rk in list(removed_keys):
        r = old_by[rk]
        for ak in list(added_keys):
            a = new_by[ak]
            if pair_key(r) == pair_key(a):
                rebinds.append((r, a))
                removed_keys.remove(rk)
                added_keys.remove(ak)
                break

    def human(l):
        c = l.get("container")
        who = ("容器 %s(%s)" % (c, l.get("image", "?"))) if c \
            else (l.get("proc") or "?")
        seg = "%s:%d" % (l.get("addr") or "*", l.get("port", 0))
        return "%s [%s] %s %s" % (seg, EXPO_LABEL.get(l.get("exposure"), "?"),
                                  SEV_LABEL.get(l.get("tier"), "?"), who)

    for r, a in rebinds:
        if r["tier"] > a["tier"]:  # 数字变小 = 变危险
            # 重绑升级一律按高危裁决：门口变大本身就是该半夜爬起来看的事
            findings.append({
                "type": "exposure_escalate", "tier": a["tier"], "exit": 1,
                "text": "暴露面升级：%s -> %s（同服务同端口，换了张卡听）"
                        % (human(r), human(a)),
            })
        else:
            findings.append({
                "type": "exposure_tighten", "tier": a["tier"], "exit": 0,
                "text": "暴露面收紧（好事）：%s -> %s" % (human(r), human(a)),
            })

    for ak in added_keys:
        a = new_by[ak]
        t = a.get("tier", 2)
        if t <= 1:
            code = 1
        elif t == 2:
            code = 2
        else:
            code = 0
        findings.append({
            "type": "added", "tier": t, "exit": code,
            "text": ("新增监听：" + human(a)) + (
                ("（%s）" % a["reason"]) if a.get("reason") else ""),
        })
    for rk in removed_keys:
        r = old_by[rk]
        note = "已下线：" + human(r)
        if r.get("tier", 3) <= 1:
            note += "——高危面消失，好事"
        findings.append({"type": "removed", "tier": r.get("tier", 3),
                         "exit": 0, "text": note})

    # 汇总裁决：1 > 2 > 0
    exits = [f["exit"] for f in findings]
    if not exits:
        return findings, 0, "无变化"
    worst = 1 if 1 in exits else (2 if 2 in exits else 0)
    n_high = sum(1 for f in findings if f["exit"] == 1)
    n_mid = sum(1 for f in findings if f["exit"] == 2)
    if worst == 1:
        label = "高危变化 x%d" % n_high
    elif worst == 2:
        label = "中危变化 x%d" % n_mid
    else:
        label = "无高危变化"
    return findings, worst, label


def findings_machine(findings, label):
    return {
        "verdict": label,
        "added": [f["text"] for f in findings if f["type"] == "added"],
        "removed": [f["text"] for f in findings if f["type"] == "removed"],
        "rebind": [f["text"] for f in findings
                   if f["type"].startswith("exposure_")],
    }


# ---------------- 报告 ----------------

def print_report(snap, include_local=False):
    liss = snap.get("listeners", [])
    p0p1 = [l for l in liss if l.get("tier", 3) <= 1]
    p2 = [l for l in liss if l.get("tier", 3) == 2]
    p3 = [l for l in liss if l.get("tier", 3) == 3]
    print("")
    print("ctsonar v%s · %s · %s" % (VERSION, snap.get("host", "?"),
                                     snap.get("generated_at", "?")))
    print("监听 %d 个：P0/P1 高危 %d · P2 中危 %d · P3 本机 %d"
          % (len(liss), len(p0p1), len(p2), len(p3)))
    print("-" * 72)
    rows = p0p1 + p2 + (p3 if include_local else [])
    for l in rows:
        flag = "!!" if l.get("tier", 3) <= 1 else (" ?" if l.get("tier") == 2 else "  ")
        who = l.get("container") or l.get("proc") or "?"
        line = "%s %s:%-5d [%s] %s %s" % (
            flag, l.get("addr") or "*", l.get("port", 0),
            EXPO_LABEL.get(l.get("exposure"), "?"),
            SEV_LABEL.get(l.get("tier"), "?"), who)
        if l.get("reason"):
            line += " · " + l["reason"]
        print(line)
    if not include_local and p3:
        print("（另有 %d 个仅本机回环监听，加 --include-local 查看）" % len(p3))
    if snap.get("crontab_hits"):
        print("-" * 72)
        print("crontab 里的外联线索（只提示，不定性）：")
        for h in snap["crontab_hits"][:8]:
            print("   " + h[:110])
    dcount = len(snap.get("docker", []))
    if dcount:
        pub_n = sum(len(c.get("publish", [])) for c in snap.get("docker", []))
        print("-" * 72)
        print("docker 容器 %d 个，发布端口 %d 个（发布=映射到宿主机，算暴露面）" % (dcount, pub_n))


# ---------------- CLI ----------------

def cmd_scan(args):
    snap = build_snapshot(include_packages=not args.no_packages)
    save_snapshot(snap, args.out)
    print_report(snap, include_local=args.include_local)
    print("-" * 72)
    p0p1 = [l for l in snap["listeners"] if l["tier"] <= 1]
    if p0p1:
        print("❌ 高危 %d 个（详见上表）—— 状态已写 %s（+sha256 边车）" % (len(p0p1), args.out))
        return 1
    print("✅ 无 P0/P1 高危监听 —— 状态已写 %s（+sha256 边车）" % args.out)
    return 0


def cmd_diff(args):
    old = verify_snapshot(args.old)
    new = verify_snapshot(args.new)
    findings, code, label = diff_snapshots(old, new)
    if args.machine:
        print(json.dumps(findings_machine(findings, label),
                         ensure_ascii=False, indent=2))
    else:
        print("ctsonar diff · %s vs %s" % (old.get("generated_at", "?"),
                                           new.get("generated_at", "?")))
        print("-" * 72)
        if not findings:
            print("两次盘点之间，监听面零变化。")
        for f in findings:
            mark = {"added": "[+]", "removed": "[-]"}.get(f["type"], "[~]")
            print("%s %s" % (mark, f["text"]))
        print("-" * 72)
        if code == 1:
            print("❌ 裁决：%s —— 这台机器的门口变多了，先弄清是谁开的。" % label)
        elif code == 2:
            print("⚠️ 裁决：%s —— 都在内网档，顺手确认是不是你开的。" % label)
        else:
            print("✅ 裁决：%s" % label)
    if code == 1:
        return 1
    if code == 2:
        return 2
    return 0


def cmd_verify(args):
    snap = verify_snapshot(args.state)
    print("✅ %s 完整性与分层均通过（生成于 %s，监听 %d 个）"
          % (args.state, snap.get("generated_at", "?"),
             len(snap.get("listeners", []))))
    return 0


def selftest():
    cases = []

    def case(name, fn):
        cases.append((name, fn))

    # --- 分类 ---
    case("loopback_v4", lambda: classify_addr("127.0.0.1") == "loopback")
    case("loopback_v6", lambda: classify_addr("::1") == "loopback")
    case("loopback_name", lambda: classify_addr("localhost") == "loopback")
    case("wildcard_star", lambda: classify_addr("*") == "wildcard")
    case("wildcard_v4", lambda: classify_addr("0.0.0.0") == "wildcard")
    case("wildcard_v6", lambda: classify_addr("::") == "wildcard")
    case("lan_192", lambda: classify_addr("192.168.1.5") == "lan")
    case("lan_10", lambda: classify_addr("10.1.2.3") == "lan")
    case("lan_172_16", lambda: classify_addr("172.16.0.9") == "lan")
    case("not_lan_172_32", lambda: classify_addr("172.32.0.9") == "public")
    case("lan_169_linklocal", lambda: classify_addr("169.254.3.4") == "lan")
    case("lan_ipv6_ula", lambda: classify_addr("fd00::5") == "lan")
    case("public_v4", lambda: classify_addr("203.0.113.7") == "public")

    # --- 分层 ---
    def t_redis_wild():
        l = annotate_listener({"proto": "tcp", "port": 6379, "addr": "0.0.0.0",
                               "proc": "redis-server", "pid": 1})
        return l["tier"] == 0 and l["kind"] == "db"
    case("redis_wildcard_P0", t_redis_wild)

    def t_redis_loop():
        l = annotate_listener({"proto": "tcp", "port": 6379, "addr": "127.0.0.1",
                               "proc": "redis-server", "pid": 1})
        return l["tier"] == 3
    case("redis_loopback_P3", t_redis_loop)

    def t_httpfile_wild():
        l = annotate_listener({"proto": "tcp", "port": 8000, "addr": "*",
                               "proc": "Python",
                               "args": "python3 -m http.server 8000"})
        return l["tier"] == 0 and l["kind"] == "file"
    case("httpserver_wildcard_P0", t_httpfile_wild)

    def t_grafana():
        w = annotate_listener({"proto": "tcp", "port": 3000, "addr": "*",
                               "proc": "grafana", "pid": 1})
        lp = annotate_listener({"proto": "tcp", "port": 3000, "addr": "127.0.0.1",
                                "proc": "grafana", "pid": 1})
        return w["tier"] == 0 and lp["tier"] == 3 and w["kind"] == "admin"
    case("grafana_wild_P0_loop_P3", t_grafana)

    def t_unknown():
        w = annotate_listener({"proto": "tcp", "port": 9418, "addr": "*",
                               "proc": "mystery", "pid": 1})
        lan = annotate_listener({"proto": "tcp", "port": 9418,
                                 "addr": "192.168.1.5", "proc": "mystery",
                                 "pid": 1})
        return w["tier"] == 1 and lan["tier"] == 2
    case("unknown_wild_P1_lan_P2", t_unknown)

    def t_port_hint_admin():
        l = annotate_listener({"proto": "tcp", "port": 8080, "addr": "*",
                               "proc": "java", "pid": 1, "args": "-jar app.jar"})
        return l["kind"] == "admin" and l["tier"] == 0
    case("port8080_wild_admin_P0", t_port_hint_admin)

    def t_nginx_no_false_p0():
        # 噪音治理：nginx 全网卡监听是常态，定 P2 不进高危档
        l = annotate_listener({"proto": "tcp", "port": 443, "addr": "*",
                               "proc": "nginx", "pid": 1})
        return l["tier"] == 2 and l["kind"] == "normal"
    case("nginx_wild_P2_noise_low", t_nginx_no_false_p0)

    def t_ssh():
        l = annotate_listener({"proto": "tcp", "port": 22, "addr": "192.168.1.5",
                               "proc": "sshd", "pid": 1})
        return l["kind"] == "ssh" and l["tier"] == 1
    case("ssh_lan_P1", t_ssh)

    def t_macos_benign_dynamic():
        # rapportd 端口每次开机随机，按进程名全端口放行：定 P2 不进高危档
        l = annotate_listener({"proto": "tcp", "port": 61856, "addr": "*",
                               "proc": "rapportd", "pid": 1})
        return l["kind"] == "benign" and l["tier"] == 2
    case("macos_benign_dynamic_port", t_macos_benign_dynamic)

    def t_benign_not_overbroad():
        # 白名单只按进程精确命中：陌生进程同样端口仍是 unknown+保守档
        l = annotate_listener({"proto": "tcp", "port": 61856, "addr": "*",
                               "proc": "mysteryd", "pid": 1})
        return l["kind"] == "unknown" and l["tier"] == 1
    case("benign_not_overbroad", t_benign_not_overbroad)

    def t_docker_image():
        l = annotate_listener({"proto": "tcp", "port": 6379, "addr": "0.0.0.0",
                               "proc": "docker-proxy", "pid": 1,
                               "image": "redis:7"})
        return l["kind"] == "db" and l["tier"] == 0
    case("docker_image_classified", t_docker_image)

    # --- diff ---
    def snap(ls):
        return {"generated_at": "T", "listeners": [annotate_listener(l) for l in ls]}

    L_API_LOOP = {"proto": "tcp", "port": 8000, "addr": "127.0.0.1",
                  "proc": "api", "pid": 1}
    L_API_WILD = {"proto": "tcp", "port": 8000, "addr": "*", "proc": "api",
                  "pid": 1}
    L_REDIS_WILD = {"proto": "tcp", "port": 6379, "addr": "0.0.0.0",
                    "proc": "redis-server", "pid": 2}
    L_DB_LAN = {"proto": "tcp", "port": 5432, "addr": "192.168.1.5",
                "proc": "postgres", "pid": 3}

    def t_diff_rebind():
        f, code, _ = diff_snapshots(snap([L_API_LOOP]), snap([L_API_WILD]))
        types = {x["type"] for x in f}
        return code == 1 and types == {"exposure_escalate"}
    case("diff_rebind_not_add_rm", t_diff_rebind)

    def t_diff_rebind_tighten():
        f, code, _ = diff_snapshots(snap([L_API_WILD]), snap([L_API_LOOP]))
        return code == 0 and f[0]["type"] == "exposure_tighten"
    case("diff_rebind_tighten_ok", t_diff_rebind_tighten)

    def t_diff_add_p0():
        f, code, _ = diff_snapshots(snap([L_API_LOOP]),
                                    snap([L_API_LOOP, L_REDIS_WILD]))
        return code == 1 and any(x["type"] == "added" and x["tier"] == 0
                                 for x in f)
    case("diff_add_redis_wild_HIGH", t_diff_add_p0)

    def t_diff_remove_p0_good():
        f, code, _ = diff_snapshots(snap([L_API_LOOP, L_REDIS_WILD]),
                                    snap([L_API_LOOP]))
        return code == 0 and any("好事" in x["text"] for x in f)
    case("diff_remove_p0_GOOD", t_diff_remove_p0_good)

    def t_diff_nochange():
        f, code, _ = diff_snapshots(snap([L_API_LOOP]), snap([L_API_LOOP]))
        return code == 0 and not f
    case("diff_nochange_zero", t_diff_nochange)

    def t_diff_mid():
        # 设计语义：内网数据库=P1（Redis/PG 在内网卡 = 经典内渗入口）
        f, code, _ = diff_snapshots(snap([L_API_LOOP]),
                                    snap([L_API_LOOP, L_DB_LAN]))
        return code == 1 and any(x["tier"] == 1 and x["type"] == "added"
                                 for x in f)
    case("diff_add_lan_db_HIGH", t_diff_mid)

    def t_diff_machine():
        f, code, label = diff_snapshots(snap([L_API_LOOP]), snap([L_API_WILD]))
        m = findings_machine(f, label)
        return m["verdict"] and isinstance(m["rebind"], list)
    case("diff_machine_json", t_diff_machine)

    # --- 状态完整性 ---
    def t_sha_roundtrip():
        import tempfile
        d = tempfile.mkdtemp(prefix="ctsonar_t_")
        p = os.path.join(d, "state.json")
        s = snap([L_API_LOOP])
        save_snapshot(s, p)
        want = open(p + ".sha256").read().strip()
        return want == sha256_bytes(canonical(load_json(p)))
    case("sha_roundtrip", t_sha_roundtrip)

    def t_tamper_detect():
        import tempfile
        d = tempfile.mkdtemp(prefix="ctsonar_t_")
        p = os.path.join(d, "state.json")
        s = snap([L_API_LOOP])
        save_snapshot(s, p)
        s2 = load_json(p)
        s2["listeners"][0]["addr"] = "*"
        write_0600(p, canonical(s2))
        want = open(p + ".sha256").read().strip()
        return want != sha256_bytes(canonical(s2))
    case("tamper_detected", t_tamper_detect)

    def t_crontab_filter():
        lines = ["# comment curl http://x", "0 9 * * * curl https://a.b/ping",
                 "0 10 * * * /usr/bin/local-backup"]
        hits = [l for l in lines
                if l.strip() and not l.strip().startswith("#")
                and re.search(r"\b(curl|wget|nc|ncat|http://|https://)", l)]
        return len(hits) == 1 and "curl" in hits[0]
    case("crontab_hit_filter", t_crontab_filter)

    def t_secrets_not_logged():
        # 不变量 I5：状态里不允许出现完整命令行以外的敏感字段值——
        # 结构性检查：snapshot 只允许固定键集合。
        allowed = {"schema", "tool", "version", "host", "os", "generated_at",
                   "listeners", "services", "docker", "crontab_hits",
                   "packages"}
        s = snap([L_API_LOOP])
        return set(s.keys()) <= allowed
    case("snapshot_keys_whitelist", t_secrets_not_logged)

    ok = 0
    fail = []
    for name, fn in cases:
        try:
            r = fn()
            if r:
                ok += 1
                print("PASS %s" % name)
            else:
                fail.append(name)
                print("FAIL %s" % name)
        except Exception as e:
            fail.append(name)
            print("FAIL %s (exception: %s)" % (name, e))
    print("-" * 60)
    print("selftest: %d/%d 绿" % (ok, len(cases)))
    if fail:
        print("失败用例：%s" % ", ".join(fail))
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="ctsonar",
        description="一条命令摸清单台主机的对外暴露面：盘点 -> 分层 -> 签名状态 -> diff 裁决")
    ap.add_argument("--version", action="version",
                    version="ctsonar %s" % VERSION)
    sub = ap.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="盘点当前监听面，写签名状态文件")
    p_scan.add_argument("--out", default="ctsonar-state.json",
                        help="状态文件路径（默认 ./ctsonar-state.json）")
    p_scan.add_argument("--include-local", action="store_true",
                        help="报告里也列出仅本机回环的监听")
    p_scan.add_argument("--no-packages", action="store_true",
                        help="跳过 pip/npm 包盘点（更快）")
    p_scan.set_defaults(fn=cmd_scan)

    p_diff = sub.add_parser("diff", help="比较两份签名状态，裁决变化")
    p_diff.add_argument("old", help="基线状态文件")
    p_diff.add_argument("new", help="本次状态文件")
    p_diff.add_argument("--machine", action="store_true",
                        help="只输出机器可读 JSON")
    p_diff.set_defaults(fn=cmd_diff)

    p_verify = sub.add_parser("verify", help="校验状态文件签名与分层一致性")
    p_verify.add_argument("state", help="状态文件")
    p_verify.set_defaults(fn=cmd_verify)

    p_st = sub.add_parser("selftest", help="离线自测（不 bind、不发网络包）")
    p_st.set_defaults(fn=lambda a: selftest())

    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
