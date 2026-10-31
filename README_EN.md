# ctsonar

> **Exposure sonar** — one command to map a host's exposure surface: listener inventory + 4-tier exposure classes + P0-P3 risk tiers + diffable signed state. Zero dependencies, single file.
> When your machine grows new doors, you should be the first to know.

[简体中文](README.md) | [English](README_EN.md)

[![release](https://img.shields.io/badge/release-v1.0.0-blue)]() [![license](https://img.shields.io/badge/license-MIT-green)]() [![python](https://img.shields.io/badge/python-3.7%2B-informational)]()

## Why

Every service binds a port. Almost nobody keeps the list. Three months later, no one can say which listeners are planned and which are leftovers from a debug session with `--bind 0.0.0.0`.

`netstat`/`lsof` give facts, not judgment. `ctsonar` classifies every listener by exposure (loopback / lan / wildcard / public), paints it with a service profile (database / admin UI / file share / remote control / ssh / unknown), assigns a P0-P3 tier, signs the state, and diffs it against yesterday.

```bash
python3 ctsonar.py scan --out /var/lib/ctsonar/state.json
python3 ctsonar.py diff state.json.old state.json
echo exit=$?    # 1 = high-risk change
```

## Quick start

```bash
python3 ctsonar.py scan
# or one-liner install
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen045/ctsonar@main/install.sh | bash
```

## Commands

| command | what it does |
|---|---|
| `scan [--out F] [--include-local] [--no-packages]` | inventory listeners, write 0600 signed state |
| `diff OLD NEW [--machine]` | adjudicate changes; exit 0/1/2/3 |
| `verify STATE` | re-check SHA256 sidecar + tier consistency |
| `selftest` | 35 offline tests, no sockets bound |

## Exposure classes

`loopback` (127.x/::1) → `lan` (10/8, 172.16/12, 192.168/16, IPv6 ULA) → `wildcard` (*, 0.0.0.0, ::) → `public` (any other concrete address).

## Tiers (pure function, same input same output)

| tier | rule |
|---|---|
| P0 | sensitive service (db/admin/file-share/remote-control) on wildcard or public |
| P1 | sensitive on lan; **unknown process on wildcard**; anything on public |
| P2 | known-common services on wildcard (nginx et al — noise control); macOS system daemons |
| P3 | loopback-only listeners |

## Diff verdict = exit code

0 none/good-only · 1 high-risk (new P0/P1, exposure escalation) · 2 medium · 3 state tampered (refuse) · 4 unsupported platform.

Rebind awareness: same (proto, port, process) moving 127.0.0.1 → * is one "escalation" event, never add+remove noise.

## Invariants

I1 read-only recon (no bind, no packets, no kill, no config writes) · I2 pure-function classification · I3 SHA256-signed state, tamper-proof verdict · I4 rebind ≠ add+remove · I5 secrets never persisted (no args beyond proc/port/addr) · I6 fixed exit-code semantics · I7 unknown services get conservative tiers, never guessed safe.

## Honest limits

ctsonar reads who listens on THIS host. It is not nmap (no remote scanning), does not judge firewall/NAT in front of you, and does not audit service vulnerabilities.

## License

MIT
