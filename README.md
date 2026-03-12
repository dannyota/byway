# 🛤️ byway

Transparent per-app VPN bypass on Linux.

## 🤔 Problem

Your VPN hijacks all routes. Some apps need to go around it.

## 💡 Solution

`byway` is a Go daemon that uses **cgroup v2 + nftables + policy routing** to transparently route traffic from specific apps through a different network interface. No wrappers, no namespaces — apps launch normally.

```
App in config ──► cgroup ──► fwmark ──► policy route ──► direct interface ──► 🌐
Everything else ──► default route ──► VPN tunnel ──► 🌐
```

## ⚙️ How it works

1. 📦 **cgroup v2** — groups configured app processes
2. 🏷️ **nftables** — marks packets from that cgroup with a fwmark
3. 🔀 **policy routing** — routes marked packets through your chosen interface
4. 👀 **proc connector** — watches for new processes matching your config
5. 🔄 **reconciler** — periodically verifies and restores rules if anything flushes them

## 📝 Config

```bash
cp example.toml byway.toml
# edit byway.toml with your interface and apps
```

```toml
interface = "wwan0"
reconcile = "5s"

apps = [
    "/usr/bin/firefox",
    "/usr/bin/curl",
]
```

## 📋 Prerequisites

- 🐧 Linux with **cgroup v2** (unified hierarchy) — default on Ubuntu 22.04+
- 🔥 **nftables** kernel support — default on all modern kernels (5.x+)
- 🔌 A second network interface for bypass traffic (or shared mode with the VPN interface)
- 🔨 [Go 1.23+](https://go.dev/dl/) to build

No userspace tools needed at runtime — byway talks directly to the kernel via netlink.

## 🚀 Usage

```bash
go build -o byway .
sudo ./byway -config byway.toml
```

Runs as root (required for cgroup, nftables, netlink, ip rule).

## 🔌 Interface modes

| Mode | Example | Reliability |
|---|---|---|
| 🟢 **Dedicated** | `wwan0`, `eth1`, `usb0` | High — separate physical path |
| 🟡 **Shared** | `wlan0` (same as VPN) | Best-effort — reconciler mitigates rule flushes |

## 🔄 Lifecycle

- **Start** → detect gateway, create cgroup, nftables rule, ip rule + route table
- **Run** → three concurrent loops: config watcher 👁️, process monitor 🔍, reconciler 🔄
- **Hot-reload** → edit `byway.toml` while running — app list, interface, and reconcile interval update live
- **Stop** → `Ctrl+C` cleans up everything — system returns to default routing
- **Crash recovery** → kernel state persists; on restart, existing rules are adopted without disruption

## 📦 Dependencies

Go 1.23+ and:

- [`BurntSushi/toml`](https://github.com/BurntSushi/toml) — config parsing
- [`fsnotify/fsnotify`](https://github.com/fsnotify/fsnotify) — config hot-reload
- [`google/nftables`](https://github.com/google/nftables) — nftables management
- [`vishvananda/netlink`](https://github.com/vishvananda/netlink) — route/rule management
- [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) — netlink proc connector
