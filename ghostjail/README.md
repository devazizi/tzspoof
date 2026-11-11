# ghostjail

Rootless identity spoofing and network jail for Linux, in one static binary.
It merges `tzspoof` (timezone/hostname spoofing) and `tunjail` (proxy-only
network namespace with a kill switch). Nothing needs root: no `sudo`, no
iptables, no veth pairs. When the session ends, nothing is left behind.

```bash
# Your own tools through the proxy, intranet direct, looking like London:
ghostjail -x socks5://127.0.0.1:2080 --direct private -t london -H box-01

# Run an unknown Linux binary: offline, empty $HOME and /tmp, clean environment:
ghostjail --analysis -t ny -H desktop-7 --ro ./samples -- ./samples/unknown.bin
```

## How it works

```
 host network namespace                       new user/mount/UTS/net namespaces
┌─────────────────────────────────┐          ┌──────────────────────────────────────┐
│ ghostjail (parent)              │  tun fd  │ ghostjail init -> your command        │
│  gVisor TCP/IP stack (tun2socks)│<─────────│  lo + tun0 (198.18.0.1/15): only route│
│  router per connection:         │ SCM_RIGHTS│  /etc/localtime, timezone, hostname, │
│   --direct CIDR -> direct dial  │          │  hosts, nsswitch, machine-id, resolv  │
│   :53 UDP/TCP   -> DoH resolver │          │  replaced by private mounts          │
│   everything else -> --proxy    │          │  no capabilities, no_new_privs=1     │
└─────────────────────────────────┘          └──────────────────────────────────────┘
```

- The child creates `tun0` inside its own network namespace (allowed without
  root inside a user namespace) and passes the file descriptor to the parent.
  The parent stays in the host namespace, so it can reach your local proxy and
  your VPN routes, and runs a userspace TCP/IP stack on that descriptor.
- **Kill switch by construction:** `tun0` is the jail's only interface. If the
  proxy is down, connections fail; nothing can take another route. IPv6 has no
  route at all.
- **Host loopback is not reachable** from the jail (its `127.0.0.1` is its
  own), unlike tunjail, whose DNAT exposed every host loopback port.
- Identity files are replaced with the new mount API (`open_tree`/`move_mount`):
  a symlinked `/etc/localtime` stays a symlink and the real zone files are
  never overlaid.
- The jailed command runs as your UID with **no capabilities** and
  `no_new_privs`, so `sudo`, `su` and setuid/file-capability binaries cannot
  gain privileges.

## Requirements

- Linux >= 5.12 (user namespaces, `open_tree`/`move_mount`, `mount_setattr`),
  with unprivileged user namespaces enabled and `/dev/net/tun` available
- Go >= 1.24 and a C compiler to build (the preload library is C)

## Build, test, install

```bash
make            # bin/ghostjail (static, CGO_ENABLED=0) and bin/libghostjail.so
make test       # go vet, Go unit tests, hermetic integration tests (python3 >= 3.12)
make PREFIX=~/.local install
```

The integration tests run `bin/ghostjail` inside a throwaway namespace with a
fake `/etc` and only use local servers; they do not touch the real network.

## Usage

```
ghostjail [run] [OPTIONS] [--] [COMMAND [ARGS...]]   (default: $SHELL)
ghostjail zones [FILTER]
ghostjail status
ghostjail version
```

| Option | Meaning |
|---|---|
| `-t, --tz ZONE` | Timezone: alias (`tokyo`, `ny`), name (`Europe/London`) or search term |
| `-H, --hostname NAME` | Hostname via UTS namespace; also `/etc/hostname`, `/etc/hosts` (`127.0.1.1 NAME` first) and `files` first in `nsswitch.conf` |
| `--machine-id ID` | Replace `/etc/machine-id` and `/var/lib/dbus/machine-id`: `random` or 32 hex chars |
| `-n, --net MODE` | `host` (default), `none` (loopback only) or `proxy` (default when `--proxy` is given) |
| `-x, --proxy URL` | Upstream: `socks5://`, `http://`, `ss://`, `socks4://`, `direct://` (no proxy, but jailed and logged), `reject://` (refuse all, log attempts). Default `socks5://127.0.0.1:2080` |
| `--direct CIDR` | Dial these destinations directly from the host network (VPN/intranet). `private` = RFC 1918 ranges. Repeatable |
| `--dns URL` | DNS-over-HTTPS endpoint with an IP host, tried in order. Default `https://1.1.1.1/dns-query`, `https://8.8.8.8/dns-query`. `off` disables |
| `-l, --log FILE` | JSON-lines log of every TCP/UDP connection and DNS query |
| `--private-tmp` | Empty `/tmp`, `/var/tmp` and `/dev/shm` (shared memory is an IPC channel to host processes) |
| `--private-run` | Empty `/run`: hides every host socket (`docker.sock`, system/session D-Bus, ssh/gpg agents, systemd) |
| `--tmp-home` | Empty `$HOME` (hides `~/.ssh`, `~/.kube`, browser profiles, shell history) |
| `--hide PATH` | Mask a file or directory. Repeatable |
| `--ro PATH`, `--rw PATH` | Expose a host path at the same location, even under a hidden `$HOME`/`/tmp` |
| `--clean-env` | Minimal environment (`PATH HOME USER LOGNAME SHELL TERM COLORTERM LANG LANGUAGE LC_*`), no `GHOSTJAIL*`/`TZ` markers |
| `--no-preload` | Do not inject `libghostjail.so` |
| `--analysis` | `--net none` (unless `--net`/`--proxy` given), `--private-tmp`, `--private-run`, `--tmp-home`, `--machine-id random`, `--clean-env`, `--no-preload` |
| `-q, --quiet` | No banner or warnings |

Options go before the command; everything after the command (or `--`) is
passed to it untouched.

Exit codes: the command's own code; `128+N` if it was killed by signal N;
`125` jail setup failed; `126` cannot execute; `127` command not found; `2`
invalid options.

### Migrating from tunjail

| tunjail | ghostjail |
|---|---|
| `tunjail_ctl.py up` / `down` / `heal` | not needed: each session builds and removes its own jail |
| `tunjail_ctl.py exec [cmd]` | `ghostjail -x socks5://127.0.0.1:2080 --direct private -- [cmd]` |
| `CORPORATE_SUBNETS` | `--direct private` or `--direct 192.168.113.0/24 --direct ...` |
| DoH DNS proxy daemon | built in (`--dns`) |
| `OUTPUT DROP` kill switch, IPv6 off | built in (single `tun0` route, no IPv6 route) |
| private `/tmp` | `--private-tmp` |
| `status` connectivity checks | `ghostjail status`; `--log FILE` for every connection |

Differences: sessions do not share one jail (each `ghostjail` has its own
stack), and host loopback services are not reachable from inside. A prompt
that checks `IN_TUNJAIL` should check `GHOSTJAIL=1` instead.

### Analysing unknown software

```bash
mkdir -p ~/lab/out
cd ~/lab
ghostjail --analysis -t europe/berlin -H WS-4471 \
  --ro ~/lab/sample --rw ~/lab/out -- ./sample/unknown.bin
```

- Offline by default. To watch what it tries to reach without letting it out:
  `--analysis -x reject:// -l ~/lab/out/net.log` (every connection attempt and
  DNS query is logged and refused). With `-x direct://` or a proxy it gets real
  network access through the jail, still logged.
- The sample sees an empty home, empty `/tmp`, `/var/tmp`, `/dev/shm` and
  `/run` (no Docker socket, D-Bus or agent sockets), no `sudo`, and none of
  your environment variables.
- **Unix sockets ignore network namespaces, and your supplementary groups stay
  effective inside the user namespace.** Without `--private-run`, a jailed
  process in the `docker` group can use `/run/docker.sock`, which is root on
  the host. Never run untrusted code without `--analysis` or `--private-run`.

**Limits.** This is a shared-kernel sandbox, like containers. It is suitable
for triage of Linux binaries; anything you suspect is actual malware (kernel
exploits, VM-aware payloads) belongs in a virtual machine. The jail also does
not isolate processes (`/proc` shows host processes), IPC or seccomp-filter
syscalls.

### Other limits

- `hostnamectl` and other D-Bus clients ask systemd outside the jail and see
  the real host, unless `--private-run` hides the buses.
- Supplementary groups cannot be dropped without root, so group-owned
  devices and files (for example `/dev/kvm` for group `kvm`) stay accessible.
- `/etc/hosts` keeps its original lines (a line naming the real host stays
  readable).
- DNS answers include AAAA records but the jail has no IPv6 route; programs
  fall back to IPv4.
- `--hide` and `--tmp-home` mask paths, but an already open file descriptor
  passed in from outside stays usable.
- `libghostjail.so` (loaded unless `--no-preload`) reports files owned by the
  overflow UID (65534, i.e. host root inside the user namespace) as UID 0, so
  tools like `ssh` accept root-owned config files.

## Layout

```
cmd/ghostjail/       CLI and host-side session (namespaces, handshake, signals)
internal/sandbox/    in-jail init: mounts, hostname, tun0, capability drop, exec
internal/network/    host-side stack: router, DoH resolver, logging
internal/identity/   timezone resolution, hostname rules, /etc file contents
internal/config/     session settings shared by both sides
preload/             LD_PRELOAD hook (C)
tests/               hermetic integration tests
```
