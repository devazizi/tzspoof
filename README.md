# tzspoof

A lightweight, zero-dependency, high-fidelity **Timezone Spoofing Utility** for Linux written in C.

`tzspoof` allows you to spawn an interactive shell or execute any process (Python, Node.js, Go, Rust, C/C++, cURL, etc.) in a completely spoofed timezone without modifying host system files or requiring root privileges.

---

## Key Features

- **Unprivileged Linux Namespace Isolation**: Leverages User (`CLONE_NEWUSER`) and Mount (`CLONE_NEWNS`) namespaces to bind mount the target timezone tzfile over `/etc/localtime` and `/etc/timezone`.
- **Zero Impact on Host**: The host system clock, configuration, and `/etc` files remain 100% untouched. When the subshell or command exits, the namespace is automatically torn down by the kernel.
- **Works with Static & Dynamic Binaries**: Because changes happen at the Linux Virtual File System (VFS) layer, statically linked binaries (Go, Rust), dynamic libraries (glibc/musl), and interpreted runtimes (Python, Node.js, Ruby) all see the spoofed timezone identically.
- **Companion Preload Hook (`libtzspoof.so`)**: Intercepts `readlink`, `__readlink_chk`, and `readlinkat` on `/etc/localtime`, ensuring utilities that inspect the symlink target directly (such as `readlink /etc/localtime`) report the exact target timezone path.
- **Smart Aliases & Fuzzy Matching**: Supports popular shortcuts (e.g. `tokyo`, `london`, `ny`, `la`, `berlin`, `tehran`, `dubai`, `utc`), case-insensitive searches, and city suffix resolution.
- **Optional Hostname Spoofing (`-H NAME`)**: Adds a UTS namespace so `uname -n`, `hostname`, `gethostname()` and `/proc/sys/kernel/hostname` report `NAME` for static and dynamic binaries alike, and replaces `/etc/hostname` and `/etc/hosts` so the name resolves locally.
- **Preserved User Identity**: Maps the user's real UID/GID inside the namespace, preserving file permissions, home directory access, and shell prompt settings.

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │             Host System               │
                      │  /etc/localtime -> Asia/Tehran         │
                      │  /etc/timezone  -> Asia/Tehran         │
                      └──────────────────┬────────────────────┘
                                         │
                             tzspoof tokyo (or bash/zsh)
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │      Isolated Mount & User NS         │
                      │                                       │
                      │  • UID/GID: Same as caller (no root)  │
                      │  • Mounts: Recursive Private          │
                      │  • /etc/localtime ───► Asia/Tokyo     │
                      │  • /etc/timezone  ───► "Asia/Tokyo"   │
                      │  • Environment:    TZ=Asia/Tokyo      │
                      │  • Preload Hook:   readlink -> Tokyo  │
                      │                                       │
                      │    [ Subshell / Custom Command ]      │
                      │  (Node, Python, Go, cURL, bash, zsh)  │
                      └───────────────────────────────────────┘
```

---

## Building & Installation

### Requirements

- Linux Kernel ≥ 5.2 (unprivileged user namespaces and the `open_tree`/`move_mount` mount API); on older kernels tzspoof falls back to environment mode (`-e`)
- GCC or Clang
- Make

### Build

```bash
cd tzspoof
make
```

This produces:
- `bin/tzspoof`: Main CLI binary.
- `bin/libtzspoof.so`: Companion preload library.

### Run Tests

```bash
make test
```

`make test` includes `tests/test_tzspoof.py` (Python >= 3.12), which runs `bin/tzspoof` in a throwaway namespace with a fake `/etc` to cover symlinked and regular-file `/etc/localtime` hosts and nested sessions.

### Install (Optional)

```bash
# Install to /usr/local (default)
sudo make install

# Or install to user directory (~/.local):
make PREFIX=~/.local install
```

---

## Usage

### 1. Spawn an Interactive Shell

Spawn a subshell (automatically selects `$SHELL` or `/bin/bash`):

```bash
# Using an alias:
tzspoof tokyo

# Using a canonical zone name:
tzspoof Europe/London

# Exit back to host shell:
exit
```

### 2. Run a One-Shot Command

Execute any command in the spoofed timezone and capture its return code:

```bash
# Check date in New York:
tzspoof ny date

# Run a Python one-liner in Tokyo:
tzspoof tokyo python3 -c "import datetime; print(datetime.datetime.now().astimezone())"

# Execute complex commands with -- delimiter:
tzspoof london -- sh -c 'date; cat /etc/timezone; readlink /etc/localtime'
```

### 3. Spoof the Hostname Too

```bash
# Run a build as if on a different machine:
tzspoof -H build-01 utc -- sh -c 'hostname; uname -n; getent hosts build-01'
```

With `-H`, tzspoof also:
- puts `127.0.1.1 NAME` at the top of `/etc/hosts`, so forward and reverse lookups return the spoofed name;
- moves `files` to the front of the `hosts:` line in `/etc/nsswitch.conf`. Otherwise modules such as `resolve` (systemd-resolved), which run outside the namespace, answer first with the real host's data.

Limits: `hostnamectl` and other D-Bus clients still ask systemd-hostnamed, which is outside the namespace, and so do `systemd-resolved` lookups made directly over D-Bus. `/etc/hosts` keeps its original lines, so a line that names the real host is still readable. `/etc/machine-id`, IP addresses and reverse DNS still identify the real host. `-H` needs namespaces: it cannot be combined with `-e`, and tzspoof exits with an error instead of falling back if namespace setup fails.

### 4. Check Current Timezone Status

```bash
tzspoof -c
```

Output:
```text
Current Timezone Status:
  • Timezone    : Asia/Tokyo
  • Local Time  : Fri Nov 06 2026 17:15:00 JST (UTC+0900)
  • Source Path : /usr/share/zoneinfo/Asia/Tokyo
  • Spoof State : ACTIVE (Target: Asia/Tokyo)
```

### 5. Search and List Available Timezones

```bash
# List all timezones matching 'Europe':
tzspoof -l Europe

# Search for a specific city:
tzspoof -l Tokyo
```

---

## Practical Examples & Real-World Use Cases

### 1. Test Suites (Catching Timezone-Dependent Bugs)

Many unit and integration tests accidentally pass because the developer's machine happens to be in a specific timezone, then fail in CI/CD (running in UTC) or on customer servers. Run your entire test suite under various timezones before pushing:

```bash
# Test Python code under Tokyo (UTC+9, no DST):
tzspoof tokyo pytest tests/

# Test Node.js / Jest in New York (handles DST transitions):
tzspoof ny npm test

# Test Go packages under London (GMT/BST):
tzspoof london go test -v ./...

# Test Rust binaries strictly in UTC:
tzspoof utc cargo test
```

### 2. Git Commit Privacy & Anti-Fingerprinting

By default, `git commit` records your system's exact timezone offset (e.g. `+0330`, `+0200`, `-0500`) in both author and committer metadata, leaking your geographical region into public repositories:

```bash
# Commit strictly with UTC timezone:
tzspoof utc git commit -m "feat(api): add auth endpoint"

# Verify that the commit offset is clean +0000:
git log -1 --format="Author: %an <%ae>%nDate:   %ad%nCommit: %cd" --date=iso
```

### 3. Database Clients & Timezone-Aware Queries (PostgreSQL, MySQL)

PostgreSQL dynamically initializes the session timezone based on the client machine's `/etc/localtime`. Test how your database queries and ORMs format timestamps across regions:

```bash
# Connect to PostgreSQL from a New York perspective:
tzspoof ny psql -h localhost -U postgres -d my_db -c "SHOW timezone; SELECT now();"

# Run database migrations from a London perspective:
tzspoof london alembic upgrade head
```

### 4. Headless Browsers & Web Scraping (Bypassing Timezone Leaks)

Headless browsers (Puppeteer, Playwright, Selenium, Chromium) inspect `/etc/localtime` and Javascript `Intl.DateTimeFormat().resolvedOptions().timeZone` to detect your locale:

```bash
# Run headless scraper matching a London residential proxy:
tzspoof london node scrape_site.js

# Run Python Playwright tests matching Tokyo timezone:
tzspoof tokyo python3 -m playwright test
```

### 5. Log Pipeline & Timestamp Parsing Verification

Verify whether your log ingestors (Vector, Fluentbit, Logstash, Elasticsearch) correctly handle local non-UTC timestamps without corrupting event order:

```bash
# Simulate syslog events from an Asian datacenter:
tzspoof tokyo logger -t "app-worker" "Batch processing completed successfully"

# Inspect formatting of standard date commands:
tzspoof ny date --iso-8601=seconds
# Output: 2026-11-06T03:45:00-05:00
```

### 6. Daylight Saving Time (DST) Transition Testing

Quickly check how your code formats dates across winter and summer DST boundaries:

```bash
# Check London in winter (GMT, UTC+0000):
tzspoof london date -d "2026-01-15 12:00:00"

# Check London in summer (BST, UTC+0100):
tzspoof london date -d "2026-07-15 12:00:00"
```

### 7. Self-Enforcing Scripts (Shebang Pattern)

To ensure an administrative or deployment script always runs in a fixed timezone regardless of the operator's machine, add this self-wrapping guard at the top of the script:

```bash
#!/usr/bin/env bash
# Ensure script always executes within UTC:
if [ -z "$TZSPOOF_ACTIVE" ]; then
    exec tzspoof -q utc -- "$0" "$@"
fi

echo "Running critical deployment in: $(cat /etc/timezone 2>/dev/null || date +%Z)"
# ... deployment logic here ...
```

### 8. Pipelining in Scripts (Quiet Mode `-q`)

When embedding `tzspoof` in shell pipelines or cron scripts, pass `-q` / `--quiet` to suppress all banners and informational messages:

```bash
# Capture Tokyo epoch date without banner pollution:
TOKYO_DATE=$(tzspoof -q tokyo date +"%Y-%m-%d %H:%M:%S")

# Pipe directly into jq or other tools:
tzspoof -q utc python3 -c 'import json, datetime; print(json.dumps({"time": datetime.datetime.now().isoformat()}))' | jq .
```

### 9. Productivity Aliases for `~/.zshrc` / `~/.bashrc`

Add these quick aliases to your shell configuration to jump into different timezones effortlessly:

```bash
# Add to ~/.zshrc or ~/.bashrc:
alias in-utc="tzspoof utc"
alias in-ny="tzspoof ny"
alias in-tokyo="tzspoof tokyo"
alias in-london="tzspoof london"
alias in-berlin="tzspoof berlin"
alias in-dubai="tzspoof dubai"
```

Then in any terminal:
```bash
$ in-tokyo
# Subshell spawns with Tokyo timezone active
$ date
Fri Nov 06 17:45:00 JST 2026
$ exit
```

---

## CLI Options

Options may appear before or right after `<TIMEZONE>` (`tzspoof -s tokyo -H box`). Parsing stops at the first non-option or `--`, so arguments of the command itself are never read as tzspoof options. `-s` together with a command is an error.

| Flag | Long Option | Description |
|---|---|---|
| `-s` | `--shell` | Explicitly spawn an interactive shell (default if no command given) |
| `-l` | `--list [FILTER]` | List available system timezones with optional filter |
| `-c` | `--current` | Display current active timezone and local time |
| `-q` | `--quiet` | Quiet mode (suppress banners and informational messages) |
| `-e` | `--env-only` | Skip Linux namespaces; only use `$TZ` and preload hook |
| `-p` | `--preload` | Force loading of `libtzspoof.so` preload hook |
| `-H` | `--hostname NAME` | Also spoof the hostname (UTS namespace, `/etc/hostname`, `/etc/hosts`) |
| `-v` | `--version` | Display version information |
| `-h` | `--help` | Display help menu |

---

## Built-in Aliases

| Alias | Target Timezone | Alias | Target Timezone |
|---|---|---|---|
| `utc`, `gmt`, `zulu` | `UTC` | `ny`, `nyc`, `newyork` | `America/New_York` |
| `tokyo`, `japan` | `Asia/Tokyo` | `la`, `losangeles` | `America/Los_Angeles` |
| `london`, `uk` | `Europe/London` | `chicago` | `America/Chicago` |
| `paris` | `Europe/Paris` | `toronto` | `America/Toronto` |
| `berlin`, `germany` | `Europe/Berlin` | `vancouver` | `America/Vancouver` |
| `amsterdam` | `Europe/Amsterdam` | `dubai`, `uae` | `Asia/Dubai` |
| `rome` | `Europe/Rome` | `tehran`, `iran` | `Asia/Tehran` |
| `madrid` | `Europe/Madrid` | `singapore` | `Asia/Singapore` |
| `zurich` | `Europe/Zurich` | `hongkong` | `Asia/Hong_Kong` |
| `moscow` | `Europe/Moscow` | `seoul`, `korea` | `Asia/Seoul` |
| `sydney` | `Australia/Sydney` | `cairo` | `Africa/Cairo` |

*(Any other valid file in `/usr/share/zoneinfo` is also supported directly or via case-insensitive search)*.

---

## License

MIT License.
