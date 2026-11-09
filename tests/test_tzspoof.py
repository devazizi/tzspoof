"""Hermetic regression tests for tzspoof.

Each test runs bin/tzspoof inside a throwaway user+mount namespace whose
/etc is a private copy-by-symlink of the real /etc, with /etc/localtime
and /etc/timezone replaced by known fixtures. This makes the host layout
(symlinked vs regular /etc/localtime) controllable and keeps results
independent of the machine's real timezone or an outer tzspoof session.

Requires Linux, Python >= 3.12 (os.unshare) and unprivileged user
namespaces. Run: python3 -I tests/test_tzspoof.py
"""

import ctypes
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TZSPOOF = ROOT / "bin" / "tzspoof"
ZONEINFO = Path("/usr/share/zoneinfo")
HOST_ZONE = "Europe/Paris"  # fixture zone for the fake host

MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 1 << 18

_libc = ctypes.CDLL(None, use_errno=True)


def _mount(src, target, fstype, flags):
    if _libc.mount(src, target, fstype, ctypes.c_ulong(flags), None) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {src!r} -> {target!r}: {os.strerror(err)}")


def _inner(mountpoint: str, localtime_kind: str, cmd: str) -> None:
    """Runs in the sandbox child: build a fake /etc, then exec cmd."""
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
    Path("/proc/self/setgroups").write_text("deny")
    Path("/proc/self/uid_map").write_text(f"{uid} {uid} 1\n")
    Path("/proc/self/gid_map").write_text(f"{gid} {gid} 1\n")
    _mount(None, b"/", None, MS_REC | MS_PRIVATE)
    _mount(b"tmpfs", mountpoint.encode(), b"tmpfs", 0)

    base = Path(mountpoint)
    real_etc, fake_etc = base / "realetc", base / "fakeetc"
    real_etc.mkdir()
    fake_etc.mkdir()
    _mount(b"/etc", str(real_etc).encode(), None, MS_BIND | MS_REC)
    for entry in os.listdir(real_etc):
        if entry not in ("localtime", "timezone"):
            (fake_etc / entry).symlink_to(real_etc / entry)

    zone_file = ZONEINFO / HOST_ZONE
    if localtime_kind == "symlink":
        (fake_etc / "localtime").symlink_to(zone_file)
    else:
        (fake_etc / "localtime").write_bytes(zone_file.read_bytes())
    (fake_etc / "timezone").write_text(HOST_ZONE + "\n")
    _mount(str(fake_etc).encode(), b"/etc", None, MS_BIND | MS_REC)

    env = {k: v for k, v in os.environ.items()
           if not (k == "TZ" or k == "LD_PRELOAD" or k.startswith("TZSPOOF_"))}
    env["T"] = str(TZSPOOF)
    # exec drops namespace capabilities (non-root uid), like a normal user shell.
    os.execve("/bin/sh", ["sh", "-c", cmd], env)


def sandbox(cmd: str, localtime: str = "symlink") -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix="tzspoof-test-") as mnt:
        return subprocess.run(
            [sys.executable, "-I", __file__, "--inner", mnt, localtime, cmd],
            capture_output=True, text=True, timeout=60,
        )


def lines(result: subprocess.CompletedProcess) -> list[str]:
    if result.returncode != 0:
        raise AssertionError(f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result.stdout.strip().splitlines()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Probes that bypass the preload hook and $TZ, so they see only the mounts.
RAW = "env -u LD_PRELOAD -u TZ"


@unittest.skipUnless(TZSPOOF.exists(), "run 'make' first")
class SymlinkHostTest(unittest.TestCase):
    """Host where /etc/localtime is a symlink (systemd default)."""

    def test_host_zone_file_is_not_overlaid(self):
        # Bug 1: mount(2) followed the symlink and replaced the host zone file.
        out = lines(sandbox(
            f"$T -q tokyo sh -c 'sha256sum {ZONEINFO / HOST_ZONE} | cut -d\" \" -f1; "
            f"TZ={HOST_ZONE} {RAW.replace('-u TZ', '')} date +%Z'"))
        self.assertEqual(out[0], sha256(ZONEINFO / HOST_ZONE))
        self.assertIn(out[1], ("CET", "CEST"))

    def test_mounts_alone_spoof_zone(self):
        out = lines(sandbox(
            f"$T -q tokyo sh -c '{RAW} readlink /etc/localtime; {RAW} date +%Z; "
            f"cat /etc/timezone; {RAW} stat -c %F /etc/localtime'"))
        self.assertEqual(out, [str(ZONEINFO / "Asia/Tokyo"), "JST", "Asia/Tokyo", "symbolic link"])

    def test_nested_session_replaces_timezone_file(self):
        # Bug 2: the outer session's unlinked temp file blocked the inner mount.
        res = sandbox(
            f"$T -q tokyo $T -q london sh -c 'cat /etc/timezone; {RAW} readlink /etc/localtime; "
            f"{RAW} date +%Z'")
        out = lines(res)
        self.assertEqual(out[:2], ["Europe/London", str(ZONEINFO / "Europe/London")])
        self.assertIn(out[2], ("GMT", "BST"))
        self.assertNotIn("Warning", res.stderr)

    def test_preload_lstat_matches_readlink(self):
        # Bug 3: lstat was redirected to the target and reported a regular file.
        out = lines(sandbox(
            "$T -q tokyo sh -c 'stat -c %F /etc/localtime; readlink /etc/localtime'"))
        self.assertEqual(out, ["symbolic link", str(ZONEINFO / "Asia/Tokyo")])

    def test_env_only_mode_hooks_are_consistent(self):
        out = lines(sandbox(
            "$T -q -e tokyo sh -c 'stat -c %F /etc/localtime; readlink /etc/localtime; date +%Z'"))
        self.assertEqual(out, ["symbolic link", str(ZONEINFO / "Asia/Tokyo"), "JST"])

    def test_env_only_open_nofollow_is_not_redirected(self):
        script = ("import os,errno\n"
                  "try:\n os.open('/etc/localtime', os.O_RDONLY | os.O_NOFOLLOW); print('opened')\n"
                  "except OSError as e:\n print(errno.errorcode[e.errno])")
        out = lines(sandbox(f"$T -q -e tokyo {sys.executable} -I -c \"{script}\""))
        self.assertEqual(out, ["ELOOP"])


@unittest.skipUnless(TZSPOOF.exists(), "run 'make' first")
class RegularFileHostTest(unittest.TestCase):
    """Host where /etc/localtime is a plain copy of the zone file."""

    def test_regular_file_stays_regular(self):
        res = sandbox(
            f"$T -q tokyo sh -c '{RAW} stat -c %F /etc/localtime; {RAW} date +%Z; "
            "readlink /etc/localtime || echo not-a-link'", localtime="regular")
        self.assertEqual(lines(res), ["regular file", "JST", "not-a-link"])


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--inner":
        _inner(sys.argv[2], sys.argv[3], sys.argv[4])
    if sys.version_info < (3, 12) or not hasattr(os, "unshare"):
        print("SKIP: tests require Python >= 3.12 (os.unshare)")
        sys.exit(0)
    unittest.main(verbosity=2)
