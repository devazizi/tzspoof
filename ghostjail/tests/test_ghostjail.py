"""Hermetic integration tests for ghostjail.

Each test runs bin/ghostjail inside a throwaway user+mount namespace whose
/etc is a private copy-by-symlink of the real /etc with known fixtures for
localtime, timezone, hostname, hosts, nsswitch.conf and machine-id. Results
do not depend on the machine's real identity or an outer jail session.
Network tests use only local servers.

Requires Linux, Python >= 3.12 (os.unshare) and unprivileged user namespaces.
Run: python3 -I tests/test_ghostjail.py
"""

import ctypes
import hashlib
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GJ = ROOT / "bin" / "ghostjail"
ZONEINFO = Path("/usr/share/zoneinfo")
HOST_ZONE = "Europe/Paris"
HOST_NAME = "fixture-host"
HOST_MACHINE_ID = "0123456789abcdef0123456789abcdef"
NSSWITCH_HOSTS = "hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns"

MS_BIND, MS_REC, MS_PRIVATE = 0x1000, 0x4000, 1 << 18
_libc = ctypes.CDLL(None, use_errno=True)


def _mount(src, target, fstype, flags):
    if _libc.mount(src, target, fstype, ctypes.c_ulong(flags), None) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {src!r} -> {target!r}: {os.strerror(err)}")


def _inner(mountpoint: str, localtime_kind: str, cmd: str) -> None:
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
    fixtures = {"localtime", "timezone", "hostname", "hosts", "nsswitch.conf", "machine-id"}
    for entry in os.listdir(real_etc):
        if entry not in fixtures:
            (fake_etc / entry).symlink_to(real_etc / entry)

    zone_file = ZONEINFO / HOST_ZONE
    if localtime_kind == "symlink":
        (fake_etc / "localtime").symlink_to(zone_file)
    else:
        (fake_etc / "localtime").write_bytes(zone_file.read_bytes())
    (fake_etc / "timezone").write_text(HOST_ZONE + "\n")
    (fake_etc / "hostname").write_text(HOST_NAME + "\n")
    (fake_etc / "hosts").write_text(f"127.0.0.1 localhost\n127.0.1.1 {HOST_NAME}\n")
    (fake_etc / "nsswitch.conf").write_text(f"passwd: files\ngroup: files\n{NSSWITCH_HOSTS}\n")
    (fake_etc / "machine-id").write_text(HOST_MACHINE_ID + "\n")
    _mount(str(fake_etc).encode(), b"/etc", None, MS_BIND | MS_REC)

    env = {k: v for k, v in os.environ.items()
           if not (k in ("TZ", "LD_PRELOAD") or k.startswith(("TZSPOOF_", "GHOSTJAIL"))
                   or k.lower().endswith("_proxy"))}
    env["G"] = str(GJ)
    os.execve("/bin/sh", ["sh", "-c", cmd], env)


def sandbox(cmd: str, localtime: str = "symlink", timeout: int = 60) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix="ghostjail-test-") as mnt:
        return subprocess.run(
            [sys.executable, "-I", __file__, "--inner", mnt, localtime, cmd],
            capture_output=True, text=True, timeout=timeout,
        )


def lines(result: subprocess.CompletedProcess) -> list[str]:
    if result.returncode != 0:
        raise AssertionError(f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result.stdout.strip().splitlines()


RAW = "env -u LD_PRELOAD -u TZ"


@unittest.skipUnless(GJ.exists(), "run 'make' first")
class IdentityTest(unittest.TestCase):
    def test_symlinked_localtime(self):
        digest = hashlib.sha256((ZONEINFO / HOST_ZONE).read_bytes()).hexdigest()
        out = lines(sandbox(
            f"$G -q -t tokyo -- sh -c '{RAW} readlink /etc/localtime; {RAW} date +%Z; cat /etc/timezone; "
            f"{RAW} stat -c %F /etc/localtime; sha256sum {ZONEINFO / HOST_ZONE} | cut -c1-64'"))
        self.assertEqual(out, [str(ZONEINFO / "Asia/Tokyo"), "JST", "Asia/Tokyo", "symbolic link", digest])

    def test_regular_localtime(self):
        out = lines(sandbox(f"$G -q -t tokyo -- sh -c '{RAW} stat -c %F /etc/localtime; {RAW} date +%Z'",
                            localtime="regular"))
        self.assertEqual(out, ["regular file", "JST"])

    def test_hostname_and_lookups(self):
        out = lines(sandbox(
            "$G -q -H build-01 -- sh -c 'uname -n; cat /etc/hostname; getent ahostsv4 build-01 | head -1; "
            "getent hosts 127.0.1.1; grep ^hosts: /etc/nsswitch.conf'; uname -n"))
        self.assertEqual(out[:2], ["build-01", "build-01"])
        # IPv4 explicitly: for AAAA, nss-myhostname answers the current hostname with the
        # link-local addresses of whatever interfaces are up, which varies by machine.
        self.assertEqual(out[2].split(), ["127.0.1.1", "STREAM", "build-01"])
        self.assertEqual(out[3].split(), ["127.0.1.1", "build-01"])
        self.assertEqual(out[4], "hosts: files mymachines resolve [!UNAVAIL=return] myhostname dns")
        self.assertNotEqual(out[5], "build-01")

    def test_machine_id(self):
        out = lines(sandbox("$G -q --machine-id 89abcdef0123456789abcdef01234567 -- cat /etc/machine-id; "
                            "$G -q --machine-id random -- cat /etc/machine-id; cat /etc/machine-id"))
        self.assertEqual(out[0], "89abcdef0123456789abcdef01234567")
        self.assertRegex(out[1], r"^[0-9a-f]{32}$")
        self.assertNotIn(out[1], (HOST_MACHINE_ID, out[0]))
        self.assertEqual(out[2], HOST_MACHINE_ID)

    def test_nested_sessions(self):
        out = lines(sandbox("$G -q -t tokyo -H outer -- $G -q -t london -H inner -- "
                            f"sh -c 'cat /etc/timezone; uname -n; {RAW} readlink /etc/localtime'"))
        self.assertEqual(out, ["Europe/London", "inner", str(ZONEINFO / "Europe/London")])

    def test_command_gets_no_capabilities(self):
        out = lines(sandbox("$G -q -t utc -H x -- sh -c 'grep -E \"^(CapEff|CapPrm|CapAmb|CapInh|NoNewPrivs)\" "
                            "/proc/self/status | tr -s \"\\t\" \" \"'"))
        self.assertEqual(out, ["CapInh: 0000000000000000", "CapPrm: 0000000000000000",
                               "CapEff: 0000000000000000", "CapAmb: 0000000000000000", "NoNewPrivs: 1"])


@unittest.skipUnless(GJ.exists(), "run 'make' first")
class CliTest(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(sandbox("$G -q -- sh -c 'exit 7'").returncode, 7)
        self.assertEqual(sandbox("$G -q -- /nonexistent").returncode, 127)
        self.assertEqual(sandbox("$G -q -- sh -c 'kill -TERM $$'").returncode, 128 + 15)

    def test_rejects_bad_input(self):
        for args in ("-H -bad", "-t nowhere-zone", "--machine-id XYZ", "-n bogus", "--direct 10.0.0.0/8",
                     "--log /tmp/x", "-x socks5://h:1 --dns http://1.1.1.1/q", "--hide relative/path"):
            with self.subTest(args=args):
                res = sandbox(f"$G -q {args} -- true")
                self.assertEqual(res.returncode, 2, res.stderr)

    def test_command_arguments_not_parsed(self):
        out = lines(sandbox(f"$G -q -t utc -- {sys.executable} -I -c 'import sys; print(sys.argv[1:])' -H x"))
        self.assertEqual(out, ["['-H', 'x']"])


@unittest.skipUnless(GJ.exists(), "run 'make' first")
class FilesystemTest(unittest.TestCase):
    def test_analysis_preset(self):
        home = os.environ["HOME"]
        out = lines(sandbox(
            "cd \"$HOME\" && SSH_AUTH_SOCK=/x/agent KUBECONFIG=/x/kube SECRET_TOKEN=abc "
            "$G -q --analysis -- sh -c 'pwd; ls -A $HOME | wc -l; cat /tmp/* /var/tmp/* /dev/shm/* /run/* 2>&1 | grep -vc \"No such file\"; "
            "ip -br link | wc -l; "
            "env | grep -cE \"GHOSTJAIL|TZ=|LD_PRELOAD|SSH_AUTH_SOCK|KUBECONFIG|SECRET_TOKEN\"; "
            "grep NoNewPrivs /proc/self/status | cut -f2'"))
        self.assertEqual(out, [home, "0", "0", "1", "0", "1"])

    def test_private_run_hides_host_sockets(self):
        sock = socket.socket(socket.AF_UNIX)
        path = f"/run/user/{os.getuid()}/ghostjail-test-{os.getpid()}.sock"
        try:
            sock.bind(path)
        except OSError:
            self.skipTest("no writable /run/user/UID")
        try:
            out = lines(sandbox(f"$G -q -- sh -c 'test -S {path} && echo seen'; "
                                f"$G -q --private-run -- sh -c 'test -S {path} && echo seen || echo hidden'"))
        finally:
            sock.close()
            os.unlink(path)
        self.assertEqual(out, ["seen", "hidden"])

    def test_cwd_inside_hidden_home_falls_back(self):
        work = Path(os.environ["HOME"])
        out = lines(sandbox(f"cd {work} && $G -q --tmp-home -- sh -c 'pwd; ls -A | wc -l'"))
        self.assertEqual(out, [str(work), "0"])

    def test_ro_and_rw_binds_survive_masks(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"], prefix=".ghostjail-bind-") as d:
            (Path(d) / "sample.sh").write_text("#!/bin/sh\necho sample-ran\n")
            (Path(d) / "sample.sh").chmod(0o755)
            out_dir = Path(d) / "out"
            out_dir.mkdir()
            res = sandbox(
                f"cd {d} && $G -q --analysis --ro {d} --rw {out_dir} -- sh -c "
                f"'./sample.sh; touch {d}/x 2>/dev/null || echo ro-denied; echo hi > {out_dir}/report; "
                "ls -A $HOME'")
            self.assertEqual(lines(res), ["sample-ran", "ro-denied", Path(d).name])
            self.assertEqual((out_dir / "report").read_text(), "hi\n")

    def test_hide_file_and_dir(self):
        with tempfile.TemporaryDirectory(prefix="ghostjail-hide-") as d:
            (Path(d) / "secret").write_text("s3cret")
            out = lines(sandbox(f"$G -q --hide {d}/secret -- cat {d}/secret | wc -c; "
                                f"$G -q --hide {d} -- ls -A {d} | wc -l"))
            self.assertEqual(out, ["0", "0"])


class _Server:
    """Local HTTP server on the host's primary IPv4 (reachable via direct)."""

    def __enter__(self):
        ip = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True,
                            text=True).stdout.split("src ")[1].split()[0]
        handler = type("H", (http.server.BaseHTTPRequestHandler,), {
            "do_GET": lambda s: (s.send_response(204), s.end_headers()),
            "log_message": lambda *a: None,
        })
        self.srv = http.server.ThreadingHTTPServer((ip, 0), handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://{ip}:{self.srv.server_address[1]}/"
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def _has_route() -> bool:
    """IPv4 default route whose source address is outside the jail range.

    Inside a ghostjail proxy session the "host" address is the jail's own
    198.18.0.1, which a nested jail sees as its own tun0 address.
    """
    import ipaddress
    r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True)
    if r.returncode != 0 or "src " not in r.stdout:
        return False
    src = ipaddress.ip_address(r.stdout.split("src ")[1].split()[0])
    return src not in ipaddress.ip_network("198.18.0.0/15")


# No --noproxy '*': its quotes would break the single-quoted sh -c strings,
# and ghostjail drops *_proxy variables in network jails anyway.
CURL = "curl -sS --max-time 5 -o /dev/null -w %{http_code}"


@unittest.skipUnless(GJ.exists() and _has_route(),
                     "needs 'make' and an IPv4 default route outside 198.18.0.0/15 (not inside a ghostjail)")
class NetworkTest(unittest.TestCase):
    def test_none_has_only_loopback(self):
        with _Server() as s:
            res = sandbox(f"$G -q -n none -- sh -c 'ip -br link | cut -d\" \" -f1; {CURL} {s.url}'")
        self.assertEqual(res.stdout.split()[:1], ["lo"])
        self.assertTrue(res.stdout.strip().endswith("000"), res.stdout)

    def test_direct_upstream_and_log(self):
        with _Server() as s, tempfile.TemporaryDirectory() as d:
            log = Path(d) / "conn.log"
            out = lines(sandbox(f"$G -q -x direct:// --dns off -l {log} -- sh -c "
                                f"'ip -br link | cut -d\" \" -f1 | sort | tr \"\\n\" \" \"; echo; {CURL} {s.url}'"))
            self.assertEqual(out, ["lo tun0 ", "204"])
            self.assertIn("[TCP] 198.18.0.1:", log.read_text())

    def test_kill_switch_dead_proxy(self):
        with _Server() as s:
            out = lines(sandbox(f"$G -q -x socks5://127.0.0.1:1 --dns off -- sh -c '{CURL} {s.url} || true'"))
        self.assertEqual(out[-1], "000")

    def test_bypass_reaches_lan(self):
        with _Server() as s:
            out = lines(sandbox(f"$G -q -x reject:// --direct private --dns off -- {CURL} {s.url}"))
        self.assertEqual(out, ["204"])

    def test_host_loopback_unreachable(self):
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen()
        port = lsock.getsockname()[1]
        try:
            out = lines(sandbox(f"$G -q -x direct:// --direct 127.0.0.0/8 --dns off -- "
                                f"sh -c 'curl -sS --max-time 3 http://127.0.0.1:{port}/ "
                                "-o /dev/null -w %{http_code} || true'"))
        finally:
            lsock.close()
        self.assertEqual(out[-1], "000")  # jail loopback is its own

    def test_proxy_env_is_dropped(self):
        out = lines(sandbox("http_proxy=http://127.0.0.1:2080 HTTPS_PROXY=x $G -q -x direct:// --dns off -- "
                            "sh -c 'env | grep -ci _proxy || true'"))
        self.assertEqual(out, ["0"])


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--inner":
        _inner(sys.argv[2], sys.argv[3], sys.argv[4])
    if sys.version_info < (3, 12) or not hasattr(os, "unshare"):
        print("SKIP: tests require Python >= 3.12 (os.unshare)")
        sys.exit(0)
    unittest.main(verbosity=2)
