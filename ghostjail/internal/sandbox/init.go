// Package sandbox runs inside the new namespaces: it builds the jail
// (mounts, hostname, network) and then executes the target command.
package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/sabz/ghostjail/internal/config"
	"github.com/sabz/ghostjail/internal/identity"
)

// InitArg is argv[1] that selects the in-jail init mode.
const InitArg = "__ghostjail_init"

// ctlFD is the control socket passed by the parent via ExtraFiles.
const ctlFD = 3

// ExitSetupFailed is returned when the jail could not be built.
const ExitSetupFailed = 125

// Messages on the control socket.
const (
	MsgTun   = "tun"   // child -> parent, carries the tun fd
	MsgNoTun = "notun" // child -> parent, no network engine needed
	MsgGo    = "go"    // parent -> child, network engine ready
)

// Init never returns: it execs the command or exits.
func Init() {
	// prctl(NO_NEW_PRIVS) is per-thread and must be set on the thread that
	// calls execve, so pin this goroutine to its OS thread for good.
	runtime.LockOSThread()

	unix.CloseOnExec(ctlFD)
	ctl, err := net.FileConn(os.NewFile(ctlFD, "ghostjail-ctl"))
	if err != nil {
		fatal(fmt.Errorf("control socket: %w", err))
	}
	conn := ctl.(*net.UnixConn)

	buf := make([]byte, 1<<20)
	n, err := conn.Read(buf)
	if err != nil {
		fatal(fmt.Errorf("read session: %w", err))
	}
	var s config.Session
	if err := json.Unmarshal(buf[:n], &s); err != nil {
		fatal(fmt.Errorf("decode session: %w", err))
	}

	tunFD, err := build(&s)
	if err != nil {
		fatal(err)
	}

	if tunFD >= 0 {
		_, _, err = conn.WriteMsgUnix([]byte(MsgTun), unix.UnixRights(tunFD), nil)
		unix.Close(tunFD)
	} else {
		_, err = conn.Write([]byte(MsgNoTun))
	}
	if err != nil {
		fatal(fmt.Errorf("handshake: %w", err))
	}
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != MsgGo {
		fatal(errors.New("host side did not start the network engine"))
	}
	conn.Close()

	execCommand(&s)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "ghostjail: %v\n", err)
	os.Exit(ExitSetupFailed)
}

func warn(s *config.Session, format string, args ...any) {
	if !s.Quiet {
		fmt.Fprintf(os.Stderr, "ghostjail: warning: "+format+"\n", args...)
	}
}

// build applies every mount/UTS/network change. Returns the tun fd (or -1).
func build(s *config.Session) (int, error) {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return -1, fmt.Errorf("make / private: %w", err)
	}
	sc, err := newScratch()
	if err != nil {
		return -1, err
	}
	defer sc.Close()

	if s.TZPath != "" {
		if err := applyTimezone(s, sc); err != nil {
			return -1, err
		}
	}
	if s.Hostname != "" {
		if err := applyHostname(s, sc); err != nil {
			return -1, err
		}
	}
	if s.MachineID != "" {
		if err := sc.WriteFile("machine-id", s.MachineID+"\n", 0o444); err != nil {
			return -1, err
		}
		for _, t := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if _, err := sc.replaceFile("machine-id", t); err != nil {
				return -1, err
			}
		}
	}

	tunFD := -1
	if s.Net != config.NetHost {
		if err := loUp(); err != nil {
			return -1, err
		}
	}
	if s.Net == config.NetProxy {
		if err := sc.WriteFile("resolv.conf", "nameserver "+config.TunDNSServer+"\n", 0o644); err != nil {
			return -1, err
		}
		if ok, err := sc.replaceFile("resolv.conf", "/etc/resolv.conf"); err != nil {
			return -1, err
		} else if !ok {
			warn(s, "/etc/resolv.conf does not exist; DNS inside the jail may not work")
		}
		if tunFD, err = createTun(); err != nil {
			return -1, err
		}
	}

	// Clone --ro/--rw sources before anything is masked, so a sample can
	// live under a path that --tmp-home/--private-tmp/--hide then hides.
	binds, err := cloneBinds(s.Binds)
	if err != nil {
		return -1, err
	}
	defer func() {
		for _, b := range binds {
			unix.Close(b.fd)
		}
	}()
	cwd, _ := unix.Getwd()

	if s.PrivateTmp {
		// /dev/shm is shared memory with host processes: an IPC channel.
		for _, d := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
			if st, err := os.Lstat(d); err != nil || !st.IsDir() {
				continue
			}
			if err := mountTmpfs(d, "1777"); err != nil {
				return -1, err
			}
		}
	}
	if s.PrivateRun {
		// Unix sockets ignore network namespaces, and supplementary groups
		// (e.g. docker) stay effective in the user namespace, so
		// /run/docker.sock would otherwise be a path to host root.
		if err := mountTmpfs("/run", "0755"); err != nil {
			return -1, err
		}
	}
	if s.TmpHome {
		home := os.Getenv("HOME")
		if home == "" || home == "/" {
			return -1, errors.New("--tmp-home: $HOME is not set")
		}
		if err := mountTmpfs(home, "0700"); err != nil {
			return -1, err
		}
	}
	for i, p := range s.Hide {
		if err := hidePath(sc, i, p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				warn(s, "--hide %s: path does not exist", p)
				continue
			}
			return -1, err
		}
	}
	if err := attachBinds(binds); err != nil {
		return -1, err
	}

	// The working directory still references the pre-mount tree; a masked
	// directory would stay readable through it. Re-resolve the path, and
	// fall back to $HOME when it no longer exists inside the jail.
	if err := os.Chdir(cwd); err != nil || cwd == "" {
		if err := os.Chdir(os.Getenv("HOME")); err != nil {
			_ = os.Chdir("/")
		}
	}
	return tunFD, nil
}

func applyTimezone(s *config.Session, sc *scratch) error {
	st, err := os.Lstat("/etc/localtime")
	switch {
	case err != nil:
		warn(s, "/etc/localtime does not exist; only $TZ is set")
	case st.Mode()&os.ModeSymlink != 0:
		// Keep the host's file type: a symlink stays a symlink, so
		// readlink-based detection (Java, Node, timedatectl) sees the zone.
		if err := sc.Symlink("localtime", s.TZPath); err != nil {
			return err
		}
		if err := mountOver(sc.fd, "localtime", true, "/etc/localtime"); err != nil {
			return err
		}
	default:
		if err := mountOver(unix.AT_FDCWD, s.TZPath, false, "/etc/localtime"); err != nil {
			return err
		}
	}
	if err := sc.WriteFile("timezone", s.TZName+"\n", 0o644); err != nil {
		return err
	}
	if _, err := sc.replaceFile("timezone", "/etc/timezone"); err != nil {
		warn(s, "could not replace /etc/timezone: %v", err)
	}
	return nil
}

func applyHostname(s *config.Session, sc *scratch) error {
	if err := unix.Sethostname([]byte(s.Hostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if err := sc.WriteFile("hostname", s.Hostname+"\n", 0o644); err != nil {
		return err
	}
	replace := map[string]string{"hostname": "/etc/hostname"}
	if orig, err := os.ReadFile("/etc/hosts"); err == nil {
		if err := sc.WriteFile("hosts", identity.HostsWithName(string(orig), s.Hostname), 0o644); err != nil {
			return err
		}
		replace["hosts"] = "/etc/hosts"
	}
	if orig, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		if err := sc.WriteFile("nsswitch.conf", identity.NsswitchFilesFirst(string(orig)), 0o644); err != nil {
			return err
		}
		replace["nsswitch.conf"] = "/etc/nsswitch.conf"
	}
	for name, target := range replace {
		if _, err := sc.replaceFile(name, target); err != nil {
			warn(s, "could not replace %s: %v", target, err)
		}
	}
	return nil
}

// hidePath masks a directory with an empty tmpfs or a file with an empty file.
func hidePath(sc *scratch, i int, p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("--hide %s: %w", p, err)
	}
	if st.IsDir() {
		return mountTmpfs(p, "0700")
	}
	name := fmt.Sprintf("hidden-%d", i)
	if err := sc.WriteFile(name, "", 0o400); err != nil {
		return err
	}
	return mountOver(sc.fd, name, false, p)
}

// proxyEnv are variables that would point programs at a host-loopback
// proxy that is unreachable from the jail's own loopback.
var proxyEnv = []string{"http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"}

// cleanEnvKeep are the variables kept with --clean-env.
var cleanEnvKeep = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"TERM": true, "COLORTERM": true, "LANG": true, "LANGUAGE": true,
}

// preloadVisible keeps only LD_PRELOAD entries that exist inside the jail
// (--tmp-home/--hide can mask them), avoiding ld.so errors in every process.
func preloadVisible(list string) string {
	var keep []string
	for _, p := range strings.FieldsFunc(list, func(r rune) bool { return r == ':' || r == ' ' }) {
		if _, err := os.Stat(p); err == nil {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ":")
}

func buildEnv(s *config.Session) []string {
	drop := map[string]bool{"LD_PRELOAD": true}
	for _, k := range proxyEnv {
		if s.Net != config.NetHost {
			drop[k] = true
			drop[strings.ToUpper(k)] = true
		}
	}
	// With --clean-env, set nothing that marks the session: samples check
	// for such variables. /etc/localtime and uname already carry the
	// spoofed identity, so $TZ and the GHOSTJAIL_* markers are not needed.
	set := map[string]string{}
	if !s.CleanEnv {
		set["GHOSTJAIL"] = "1"
		set["GHOSTJAIL_NET"] = s.Net
		if s.TZName != "" {
			set["TZ"] = s.TZName
			set["GHOSTJAIL_TZ"] = s.TZName
			set["GHOSTJAIL_TZ_PATH"] = s.TZPath
		}
		if s.Hostname != "" {
			set["GHOSTJAIL_HOSTNAME"] = s.Hostname
			set["HOSTNAME"] = s.Hostname
			set["HOST"] = s.Hostname
		}
	}
	preload := s.PreloadPath
	if !s.CleanEnv {
		if cur := os.Getenv("LD_PRELOAD"); cur != "" && !strings.Contains(cur, s.PreloadPath) {
			preload = strings.Trim(preload+":"+cur, ":")
		}
	}
	if preload = preloadVisible(preload); preload != "" {
		set["LD_PRELOAD"] = preload
	}

	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if drop[k] || strings.HasPrefix(k, "GHOSTJAIL") || strings.HasPrefix(k, "TZSPOOF") {
			continue
		}
		if s.CleanEnv && !cleanEnvKeep[k] && !strings.HasPrefix(k, "LC_") {
			continue
		}
		if _, overridden := set[k]; overridden {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range set {
		env = append(env, k+"="+v)
	}
	return env
}

// dropCapabilities clears the ambient and inheritable sets on this (the
// exec'ing) thread, so the command starts with no capabilities at all:
// execve as a non-zero uid then yields empty permitted/effective sets.
func dropCapabilities() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

func execCommand(s *config.Session) {
	argv := s.Command
	path, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghostjail: %v\n", err)
		os.Exit(127)
	}
	env := buildEnv(s)

	// No setuid/file-capability gains for anything started in the jail
	// (sudo, su, ping with caps). Inside the user namespace setuid root
	// could not work anyway; this makes the denial explicit.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fatal(fmt.Errorf("no_new_privs: %w", err))
	}
	if err := dropCapabilities(); err != nil {
		fatal(err)
	}
	err = syscall.Exec(path, argv, env)
	fmt.Fprintf(os.Stderr, "ghostjail: exec %s: %v\n", path, err)
	os.Exit(126)
}
