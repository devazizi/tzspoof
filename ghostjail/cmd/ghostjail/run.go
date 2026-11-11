package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/sabz/ghostjail/internal/config"
	"github.com/sabz/ghostjail/internal/network"
	"github.com/sabz/ghostjail/internal/sandbox"
)

// runSession starts the init process in new namespaces, serves its network
// (if any) from the host namespace, and returns the command's exit code.
func runSession(s *config.Session, netOpts network.Options) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("locate own binary: %w", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 1, fmt.Errorf("socketpair: %w", err)
	}
	parentEnd := os.NewFile(uintptr(fds[0]), "ghostjail-ctl")
	childEnd := os.NewFile(uintptr(fds[1]), "ghostjail-ctl-child")
	defer parentEnd.Close()

	cloneFlags := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWNS)
	if s.Hostname != "" {
		cloneFlags |= unix.CLONE_NEWUTS
	}
	if s.Net != config.NetHost {
		cloneFlags |= unix.CLONE_NEWNET
	}
	uid, gid := os.Getuid(), os.Getgid()

	cmd := exec.Command(self, sandbox.InitArg)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childEnd}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		// Same IDs inside: files, prompts and permissions stay as they are.
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		// Exec as a non-zero uid would drop the namespace capabilities the
		// init stage needs (mounts, sethostname, tun/netlink). Ambient caps
		// survive that exec; init clears them before running the command.
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN},
	}

	// Caught (not ignored) signals are reset to default in the child by
	// execve, so the jailed command still gets Ctrl+C from the terminal
	// while this process keeps serving its network until it exits.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM, unix.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		childEnd.Close()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSPC) {
			return 1, fmt.Errorf("cannot create user namespace (%v); check kernel.unprivileged_userns_clone and user.max_user_namespaces", err)
		}
		return 1, fmt.Errorf("start jail: %w", err)
	}
	childEnd.Close()

	go func() {
		for sig := range sigs {
			// The terminal already delivers INT/QUIT to the whole
			// foreground process group; forward the rest.
			if sig == unix.SIGTERM || sig == unix.SIGHUP {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	engine, err := handshake(parentEnd, s, netOpts)
	if engine != nil {
		defer engine.Close()
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 1, err
	}
	return exitCode(cmd.Wait()), nil
}

// handshake sends the session, receives the tun fd and starts the engine.
// If the child dies during setup it already printed why; the caller then
// reports the child's own exit code.
func handshake(f *os.File, s *config.Session, netOpts network.Options) (*network.Engine, error) {
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()

	payload, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, nil // child exited before setup; its status tells the story
	}

	buf := make([]byte, 64)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil || n == 0 {
		return nil, nil // setup failed inside the jail
	}

	var engine *network.Engine
	if string(buf[:n]) == sandbox.MsgTun {
		tunFD, err := parseFD(oob[:oobn])
		if err != nil {
			return nil, err
		}
		if engine, err = network.Start(tunFD, netOpts); err != nil {
			unix.Close(tunFD)
			return nil, err
		}
	}
	// A write error means the child died; Wait reports its status.
	_, _ = conn.Write([]byte(sandbox.MsgGo))
	return engine, nil
}

func parseFD(oob []byte) (int, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil || len(msgs) != 1 {
		return -1, fmt.Errorf("no tun fd received: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return -1, fmt.Errorf("bad tun fd message: %v", err)
	}
	return fds[0], nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "ghostjail: wait: %v\n", err)
	return 1
}
