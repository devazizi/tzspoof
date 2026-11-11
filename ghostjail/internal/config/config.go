// Package config holds the session settings shared by the host-side
// parent and the in-jail init process.
package config

// Network modes.
const (
	NetHost  = "host"  // share the host network (no network namespace)
	NetNone  = "none"  // loopback only
	NetProxy = "proxy" // everything through the userspace stack (proxy/direct/DNS)
)

// Jail-side addressing for NetProxy. 198.18.0.0/15 is reserved for
// benchmarking (RFC 2544) and does not collide with corporate ranges.
const (
	TunName      = "tun0"
	TunAddr      = "198.18.0.1/15"
	TunDNSServer = "198.18.0.2" // any UDP/TCP :53 is intercepted; this is just the resolv.conf target
	TunMTU       = 1500
)

// Bind exposes a host path at the same path inside the jail, applied after
// all masks so it stays visible under --tmp-home/--private-tmp/--hide.
type Bind struct {
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
}

// Session is sent from the parent to the init process over the control socket.
type Session struct {
	Command []string `json:"command"`

	TZName   string `json:"tz_name,omitempty"`
	TZPath   string `json:"tz_path,omitempty"`
	Hostname string `json:"hostname,omitempty"`

	// MachineID replaces /etc/machine-id (and /var/lib/dbus/machine-id).
	MachineID string `json:"machine_id,omitempty"`

	Net string `json:"net"`

	PrivateTmp bool     `json:"private_tmp"` // /tmp, /var/tmp, /dev/shm
	PrivateRun bool     `json:"private_run"` // /run: hides host sockets (docker, D-Bus, agents)
	TmpHome    bool     `json:"tmp_home"`
	Hide       []string `json:"hide,omitempty"` // absolute paths to mask
	Binds      []Bind   `json:"binds,omitempty"`

	PreloadPath string `json:"preload_path,omitempty"`
	// CleanEnv starts the command with a minimal environment instead of
	// inheriting the caller's (tokens, agent sockets, KUBECONFIG, ...).
	CleanEnv bool `json:"clean_env"`
	Quiet    bool `json:"quiet"`
}
