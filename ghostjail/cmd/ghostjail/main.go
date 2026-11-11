// Command ghostjail runs a command in a rootless jail with a spoofed
// identity (timezone, hostname, machine-id) and optional network
// isolation that routes all traffic through a proxy with a built-in
// kill switch.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/sabz/ghostjail/internal/config"
	"github.com/sabz/ghostjail/internal/identity"
	"github.com/sabz/ghostjail/internal/network"
	"github.com/sabz/ghostjail/internal/sandbox"
)

const version = "0.1.0"

const usage = `ghostjail %s - rootless identity spoofing and network jail

USAGE:
  ghostjail [run] [OPTIONS] [--] [COMMAND [ARGS...]]   (default: $SHELL)
  ghostjail zones [FILTER]                             list timezones
  ghostjail status                                     show the current session
  ghostjail version

IDENTITY:
  -t, --tz ZONE           timezone: alias (tokyo, ny), name (Europe/London) or search term
  -H, --hostname NAME     hostname (UTS namespace, /etc/hostname, /etc/hosts)
      --machine-id ID     replace /etc/machine-id: "random" or 32 lowercase hex characters

NETWORK:
  -n, --net MODE          host | none | proxy  (default: proxy if --proxy is set, else host)
  -x, --proxy URL         upstream for --net proxy: socks5://H:P, http://H:P, ss://..., direct://, reject://
                          (default socks5://127.0.0.1:2080). The jail has no other route: kill switch.
      --direct CIDR       dial CIDR directly from the host network (VPN/intranet); repeatable.
                          "private" = 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
      --dns URL           DNS-over-HTTPS endpoint with an IP host, repeatable, tried in order
                          (default https://1.1.1.1/dns-query, https://8.8.8.8/dns-query); "off" disables
  -l, --log FILE          log every connection and DNS query (JSON lines)

FILESYSTEM:
      --private-tmp       empty /tmp, /var/tmp and /dev/shm
      --private-run       empty /run: hides host sockets (docker.sock, D-Bus, ssh/gpg agents)
      --tmp-home          empty $HOME (hides ~/.ssh, ~/.kube, browser profiles, ...)
      --hide PATH         mask a file or directory; repeatable
      --ro PATH           expose PATH read-only (even under a hidden $HOME/tmp); repeatable
      --rw PATH           expose PATH read-write; repeatable
      --clean-env         start with a minimal environment (PATH, HOME, USER, SHELL, TERM, LANG, LC_*)
      --no-preload        do not inject libghostjail.so (it remaps "nobody" owners for tools like ssh)

PRESETS:
      --analysis          for unknown software: --net none (unless --proxy/--net given),
                          --private-tmp, --private-run, --tmp-home, random --machine-id,
                          --clean-env, --no-preload

OTHER:
  -q, --quiet             no banner or warnings
  -h, --help              this help
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == sandbox.InitArg {
		sandbox.Init() // never returns
	}
	os.Exit(cli(os.Args[1:]))
}

func cli(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "zones":
			filter := ""
			if len(args) > 1 {
				filter = args[1]
			}
			for _, z := range identity.ListZones(filter) {
				fmt.Println(z)
			}
			return 0
		case "status":
			return status()
		case "version", "--version", "-v":
			fmt.Println("ghostjail", version)
			return 0
		case "run":
			args = args[1:]
		}
	}

	s, netOpts, err := parseRun(args)
	if err == pflag.ErrHelp {
		fmt.Printf(usage, version)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghostjail: %v\n", err)
		return 2
	}
	if !s.Quiet {
		fmt.Fprintln(os.Stderr, banner(s, netOpts))
	}
	if s.Net == config.NetProxy {
		if err := network.SetupLogging(netOpts.LogFile); err != nil {
			fmt.Fprintf(os.Stderr, "ghostjail: %v\n", err)
			return 1
		}
	}
	code, err := runSession(s, netOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghostjail: %v\n", err)
	}
	return code
}

var privateNets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func parseRun(args []string) (*config.Session, network.Options, error) {
	var (
		tz, hostname, machineID, netMode, proxyURL, logFile                   string
		direct, hide, roBinds, rwBinds, dns                                   []string
		privateTmp, privateRun, tmpHome, analysis, quiet, cleanEnv, noPreload bool
	)
	fs := pflag.NewFlagSet("ghostjail", pflag.ContinueOnError)
	fs.SetInterspersed(false) // everything after the command belongs to it
	fs.Usage = func() {}
	fs.StringVarP(&tz, "tz", "t", "", "")
	fs.StringVarP(&hostname, "hostname", "H", "", "")
	fs.StringVar(&machineID, "machine-id", "", "")
	fs.StringVarP(&netMode, "net", "n", "", "")
	fs.StringVarP(&proxyURL, "proxy", "x", "", "")
	fs.StringArrayVar(&direct, "direct", nil, "")
	fs.StringArrayVar(&dns, "dns", nil, "")
	fs.StringVarP(&logFile, "log", "l", "", "")
	fs.BoolVar(&privateTmp, "private-tmp", false, "")
	fs.BoolVar(&privateRun, "private-run", false, "")
	fs.BoolVar(&tmpHome, "tmp-home", false, "")
	fs.StringArrayVar(&hide, "hide", nil, "")
	fs.StringArrayVar(&roBinds, "ro", nil, "")
	fs.StringArrayVar(&rwBinds, "rw", nil, "")
	fs.BoolVar(&cleanEnv, "clean-env", false, "")
	fs.BoolVar(&noPreload, "no-preload", false, "")
	fs.BoolVar(&analysis, "analysis", false, "")
	fs.BoolVarP(&quiet, "quiet", "q", false, "")
	if err := fs.Parse(args); err != nil {
		return nil, network.Options{}, err
	}

	s := &config.Session{Command: fs.Args(), Quiet: quiet, PrivateTmp: privateTmp, PrivateRun: privateRun, TmpHome: tmpHome}
	var o network.Options

	if analysis {
		s.PrivateTmp, s.PrivateRun, s.TmpHome = true, true, true
		cleanEnv, noPreload = true, true
		if machineID == "" {
			machineID = "random"
		}
		if netMode == "" && proxyURL == "" {
			netMode = config.NetNone
		}
	}

	if tz != "" {
		z, err := identity.ResolveZone(tz)
		if err != nil {
			return nil, o, err
		}
		s.TZName, s.TZPath = z.Name, z.Path
	}
	if hostname != "" {
		if !identity.ValidHostname(hostname) {
			return nil, o, fmt.Errorf("invalid hostname %q (letters, digits, '-' and '.'; max 64 chars, 63 per label)", hostname)
		}
		s.Hostname = hostname
	}
	switch machineID {
	case "":
	case "random":
		id, err := identity.RandomMachineID()
		if err != nil {
			return nil, o, err
		}
		s.MachineID = id
	default:
		if !identity.ValidMachineID(machineID) {
			return nil, o, fmt.Errorf("invalid --machine-id (want 32 lowercase hex characters)")
		}
		s.MachineID = machineID
	}

	switch {
	case netMode == "" && proxyURL != "":
		netMode = config.NetProxy
	case netMode == "":
		netMode = config.NetHost
	}
	switch netMode {
	case config.NetHost, config.NetNone:
		if proxyURL != "" || len(direct) > 0 || logFile != "" {
			return nil, o, fmt.Errorf("--proxy, --direct and --log need --net proxy")
		}
	case config.NetProxy:
		if proxyURL == "" {
			proxyURL = "socks5://127.0.0.1:2080"
		}
		if _, err := network.ParseProxy(proxyURL); err != nil {
			return nil, o, err
		}
		o.Proxy = proxyURL
		for _, d := range direct {
			cidrs := []string{d}
			if d == "private" {
				cidrs = privateNets
			}
			for _, c := range cidrs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					return nil, o, fmt.Errorf("--direct %q: %w", c, err)
				}
				o.Bypass = append(o.Bypass, p.Masked())
			}
		}
		switch {
		case len(dns) == 0:
			o.DoH = network.DefaultDoH
		case len(dns) == 1 && dns[0] == "off":
		default:
			for _, u := range dns {
				if err := network.ValidateDoH(u); err != nil {
					return nil, o, fmt.Errorf("--dns: %w", err)
				}
			}
			o.DoH = dns
		}
		if logFile != "" {
			abs, err := filepath.Abs(logFile)
			if err != nil {
				return nil, o, err
			}
			o.LogFile = abs
		}
	default:
		return nil, o, fmt.Errorf("--net must be host, none or proxy")
	}
	s.Net = netMode

	home := os.Getenv("HOME")
	for _, h := range hide {
		if strings.HasPrefix(h, "~/") && home != "" {
			h = filepath.Join(home, h[2:])
		}
		if !filepath.IsAbs(h) {
			return nil, o, fmt.Errorf("--hide %q: path must be absolute", h)
		}
		s.Hide = append(s.Hide, filepath.Clean(h))
	}
	for i, list := range [][]string{roBinds, rwBinds} {
		for _, b := range list {
			abs, err := filepath.Abs(b)
			if err != nil {
				return nil, o, err
			}
			if _, err := os.Stat(abs); err != nil {
				return nil, o, fmt.Errorf("bind %s: %w", abs, err)
			}
			s.Binds = append(s.Binds, config.Bind{Path: abs, Writable: i == 1})
		}
	}

	if len(s.Command) == 0 {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/sh"
		}
		s.Command = []string{shell}
	}
	s.CleanEnv = cleanEnv
	if !noPreload {
		s.PreloadPath = findPreload()
	}
	return s, o, nil
}

// findPreload locates libghostjail.so next to the binary or in lib dirs.
func findPreload() string {
	var cands []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands, filepath.Join(dir, "libghostjail.so"), filepath.Join(dir, "..", "lib", "libghostjail.so"))
	}
	cands = append(cands, "/usr/local/lib/libghostjail.so", "/usr/lib/libghostjail.so")
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			return filepath.Clean(c)
		}
	}
	return ""
}

func banner(s *config.Session, o network.Options) string {
	parts := []string{"ghostjail:"}
	if s.TZName != "" {
		parts = append(parts, "tz="+s.TZName)
	}
	if s.Hostname != "" {
		parts = append(parts, "hostname="+s.Hostname)
	}
	if s.MachineID != "" {
		parts = append(parts, "machine-id="+s.MachineID[:8]+"...")
	}
	netDesc := "net=" + s.Net
	if s.Net == config.NetProxy {
		netDesc += " via " + o.Proxy
		if len(o.Bypass) > 0 {
			netDesc += fmt.Sprintf(" (direct: %d ranges)", len(o.Bypass))
		}
		if len(o.DoH) > 0 {
			netDesc += " dns=" + o.DoH[0]
		}
	}
	parts = append(parts, netDesc)
	if s.PrivateTmp {
		parts = append(parts, "private-tmp")
	}
	if s.PrivateRun {
		parts = append(parts, "private-run")
	}
	if s.TmpHome {
		parts = append(parts, "tmp-home")
	}
	if len(s.Hide) > 0 {
		parts = append(parts, fmt.Sprintf("hidden=%d", len(s.Hide)))
	}
	return strings.Join(parts, " ")
}

func status() int {
	if os.Getenv("GHOSTJAIL") != "1" {
		fmt.Println("not inside a ghostjail session")
		return 1
	}
	host, _ := os.Hostname()
	fmt.Printf("ghostjail session\n  timezone : %s\n  hostname : %s\n  network  : %s\n",
		orDash(os.Getenv("GHOSTJAIL_TZ")), host, os.Getenv("GHOSTJAIL_NET"))
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
