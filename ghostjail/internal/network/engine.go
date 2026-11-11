package network

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/proxy/direct"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"

	// Register upstream proxy schemes for proxy.Parse.
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/http"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/reject"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/shadowsocks"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/socks4"
	_ "github.com/xjasonlyu/tun2socks/v2/proxy/socks5"

	"github.com/sabz/ghostjail/internal/config"
)

// Options configures the host-side engine.
type Options struct {
	Proxy   string         // e.g. socks5://127.0.0.1:2080, direct://, reject://
	Bypass  []netip.Prefix // dialed directly from the host namespace
	DoH     []string       // DNS-over-HTTPS URLs; empty disables jail DNS
	LogFile string         // connection/DNS log; empty = silent
}

// Engine owns the userspace stack for one jail.
type Engine struct {
	stack  *stack.Stack
	tunnel *tunnel.Tunnel
}

// ParseProxy parses an upstream URL; a bare host:port means socks5.
func ParseProxy(s string) (proxy.Proxy, error) {
	if !strings.Contains(s, "://") {
		s = "socks5://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse proxy %q: %w", s, err)
	}
	p, err := proxy.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("proxy %q: %w", s, err)
	}
	return p, nil
}

// SetupLogging routes the stack's log to path (JSON lines), or discards it.
func SetupLogging(path string) error {
	if path == "" {
		log.SetLogger(zap.NewNop())
		return nil
	}
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{path}
	cfg.ErrorOutputPaths = []string{path}
	cfg.Sampling = nil // log every connection
	l, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("open log %s: %w", path, err)
	}
	log.SetLogger(l)
	return nil
}

// Start runs the stack on tunFD. The engine takes ownership of tunFD.
func Start(tunFD int, o Options) (*Engine, error) {
	upstream, err := ParseProxy(o.Proxy)
	if err != nil {
		return nil, err
	}
	directProxy, err := direct.New()
	if err != nil {
		return nil, err
	}
	router := NewRouter(upstream, directProxy, o.Bypass, o.DoH)

	dev, err := fdbased.Open(strconv.Itoa(tunFD), config.TunMTU, 0)
	if err != nil {
		return nil, fmt.Errorf("open tun fd: %w", err)
	}
	t := tunnel.New(router, statistic.DefaultManager)
	t.ProcessAsync()
	st, err := core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: t})
	if err != nil {
		t.Close()
		dev.Close()
		return nil, fmt.Errorf("create stack: %w", err)
	}
	return &Engine{stack: st, tunnel: t}, nil
}

// Close stops the stack.
func (e *Engine) Close() {
	e.tunnel.Close()
	e.stack.Close()
}
