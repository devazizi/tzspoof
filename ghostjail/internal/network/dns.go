package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xjasonlyu/tun2socks/v2/log"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

const (
	dnsTimeout     = 10 * time.Second
	maxDNSResponse = 65535
)

// DefaultDoH are DNS-over-HTTPS endpoints with IP-literal hosts (their
// certificates carry IP SANs), so no bootstrap resolution is needed.
var DefaultDoH = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}

// dialFunc dials a TCP destination from the host side (proxy or direct).
type dialFunc func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)

// Resolver answers jail DNS over DNS-over-HTTPS (RFC 8484). Port 443
// passes networks that block DNS-over-TLS (853); queries never touch the
// host resolver. Every query is logged (useful when analysing samples).
type Resolver struct {
	urls   []string
	client *http.Client
}

// ValidateDoH checks that u is an https URL with an IP-literal host.
func ValidateDoH(u string) error {
	p, err := url.Parse(u)
	if err != nil {
		return err
	}
	if p.Scheme != "https" {
		return fmt.Errorf("DoH URL must use https: %s", u)
	}
	if _, err := netip.ParseAddr(p.Hostname()); err != nil {
		return fmt.Errorf("DoH URL host must be an IP address (no bootstrap DNS): %s", u)
	}
	return nil
}

// NewResolver tries urls in order, dialing through dial.
func NewResolver(urls []string, dial dialFunc) *Resolver {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil {
				return nil, err
			}
			return dial(ctx, ap)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: dnsTimeout,
		Proxy:               nil, // never use host proxy env vars
	}
	return &Resolver{urls: urls, client: &http.Client{Transport: tr, Timeout: dnsTimeout}}
}

// Exchange sends one DNS message and returns the response and the URL used.
func (r *Resolver) Exchange(ctx context.Context, query []byte) ([]byte, string, error) {
	var lastErr error
	for _, u := range r.urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(query))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := r.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSResponse))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
			continue
		}
		return body, u, nil
	}
	return nil, "", lastErr
}

func (r *Resolver) exchangeLogged(query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	resp, via, err := r.Exchange(ctx, query)
	if err != nil {
		log.Warnf("[DNS] %s: %v", describeQuery(query), err)
		return nil, err
	}
	log.Infof("[DNS] %s via %s", describeQuery(query), via)
	return resp, nil
}

func describeQuery(q []byte) string {
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return "unparsable"
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return "no-question"
	}
	return fmt.Sprintf("%s %s", qs[0].Name.String(), qs[0].Type)
}

// tcpConn serves DNS-over-TCP (2-byte length framing) for one jail connection.
func (r *Resolver) tcpConn() net.Conn {
	jailSide, ours := net.Pipe()
	go func() {
		defer ours.Close()
		var size [2]byte
		for {
			if _, err := io.ReadFull(ours, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(ours, query); err != nil {
				return
			}
			resp, err := r.exchangeLogged(query)
			if err != nil {
				return
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out, uint16(len(resp)))
			copy(out[2:], resp)
			if _, err := ours.Write(out); err != nil {
				return
			}
		}
	}()
	return jailSide
}

// dnsPacketConn is a net.PacketConn whose writes are DNS queries and whose
// reads return the answers, appearing to come from the original server.
type dnsPacketConn struct {
	r    *Resolver
	from net.Addr

	replies  chan []byte
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func (r *Resolver) packetConn(m *M.Metadata) *dnsPacketConn {
	return &dnsPacketConn{
		r:       r,
		from:    net.UDPAddrFromAddrPort(netip.AddrPortFrom(m.DstIP, m.DstPort)),
		replies: make(chan []byte, 16),
		closed:  make(chan struct{}),
	}
}

func (c *dnsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	query := append([]byte(nil), b...)
	go func() {
		resp, err := c.r.exchangeLogged(query)
		if err != nil {
			return
		}
		select {
		case c.replies <- resp:
		case <-c.closed:
		}
	}()
	return len(b), nil
}

func (c *dnsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case resp := <-c.replies:
		return copy(p, resp), c.from, nil
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *dnsPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *dnsPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (c *dnsPacketConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *dnsPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *dnsPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*dnsPacketConn)(nil)

// tcpMetadata builds tun2socks metadata for a host-side TCP dial.
func tcpMetadata(dst netip.AddrPort) *M.Metadata {
	return &M.Metadata{Network: M.TCP, DstIP: dst.Addr(), DstPort: dst.Port()}
}
