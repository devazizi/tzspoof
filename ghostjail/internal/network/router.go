// Package network runs on the host side: a userspace TCP/IP stack
// (tun2socks/gVisor) fed by the jail's tun fd, with per-destination
// routing to an upstream proxy, direct dialing, or the DNS resolver.
package network

import (
	"context"
	"net"
	"net/netip"

	"github.com/xjasonlyu/tun2socks/v2/proxy"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// Router implements proxy.Proxy and picks a path per connection.
type Router struct {
	upstream proxy.Proxy
	direct   proxy.Proxy
	bypass   []netip.Prefix
	dns      *Resolver
}

var _ proxy.Proxy = (*Router)(nil)

// NewRouter routes destinations in bypass via direct (dialed from the host
// namespace, so host VPN routes apply) and the rest to upstream. With
// dohURLs, port 53 (UDP and TCP) is answered over DNS-over-HTTPS, which is
// itself dialed through the same routing.
func NewRouter(upstream, direct proxy.Proxy, bypass []netip.Prefix, dohURLs []string) *Router {
	r := &Router{upstream: upstream, direct: direct, bypass: bypass}
	if len(dohURLs) > 0 {
		r.dns = NewResolver(dohURLs, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return r.pick(dst.Addr()).DialContext(ctx, tcpMetadata(dst))
		})
	}
	return r
}

func (r *Router) pick(dst netip.Addr) proxy.Proxy {
	dst = dst.Unmap()
	for _, p := range r.bypass {
		if p.Contains(dst) {
			return r.direct
		}
	}
	return r.upstream
}

// DialContext handles TCP; TCP :53 is served by the resolver.
func (r *Router) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	if m.DstPort == 53 && r.dns != nil {
		return r.dns.tcpConn(), nil
	}
	return r.pick(m.DstIP).DialContext(ctx, m)
}

// DialUDP handles UDP; :53 is answered by the resolver.
func (r *Router) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	if m.DstPort == 53 && r.dns != nil {
		return r.dns.packetConn(m), nil
	}
	return r.pick(m.DstIP).DialUDP(m)
}
