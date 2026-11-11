package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xjasonlyu/tun2socks/v2/proxy"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// fakeProxy records which path a dial took.
type fakeProxy struct{ name string }

func (f *fakeProxy) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	return nil, &net.OpError{Op: f.name}
}
func (f *fakeProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	return nil, &net.OpError{Op: f.name}
}

var _ proxy.Proxy = (*fakeProxy)(nil)

func TestRouterPick(t *testing.T) {
	up, direct := &fakeProxy{"up"}, &fakeProxy{"direct"}
	bypass := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")}
	r := NewRouter(up, direct, bypass, nil)
	cases := map[string]proxy.Proxy{
		"10.1.2.3": direct, "192.168.113.5": direct, "1.1.1.1": up, "172.16.0.1": up,
		"::ffff:10.0.0.1": direct, // v4-mapped addresses are unmapped first
	}
	for ip, want := range cases {
		if got := r.pick(netip.MustParseAddr(ip)); got != want {
			t.Errorf("pick(%s) = %v, want %v", ip, got.(*fakeProxy).name, want.(*fakeProxy).name)
		}
	}
	// Without DoH, :53 is routed like any other destination.
	if _, err := r.DialUDP(&M.Metadata{DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 53}); err.(*net.OpError).Op != "up" {
		t.Errorf("UDP :53 without DoH went %v", err)
	}
}

func TestValidateDoH(t *testing.T) {
	if err := ValidateDoH("https://1.1.1.1/dns-query"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"http://1.1.1.1/dns-query", "https://dns.google/dns-query", "1.1.1.1"} {
		if ValidateDoH(bad) == nil {
			t.Errorf("ValidateDoH(%q) accepted", bad)
		}
	}
}

func query(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// newDoHServer echoes the query back with QR set, like a minimal resolver.
func newDoHServer(t *testing.T) (*httptest.Server, *Resolver) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q, _ := io.ReadAll(r.Body)
		q[2] |= 0x80 // QR: response
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(q)
	}))
	t.Cleanup(srv.Close)
	dialed := 0
	res := NewResolver([]string{"https://192.0.2.1/unreachable", srv.URL + "/dns-query"},
		func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			dialed++
			var d net.Dialer
			return d.DialContext(ctx, "tcp", dst.String())
		})
	tr := res.client.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	res.client.Timeout = 3 * time.Second
	return srv, res
}

func TestResolverFallsBackAndAnswers(t *testing.T) {
	srv, res := newDoHServer(t)
	q := query(t, "example.com.")
	resp, via, err := res.Exchange(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if via != srv.URL+"/dns-query" || resp[2]&0x80 == 0 || !bytes.Equal(resp[3:], q[3:]) {
		t.Errorf("via=%s resp=%x", via, resp)
	}
	if got := describeQuery(q); got != "example.com. TypeA" {
		t.Errorf("describeQuery = %q", got)
	}
}

func TestResolverUDPAndTCPFraming(t *testing.T) {
	_, res := newDoHServer(t)
	q := query(t, "a.test.")

	pc := res.packetConn(&M.Metadata{DstIP: netip.MustParseAddr("198.18.0.2"), DstPort: 53})
	defer pc.Close()
	if _, err := pc.WriteTo(q, nil); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || from.String() != "198.18.0.2:53" || buf[2]&0x80 == 0 || n != len(q) {
		t.Fatalf("UDP: n=%d from=%v err=%v", n, from, err)
	}

	c := res.tcpConn()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(frame, q...)); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, resp); err != nil || resp[2]&0x80 == 0 {
		t.Fatalf("TCP: resp=%x err=%v", resp, err)
	}
}

func TestPacketConnDeadline(t *testing.T) {
	_, res := newDoHServer(t)
	pc := res.packetConn(&M.Metadata{DstIP: netip.MustParseAddr("198.18.0.2"), DstPort: 53})
	defer pc.Close()
	_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := pc.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatal("ReadFrom without a query returned no error")
	}
}
