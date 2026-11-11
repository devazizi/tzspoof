package sandbox

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/sabz/ghostjail/internal/config"
)

// loUp brings loopback up in the fresh network namespace.
func loUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find lo: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("lo up: %w", err)
	}
	return nil
}

// createTun creates and configures tun0 as the only route out of the jail
// and returns its fd. IPv6 gets no route, so v6 traffic cannot leave.
func createTun() (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(config.TunName)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", err)
	}

	link, err := netlink.LinkByName(config.TunName)
	if err == nil {
		err = netlink.LinkSetMTU(link, config.TunMTU)
	}
	if err == nil {
		var addr *netlink.Addr
		if addr, err = netlink.ParseAddr(config.TunAddr); err == nil {
			err = netlink.AddrAdd(link, addr)
		}
	}
	if err == nil {
		err = netlink.LinkSetUp(link)
	}
	if err == nil {
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		})
	}
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("configure %s: %w", config.TunName, err)
	}
	return fd, nil
}
