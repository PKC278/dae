package vless

import (
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
)

var _ netproxy.PacketConn = (*packetConn)(nil)

// packetConn adapts the net.PacketConn shape used by mihomo/sing (net.Addr) to
// dae's netproxy.PacketConn (netip.AddrPort in, string out).
//
// targetAddr is the address dae dialed. It is the destination for the
// stream-style Write, and the source reported by ReadFrom when the remote does
// not carry one back.
type packetConn struct {
	net.PacketConn
	target     netip.AddrPort
	targetAddr string
}

func newPacketConn(pc net.PacketConn, targetAddr string) *packetConn {
	c := &packetConn{
		PacketConn: pc,
		targetAddr: targetAddr,
	}
	// A domain target has no AddrPort form; ReadFrom then reports whatever the
	// remote says.
	if ap, err := netip.ParseAddrPort(targetAddr); err == nil {
		c.target = ap
	}
	return c
}

func (c *packetConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *packetConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.targetAddr)
}

func (c *packetConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	n, from, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	return n, c.resolveFrom(from), nil
}

// resolveFrom normalizes the reported source. Anything that cannot be expressed
// as an AddrPort - a domain, or nothing at all - falls back to the dial target
// so dae's UDP session bookkeeping stays consistent.
func (c *packetConn) resolveFrom(from net.Addr) netip.AddrPort {
	switch v := from.(type) {
	case nil:
		return c.target
	case *net.UDPAddr:
		if ap := v.AddrPort(); ap.IsValid() {
			return c.sanitize(unmap(ap))
		}
	}
	if ap, err := netip.ParseAddrPort(from.String()); err == nil {
		return c.sanitize(unmap(ap))
	}
	return c.target
}

// sanitize rejects the placeholder destination, which XUDP echoes back when a
// Keep frame omits the address. Reporting it verbatim would hand dae an address
// its initial-reply guard cannot match.
func (c *packetConn) sanitize(ap netip.AddrPort) netip.AddrPort {
	if ap.Addr().IsUnspecified() {
		return c.target
	}
	return ap
}

func (c *packetConn) WriteTo(p []byte, addr string) (n int, err error) {
	// Deliberately unresolved: dae hands down domains in its "domain" dial
	// mode, and resolving here would both defeat remote resolution and fail for
	// names only the server can resolve. sing parses the string back into a
	// Socksaddr, keeping the FQDN intact.
	return c.PacketConn.WriteTo(p, stringAddr{network: "udp", addr: addr})
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
