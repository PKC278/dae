package vless

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"

	C "github.com/metacubex/mihomo/constant"
)

// magicKey carries dae's per-dial MagicNetwork (mark, mptcp) down to the shim.
// mihomo's C.Dialer only sees a plain network string, so the options have to
// travel out of band.
type magicKey struct{}

func withMagicNetwork(ctx context.Context, mn *netproxy.MagicNetwork) context.Context {
	return context.WithValue(ctx, magicKey{}, mn)
}

func magicNetworkFrom(ctx context.Context) netproxy.MagicNetwork {
	if mn, ok := ctx.Value(magicKey{}).(*netproxy.MagicNetwork); ok && mn != nil {
		return *mn
	}
	return netproxy.MagicNetwork{}
}

// daeDialer presents dae's dialer to mihomo as a C.Dialer. Every connection
// mihomo's VLESS adapter opens - including the ones its gRPC and XHTTP
// transports open on their own - therefore still goes through dae's chain and
// keeps dae's socket mark, which is what stops the eBPF datapath from
// capturing dae's own traffic.
type daeDialer struct {
	next netproxy.Dialer
}

var _ C.Dialer = (*daeDialer)(nil)

func (d *daeDialer) encode(ctx context.Context, network string) string {
	mn := magicNetworkFrom(ctx)
	mn.Network = network
	return mn.Encode()
}

func (d *daeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := d.next.DialContext(ctx, d.encode(ctx, network), address)
	if err != nil {
		return nil, err
	}
	if nc, ok := c.(net.Conn); ok {
		return nc, nil
	}
	return &netproxy.FakeNetConn{
		Conn:  c,
		LAddr: stringAddr{network: network},
		RAddr: stringAddr{network: network, addr: address},
	}, nil
}

func (d *daeDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	target := address
	if target == "" && rAddrPort.IsValid() {
		target = rAddrPort.String()
	}
	c, err := d.next.DialContext(ctx, d.encode(ctx, "udp"), target)
	if err != nil {
		return nil, err
	}
	pc, ok := c.(netproxy.PacketConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("dae dialer returned %T, which is not a PacketConn", c)
	}
	return netproxy.NewFakeNetPacketConn(pc,
		stringAddr{network: "udp"},
		stringAddr{network: "udp", addr: target}), nil
}

// stringAddr is a net.Addr that never resolves its host, so a domain survives
// the trip to the wire instead of being turned into a local lookup result.
type stringAddr struct {
	network string
	addr    string
}

func (a stringAddr) Network() string {
	if a.network == "" {
		return "tcp"
	}
	return a.network
}

func (a stringAddr) String() string { return a.addr }
