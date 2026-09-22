// Package vless wires mihomo's VLESS outbound into dae.
//
// dae owns the socket: every dial mihomo performs is routed back through dae's
// own dialer chain via C.Dialer, so SO_MARK, MPTCP and the rest keep working.
// Everything above the socket - the VLESS codec, Vision, the mlkem768x25519plus
// encryption suite, and the whole transport matrix (TLS, REALITY, ECH, JLS,
// Restls, ShadowTLS, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP) - is mihomo's,
// so dae tracks upstream by bumping the dependency rather than porting code.
package vless

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/netproxy"

	mo "github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

// Option is mihomo's VlessOption. It is aliased rather than mirrored so that
// new upstream fields become available without touching dae.
type Option = mo.VlessOption

// placeholderIP stands in for an unresolved XUDP destination. It is never put
// on the wire; see the comment at its use site.
var placeholderIP = netip.IPv4Unspecified()

type Dialer struct {
	proxy *mo.Vless
	// xudp mirrors the option: only Mux.Cool carries a destination in every
	// frame, which is what lets a domain target survive to the server.
	xudp bool
}

// NewDialer builds the VLESS outbound. nextDialer is used for every underlying
// connection mihomo opens.
func NewDialer(nextDialer netproxy.Dialer, option Option) (netproxy.Dialer, error) {
	option.DialerForAPI = &daeDialer{next: nextDialer}
	proxy, err := mo.NewVless(option)
	if err != nil {
		return nil, err
	}
	// NewVless normalizes the packet-encoding flags, so read the effective
	// value back rather than trusting what the caller passed in.
	return &Dialer{proxy: proxy, xudp: proxy.ProxyInfo().XUDP}, nil
}

func (d *Dialer) Close() error {
	return d.proxy.Close()
}

// PacketEncoding reports the UDP framing actually in effect, which is not
// always what was requested: mihomo forces XUDP whenever packet-addr is off,
// so plain single-destination VLESS UDP is not reachable through it.
func (d *Dialer) PacketEncoding() string {
	info := d.proxy.ProxyInfo()
	if info.XUDP {
		return "xudp"
	}
	return "packetaddr"
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	ctx = withMagicNetwork(ctx, magicNetwork)

	switch magicNetwork.Network {
	case "tcp":
		metadata, err := newMetadata(addr, C.TCP)
		if err != nil {
			return nil, err
		}
		conn, err := d.proxy.DialContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		// C.Conn embeds net.Conn, which already satisfies netproxy.Conn.
		return conn, nil
	case "udp":
		metadata, err := newMetadata(addr, C.UDP)
		if err != nil {
			return nil, err
		}
		// mihomo resolves an unresolved UDP destination locally before dialing.
		// dae resolves remotely on purpose, and the name may only be resolvable
		// by the server, so under XUDP we mark the metadata as resolved with a
		// placeholder. Mux.Cool puts no destination in the request header and
		// carries it per frame instead, where WriteTo supplies the real target,
		// so the placeholder never reaches the wire.
		if d.xudp && !metadata.Resolved() {
			metadata.DstIP = placeholderIP
		}
		pc, err := d.proxy.ListenPacketContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		return newPacketConn(pc, addr), nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

// newMetadata renders dae's dial target as mihomo metadata. A domain target
// stays a domain: dae resolves remotely by design, so Host is filled instead of
// DstIP whenever the target is not already an IP literal.
func newMetadata(addr string, network C.NetWork) (*C.Metadata, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse port of %q: %w", addr, err)
	}
	metadata := &C.Metadata{
		NetWork: network,
		DstPort: uint16(port),
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip.Unmap()
	} else {
		metadata.Host = host
	}
	return metadata, nil
}
