/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

type tcpFastOpenDialer struct {
	fallbackResolver string
}

func newTCPFastOpenDialer(fallbackResolver string) netproxy.Dialer {
	return &tcpFastOpenDialer{fallbackResolver: fallbackResolver}
}

func (d *tcpFastOpenDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTCP(ctx, addr, int(magicNetwork.Mark), magicNetwork.IPVersion, magicNetwork.Mptcp, false)
	case "udp":
		return direct.SymmetricDirect.DialContext(ctx, network, addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *tcpFastOpenDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if resolver, ok := direct.SymmetricDirect.(interface {
		LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
	}); ok {
		return resolver.LookupIPAddr(ctx, network, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

func (d *tcpFastOpenDialer) dialTCP(ctx context.Context, addr string, mark int, ipVersion string, mptcp bool, fallback bool) (c net.Conn, err error) {
	network := preferredTCPNetwork(ipVersion)
	if d.fallbackResolver != "" && !fallback {
		defer func() {
			d.tryRetry(err, addr, func() {
				c, err = d.dialTCP(ctx, addr, mark, ipVersion, mptcp, true)
			})
		}()
	}
	var dialer net.Dialer
	if mptcp {
		dialer.SetMultipathTCP(true)
	}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		if mark != 0 {
			if err := SoMarkControl(c, mark); err != nil {
				return err
			}
		}
		return tcpFastOpenControl(c)
	}
	dialer.Resolver = d.createResolver(mark, fallback)
	return dialer.DialContext(ctx, network, addr)
}

func (d *tcpFastOpenDialer) createResolver(mark int, fallback bool) *net.Resolver {
	if mark == 0 && !fallback {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			if mark != 0 {
				dialer.Control = func(network, address string, c syscall.RawConn) error {
					return SoMarkControl(c, mark)
				}
			}
			if fallback {
				return dialer.DialContext(ctx, network, d.fallbackResolver)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func (d *tcpFastOpenDialer) tryRetry(err error, addr string, callback func()) {
	host, _, _ := net.SplitHostPort(addr)
	if _, e := netip.ParseAddr(host); e == nil {
		return
	}
	if err != nil && outbounderrors.IsDNSTimeout(err) {
		callback()
	}
}

func preferredTCPNetwork(ipVersion string) string {
	switch ipVersion {
	case "4", "6":
		return "tcp" + ipVersion
	default:
		return "tcp"
	}
}
