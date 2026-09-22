/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

// ChainDial carries a chained node's connection through whichever dialer this
// group currently selects. It is the entry point a node registers against when
// its link ends in "-> group://<name>", so the chain follows the group's live
// health state and selection policy instead of a fixed first hop.
func (g *DialerGroup) ChainDial(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	networkType, err := chainNetworkType(network, addr)
	if err != nil {
		return nil, fmt.Errorf("chain through group %v: %w", g.Name, err)
	}
	d, _, _, err := g.SelectWithExclusionResult(networkType, false, nil)
	if err != nil {
		g.Resuscitate(networkType)
		return nil, fmt.Errorf("chain through group %v: %w", g.Name, err)
	}
	return d.DialContext(ctx, network, addr)
}

// chainNetworkType derives the health domain the chain hop is selected from.
// The address family of the hop's own destination decides the IP version,
// because that is the family the selected node has to be able to reach.
func chainNetworkType(network, addr string) (*dialer.NetworkType, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	l4proto := consts.L4ProtoStr_TCP
	switch magicNetwork.Network {
	case "udp", "udp4", "udp6":
		l4proto = consts.L4ProtoStr_UDP
	}
	return &dialer.NetworkType{
		L4Proto:         l4proto,
		IpVersion:       chainIpVersion(magicNetwork.IPVersion, addr),
		IsDns:           false,
		UdpHealthDomain: dialer.UdpHealthDomainData,
	}, nil
}

func chainIpVersion(magicIpVersion string, addr string) consts.IpVersionStr {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if version := consts.IpVersionFromAddr(ip); version != "" {
			return version
		}
	}
	switch magicIpVersion {
	case string(consts.IpVersionStr_4), string(consts.IpVersionStr_6):
		return consts.IpVersionStr(magicIpVersion)
	}
	// A domain that the group's node resolves itself: IPv4 reachability is the
	// one every node is expected to have.
	return consts.IpVersionStr_4
}
