/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
	tlsTransport "github.com/daeuniverse/outbound/transport/tls"
)

// fragmentDialer applies ClientHello fragmentation to every TCP connection it
// dials.
//
// dae's own TLS and WebSocket transports fragment internally, but VLESS builds
// its TLS inside mihomo, so tls_fragment has to be injected underneath the
// protocol instead. FragmentConn keys off the TLS record type, splitting only
// handshake records and passing everything else through untouched.
type fragmentDialer struct {
	nextDialer  netproxy.Dialer
	minLength   int64
	maxLength   int64
	minInterval int64
	maxInterval int64
}

func newFragmentDialer(nextDialer netproxy.Dialer, lengthRange, intervalRange string) (*fragmentDialer, error) {
	minLength, maxLength, err := parseFragmentRange(lengthRange)
	if err != nil {
		return nil, fmt.Errorf("tls_fragment_length: %w", err)
	}
	minInterval, maxInterval, err := parseFragmentRange(intervalRange)
	if err != nil {
		return nil, fmt.Errorf("tls_fragment_interval: %w", err)
	}
	return &fragmentDialer{
		nextDialer:  nextDialer,
		minLength:   minLength,
		maxLength:   maxLength,
		minInterval: minInterval,
		maxInterval: maxInterval,
	}, nil
}

func (d *fragmentDialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func (d *fragmentDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	conn, err := d.nextDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	// Only a TLS stream carries the handshake records worth splitting.
	if magicNetwork.Network != "tcp" {
		return conn, nil
	}
	return tlsTransport.NewFragmentConn(conn, d.minLength, d.maxLength, d.minInterval, d.maxInterval), nil
}

func parseFragmentRange(str string) (min, max int64, err error) {
	parts := strings.Split(str, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", str)
	}
	if min, err = strconv.ParseInt(parts[0], 10, 64); err != nil {
		return 0, 0, err
	}
	if max, err = strconv.ParseInt(parts[1], 10, 64); err != nil {
		return 0, 0, err
	}
	return min, max, nil
}
