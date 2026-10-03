/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/stretchr/testify/require"
)

type domainReplyConn struct {
	mockPacketConn
	first bool
	stop  chan struct{}
}

func (c *domainReplyConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	if !c.first {
		c.first = true
		return copy(b, "reply"), netip.AddrPort{}, nil
	}
	<-c.stop
	return 0, netip.AddrPort{}, io.EOF
}

func TestDomainProxyReplyWithoutSource(t *testing.T) {
	for _, mode := range []string{"read", "push"} {
		t.Run(mode, func(t *testing.T) {
			from := netip.MustParseAddrPort("203.0.113.7:4500")
			d, _ := newTestEndpointErrorDialer("vless", "127.0.0.1:443", io.EOF)
			t.Cleanup(func() { _ = d.Close() })
			replies := make(chan netip.AddrPort, 1)
			ue := &UdpEndpoint{Dialer: d, DialTarget: "remote.test:4500", poolKey: UdpEndpointKey{Dst: from},
				handler: func(_ *UdpEndpoint, b []byte, source netip.AddrPort) error {
					if string(b) != "reply" {
						return io.ErrUnexpectedEOF
					}
					replies <- source
					return nil
				},
			}
			if mode == "push" {
				ue.conn = &receiverConn{}
				require.True(t, ue.startTransportReceiver())
				t.Cleanup(func() { _ = ue.Close() })
				require.True(t, ue.handleReceivedPacket(netproxy.NewReceivedPacket([]byte("reply"), netip.AddrPort{}, nil, func() {})))
			} else {
				conn := &domainReplyConn{stop: make(chan struct{})}
				ue.conn = conn
				done := make(chan struct{})
				go func() { defer close(done); ue.startReadLoop() }()
				t.Cleanup(func() { close(conn.stop); <-done })
			}
			select {
			case got := <-replies:
				require.Equal(t, from, got)
				require.True(t, ue.hasReply.Load())
			case <-time.After(time.Second):
				t.Fatal("domain reply was dropped")
			}
		})
	}
}

func TestMissingReplySourceRemainsInvalidForDirectAndIPTargets(t *testing.T) {
	for _, protocol := range []string{"direct", "vless"} {
		for _, target := range []string{"remote.test:4500", "203.0.113.7:4500"} {
			address := "127.0.0.1:443"
			if protocol == "direct" {
				address = ""
			}
			d, _ := newTestEndpointErrorDialer(protocol, address, io.EOF)
			t.Cleanup(func() { _ = d.Close() })
			ue := &UdpEndpoint{Dialer: d, DialTarget: target, poolKey: UdpEndpointKey{Dst: receiverTestFrom()}}
			if protocol == "vless" && target == "remote.test:4500" {
				continue
			}
			require.False(t, ue.replySource(netip.AddrPort{}).IsValid())
			require.Equal(t, receiverTestFrom(), ue.replySource(receiverTestFrom()))
		}
	}
}
