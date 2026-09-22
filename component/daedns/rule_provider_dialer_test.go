/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestRouterWrapRuleProviderDialerUsesBootstrapForProviderHost(t *testing.T) {
	skipIfNoSocketMark(t)
	requestAddr, stopRequest := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.14"))
	defer stopRequest()
	bootstrapAddr, stopBootstrap := startTestDNSUDPServer(t, netip.MustParseAddr("198.51.100.14"))
	defer stopBootstrap()

	router, err := NewWithOption(logrus.New(), &config.Global{
		BootstrapResolver: bootstrapAddr,
	}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", requestAddr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
				},
				Fallback: "fallbackdns",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewWithOption() error = %v", err)
	}

	base := &stubDialer{}
	wrapped := router.WrapRuleProviderDialer(base, "rules.example.com")
	if wrapped == base {
		t.Fatal("expected WrapRuleProviderDialer to wrap base dialer for provider host")
	}

	resolver, ok := wrapped.(interface {
		LookupIPAddr(context.Context, string, string) ([]net.IPAddr, error)
	})
	if !ok {
		t.Fatal("wrapped dialer does not expose LookupIPAddr")
	}
	ips, err := resolver.LookupIPAddr(context.Background(), "tcp", "rules.example.com")
	if err != nil {
		t.Fatalf("LookupIPAddr() error = %v", err)
	}
	if base.lookupCalls != 0 {
		t.Fatalf("base lookup calls = %d, want 0", base.lookupCalls)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(198, 51, 100, 14)) {
		t.Fatalf("LookupIPAddr() = %v, want 198.51.100.14", ips)
	}
}

func TestRouterLookupRuleProviderIPAddrUsesBootstrapForProviderHost(t *testing.T) {
	skipIfNoSocketMark(t)
	requestAddr, stopRequest := startTestDNSUDPServer(t, netip.MustParseAddr("203.0.113.15"))
	defer stopRequest()
	bootstrapAddr, stopBootstrap := startTestDNSUDPServer(t, netip.MustParseAddr("198.51.100.15"))
	defer stopBootstrap()

	router, err := NewWithOption(logrus.New(), &config.Global{
		BootstrapResolver: bootstrapAddr,
	}, &config.Dns{
		Upstream: []config.KeyableString{
			config.KeyableString(fmt.Sprintf("fallbackdns:udp://%s", requestAddr)),
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					testInternalRule("fallbackdns", testInternalFunction("qname", testInternalParam("suffix", "example.com"))),
				},
				Fallback: "fallbackdns",
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewWithOption() error = %v", err)
	}

	ips, err := router.LookupRuleProviderIPAddr(context.Background(), "tcp", "rules.example.com")
	if err != nil {
		t.Fatalf("LookupRuleProviderIPAddr() error = %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.IPv4(198, 51, 100, 15)) {
		t.Fatalf("LookupRuleProviderIPAddr() = %v, want 198.51.100.15", ips)
	}
}
func testInternalRule(outbound string, andFunctions ...*config_parser.Function) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     config_parser.Function{Name: outbound},
	}
}

func testInternalFunction(name string, params ...*config_parser.Param) *config_parser.Function {
	return &config_parser.Function{
		Name:   name,
		Params: params,
	}
}

func testInternalParam(key, value string) *config_parser.Param {
	return &config_parser.Param{
		Key: key,
		Val: value,
	}
}

type stubDialer struct {
	lookupResult  []net.IPAddr
	lookupErr     error
	lookupCalls   int
	lookupNetwork string
	lookupHost    string
}

func (d *stubDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return nil, fmt.Errorf("unexpected dial")
}

func (d *stubDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.lookupCalls++
	d.lookupNetwork = network
	d.lookupHost = host
	if d.lookupErr != nil {
		return nil, d.lookupErr
	}
	return d.lookupResult, nil
}

// skipIfNoSocketMark skips the test if the process lacks permission to set
// SO_MARK on sockets (e.g. CI containers without CAP_NET_ADMIN).
func skipIfNoSocketMark(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("skipping: cannot create socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 0)
	if err != nil {
		t.Skipf("skipping: SO_MARK not permitted (need CAP_NET_ADMIN): %v", err)
	}
}

func startTestDNSUDPServer(t *testing.T, addr netip.Addr) (string, func()) {
	return startTestDNSUDPServerWithResponse(t, func(question dnsmessage.Question) []dnsmessage.RR {
		if question.Qtype != dnsmessage.TypeA {
			return nil
		}
		return []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{Name: question.Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET, Ttl: 60},
			A:   addr.AsSlice(),
		}}
	})
}

func startTestDNSUDPServerWithResponse(t *testing.T, answerFunc func(dnsmessage.Question) []dnsmessage.RR) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, remoteAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Msg
			if err = req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := dnsmessage.Msg{MsgHdr: dnsmessage.MsgHdr{Id: req.Id, Response: true, RecursionAvailable: true}, Question: req.Question}
			resp.Answer = append(resp.Answer, answerFunc(req.Question[0])...)
			wire, packErr := resp.Pack()
			if packErr != nil {
				continue
			}
			_, _ = pc.WriteTo(wire, remoteAddr)
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}
