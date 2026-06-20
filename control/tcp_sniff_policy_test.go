/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func mustParseTcpSniffAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort(s)
}

func TestShouldTryTcpSniffAllowsAmbiguousDirectRouting(t *testing.T) {
	cp := &ControlPlane{sniffingTimeout: time.Second}
	dst := mustParseTcpSniffAddrPort(t, "198.51.100.20:443")

	if cp.shouldTryTcpSniff(dst, &bpfRoutingResult{Outbound: uint8(consts.OutboundDirect)}) {
		t.Fatal("plain direct routing should not sniff")
	}
	if !cp.shouldTryTcpSniff(dst, &bpfRoutingResult{
		Outbound:  uint8(consts.OutboundDirect),
		NeedSniff: 1,
	}) {
		t.Fatal("ambiguous direct routing should sniff")
	}
}

func TestShouldTryTcpSniffRequiresAmbiguousDomainAcrossNormalExclusions(t *testing.T) {
	cp := &ControlPlane{
		sniffingTimeout: time.Second,
		controlPlaneGenerationState: controlPlaneGenerationState{
			dialMode: consts.DialMode_Ip,
		},
	}
	routingResult := &bpfRoutingResult{Outbound: uint8(consts.OutboundDirect), NeedSniff: 1}
	if !cp.shouldTryTcpSniff(mustParseTcpSniffAddrPort(t, "198.51.100.20:22"), routingResult) {
		t.Fatal("ambiguous routing should override dial-mode and excluded-port sniff suppression")
	}
	cp.sniffingTimeout = 0
	if cp.shouldTryTcpSniff(mustParseTcpSniffAddrPort(t, "198.51.100.20:443"), routingResult) {
		t.Fatal("zero sniffing timeout should remain an explicit hard disable")
	}
}

func TestShouldSkipTcpSniffDoesNotSuppressAmbiguousRouting(t *testing.T) {
	now := time.Now()
	cp := &ControlPlane{tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry)}
	key := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.20:443"), nil)
	for range tcpSniffFailureThreshold {
		cp.noteTcpSniffFailure(key, now)
	}
	if !cp.shouldSkipTcpSniff(&bpfRoutingResult{}, key, now) {
		t.Fatal("ordinary sniffing should honor the negative cache")
	}
	if cp.shouldSkipTcpSniff(&bpfRoutingResult{NeedSniff: 1}, key, now) {
		t.Fatal("ambiguous routing must not be suppressed by the negative cache")
	}
}

func TestDomainRoutingDecisionAccumulatesMustDirect(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "must.test",
				}},
			}},
			Outbound: config_parser.Function{Name: consts.OutboundMustRules.String()},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "test",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		rules,
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			"proxy":                        uint8(consts.OutboundUserDefinedMin),
		},
		nil,
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder: %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}

	_, mustDecision := matcher.DomainRoutingDecision("www.must.test")
	if !mustDecision.Valid || !mustDecision.Must || mustDecision.Outbound != uint8(consts.OutboundUserDefinedMin) {
		t.Fatalf("must-domain decision = %+v, want valid proxy decision with Must", mustDecision)
	}
	_, plainDecision := matcher.DomainRoutingDecision("www.plain.test")
	if !plainDecision.Valid || plainDecision.Must {
		t.Fatalf("plain-domain decision = %+v, want valid decision without Must", plainDecision)
	}
}

func TestRerouteTcpBySniffedDomainUsesExactDomainDecision(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "direct.test",
				}},
			}},
			Outbound: config_parser.Function{Name: consts.OutboundDirect.String()},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name: consts.Function_Domain,
				Params: []*config_parser.Param{{
					Key: string(consts.RoutingDomainKey_Suffix),
					Val: "proxy.test",
				}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		rules,
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			"proxy":                        uint8(consts.OutboundUserDefinedMin),
		},
		nil,
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder: %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}
	cp := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
	routingResult := &bpfRoutingResult{
		Outbound:  uint8(consts.OutboundDirect),
		Drop:      1,
		NeedSniff: 1,
	}

	err = cp.rerouteTcpBySniffedDomain(
		mustParseTcpSniffAddrPort(t, "192.0.2.10:12345"),
		mustParseTcpSniffAddrPort(t, "198.51.100.20:443"),
		"www.proxy.test",
		routingResult,
	)
	if err != nil {
		t.Fatalf("rerouteTcpBySniffedDomain: %v", err)
	}
	if got := consts.OutboundIndex(routingResult.Outbound); got != consts.OutboundUserDefinedMin {
		t.Fatalf("rerouted outbound = %v, want %v", got, consts.OutboundUserDefinedMin)
	}
	if routingResult.NeedSniff != 0 {
		t.Fatal("reroute should clear NeedSniff")
	}
	if routingResult.Drop != 0 {
		t.Fatal("reroute should replace the ambiguous drop decision")
	}
}

func TestRerouteUdpBySniffedDomainUsesExactDomainDecision(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_L4Proto,
					Params: []*config_parser.Param{{
						Val: "udp",
					}},
				},
				{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{{
						Key: string(consts.RoutingDomainKey_Suffix),
						Val: "proxy.test",
					}},
				},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}
	builder, err := NewRoutingMatcherBuilder(
		logrus.New(),
		rules,
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			"proxy":                        uint8(consts.OutboundUserDefinedMin),
		},
		nil,
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilder: %v", err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}
	cp := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: matcher}}
	routingResult := &bpfRoutingResult{
		Outbound:  uint8(consts.OutboundDirect),
		Drop:      1,
		NeedSniff: 1,
	}

	err = cp.rerouteUdpBySniffedDomain(
		mustParseTcpSniffAddrPort(t, "192.0.2.10:12345"),
		mustParseTcpSniffAddrPort(t, "198.51.100.20:443"),
		"www.proxy.test",
		routingResult,
	)
	if err != nil {
		t.Fatalf("rerouteUdpBySniffedDomain: %v", err)
	}
	if got := consts.OutboundIndex(routingResult.Outbound); got != consts.OutboundUserDefinedMin {
		t.Fatalf("rerouted outbound = %v, want %v", got, consts.OutboundUserDefinedMin)
	}
	if routingResult.NeedSniff != 0 {
		t.Fatal("reroute should clear NeedSniff")
	}
	if routingResult.Drop != 0 {
		t.Fatal("reroute should replace the ambiguous drop decision")
	}
}

func TestNoteTcpSniffFailure_AssignsExpiry(t *testing.T) {
	now := time.Now()
	cp := &ControlPlane{
		tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry),
	}
	key := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.20:443"), nil)

	for i := uint8(0); i < tcpSniffFailureThreshold; i++ {
		cp.noteTcpSniffFailure(key, now)
	}

	entry, ok := cp.tcpSniffNegSet[key]
	if !ok {
		t.Fatal("expected negative cache entry to be stored")
	}
	if entry.failures != tcpSniffFailureThreshold {
		t.Fatalf("failures = %d, want %d", entry.failures, tcpSniffFailureThreshold)
	}
	if entry.expiresAtUnixNano <= now.UnixNano() {
		t.Fatalf("expiresAtUnixNano = %d, want > %d", entry.expiresAtUnixNano, now.UnixNano())
	}
}

func TestTcpSniffNegativeCache_RequiresThresholdFailures(t *testing.T) {
	now := time.Now()
	cp := &ControlPlane{
		tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry),
	}
	key := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.22:443"), nil)

	for i := uint8(1); i < tcpSniffFailureThreshold; i++ {
		cp.noteTcpSniffFailure(key, now)
		if cp.shouldSkipTcpSniffByNegativeCache(key, now) {
			t.Fatalf("negative cache triggered after %d failures, want threshold %d", i, tcpSniffFailureThreshold)
		}
	}

	cp.noteTcpSniffFailure(key, now)
	if !cp.shouldSkipTcpSniffByNegativeCache(key, now) {
		t.Fatalf("negative cache did not trigger after %d failures", tcpSniffFailureThreshold)
	}
}

func TestCleanupNegativeCaches_RemovesExpiredTcpSniffEntries(t *testing.T) {
	now := time.Now()
	cp := &ControlPlane{
		tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry),
	}
	expiredKey := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.20:443"), nil)
	liveKey := newTcpSniffNegKey(mustParseTcpSniffAddrPort(t, "198.51.100.21:443"), nil)

	cp.tcpSniffNegSet[expiredKey] = tcpSniffNegEntry{
		failures:          tcpSniffFailureThreshold,
		expiresAtUnixNano: now.Add(-time.Second).UnixNano(),
	}
	cp.tcpSniffNegSet[liveKey] = tcpSniffNegEntry{
		failures:          tcpSniffFailureThreshold,
		expiresAtUnixNano: now.Add(time.Second).UnixNano(),
	}

	cp.cleanupNegativeCaches(now)

	if _, ok := cp.tcpSniffNegSet[expiredKey]; ok {
		t.Fatal("expired tcp sniff negative cache entry should be removed")
	}
	if _, ok := cp.tcpSniffNegSet[liveKey]; !ok {
		t.Fatal("live tcp sniff negative cache entry should be kept")
	}
}

type prefetchTestAddr string

func (a prefetchTestAddr) Network() string { return "tcp" }
func (a prefetchTestAddr) String() string  { return string(a) }

type prefetchTestConn struct {
	payload       []byte
	off           int
	deadlines     [2]time.Time
	deadlineCount int
}

func (c *prefetchTestConn) reset(payload []byte) {
	c.payload = payload
	c.off = 0
	c.deadlineCount = 0
}

func (c *prefetchTestConn) Read(p []byte) (int, error) {
	if c.off >= len(c.payload) {
		return 0, io.EOF
	}
	n := copy(p, c.payload[c.off:])
	c.off += n
	return n, nil
}

func (c *prefetchTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *prefetchTestConn) Close() error                { return nil }

func (c *prefetchTestConn) LocalAddr() net.Addr {
	return prefetchTestAddr("127.0.0.1:10001")
}

func (c *prefetchTestConn) RemoteAddr() net.Addr {
	return prefetchTestAddr("127.0.0.1:20001")
}

func (c *prefetchTestConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *prefetchTestConn) SetReadDeadline(t time.Time) error {
	if c.deadlineCount < len(c.deadlines) {
		c.deadlines[c.deadlineCount] = t
		c.deadlineCount++
	}
	return nil
}

func (c *prefetchTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestPrefetchForTcpSniff_ReplaysPrefetchedPayload(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: replay.example\r\n\r\n")
	conn := &prefetchTestConn{}
	conn.reset(payload)

	wrapped, prefetched, ready, err := prefetchForTcpSniff(conn, time.Millisecond, tcpSniffPrefetchBytes)
	if err != nil {
		t.Fatalf("prefetch failed: %v", err)
	}
	if !ready {
		t.Fatal("expected prefetch to report ready")
	}
	if want := payload[:tcpSniffPrefetchBytes]; !bytes.Equal(prefetched, want) {
		t.Fatalf("prefetched payload = %q, want %q", prefetched, want)
	}

	got, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatalf("wrapped read failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("wrapped payload = %q, want %q", got, payload)
	}
}

func TestPrefetchForTcpSniff_SuccessUsesAtMostTwoAllocs(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: alloc.example\r\n\r\n")
	conn := &prefetchTestConn{}

	allocs := testing.AllocsPerRun(1000, func() {
		conn.reset(payload)
		wrapped, prefetched, ready, err := prefetchForTcpSniff(conn, time.Millisecond, tcpSniffPrefetchBytes)
		if err != nil {
			t.Fatalf("prefetch failed: %v", err)
		}
		if !ready {
			t.Fatal("expected prefetch to report ready")
		}
		if _, ok := wrapped.(*prefixedConn); !ok {
			t.Fatalf("wrapped conn type = %T, want *prefixedConn", wrapped)
		}
		if want := payload[:tcpSniffPrefetchBytes]; !bytes.Equal(prefetched, want) {
			t.Fatalf("prefetched payload = %q, want %q", prefetched, want)
		}
	})

	if allocs > 2 {
		t.Fatalf("allocs/run = %.2f, want <= 2", allocs)
	}
}

func BenchmarkPrefetchForTcpSniffReady(b *testing.B) {
	payload := []byte("GET / HTTP/1.1\r\nHost: bench.example\r\n\r\n")
	conn := &prefetchTestConn{}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.reset(payload)
		wrapped, prefetched, ready, err := prefetchForTcpSniff(conn, time.Millisecond, tcpSniffPrefetchBytes)
		if err != nil {
			b.Fatalf("prefetch failed: %v", err)
		}
		if !ready {
			b.Fatal("expected prefetch to report ready")
		}
		if _, ok := wrapped.(*prefixedConn); !ok {
			b.Fatalf("wrapped conn type = %T, want *prefixedConn", wrapped)
		}
		if len(prefetched) != tcpSniffPrefetchBytes {
			b.Fatalf("prefetched len = %d, want %d", len(prefetched), tcpSniffPrefetchBytes)
		}
	}
}
