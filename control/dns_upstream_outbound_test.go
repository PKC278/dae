/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	ob "github.com/daeuniverse/dae/component/outbound"
	"github.com/sirupsen/logrus"
)

func newOutboundBoundDnsTestPlane(groups ...*ob.DialerGroup) *ControlPlane {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	outbounds := []*ob.DialerGroup{
		newNamedTestGroup(consts.OutboundDirect.String()),
		newNamedTestGroup(consts.OutboundBlock.String()),
	}
	outbounds = append(outbounds, groups...)
	return &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: outbounds,
		},
		soMarkFromDae: 0x100,
	}
}

func newNamedTestGroup(name string) *ob.DialerGroup {
	g := newTestFixedOutboundGroup(newTestEndpointDialer())
	g.Name = name
	return g
}

// An upstream bound by its outbound annotation is dialed through that group
// without consulting the main routing; the plane here has no routing at all,
// so reaching Route would fail the call.
func TestChooseBestDnsDialerUsesBoundOutbound(t *testing.T) {
	hk := newNamedTestGroup("hk_group")
	us := newNamedTestGroup("us_group")
	c := newOutboundBoundDnsTestPlane(hk, us)
	snapshot := DnsRequestSnapshot{
		RealSrc: netip.MustParseAddrPort("192.168.1.10:53000"),
		RealDst: netip.MustParseAddrPort("192.168.1.1:53"),
	}
	newUpstream := func(outbound string) *dns.Upstream {
		return &dns.Upstream{
			Scheme:   dns.UpstreamScheme_UDP,
			Hostname: "8.8.8.8",
			Port:     53,
			Ip46:     &netutils.Ip46{Ip4: netip.MustParseAddr("8.8.8.8")},
			Outbound: outbound,
		}
	}

	for _, want := range []*ob.DialerGroup{us, hk} {
		dialArg, err := c.chooseBestDnsDialerSnapshot(context.Background(), snapshot, newUpstream(want.Name))
		if err != nil {
			t.Fatalf("%s: %v", want.Name, err)
		}
		if dialArg.bestOutbound != want {
			t.Fatalf("bound %s, dialed through %v", want.Name, dialArg.bestOutbound.Name)
		}
		if dialArg.mark != c.soMarkFromDae {
			t.Fatalf("%s: mark = %#x, want so_mark_from_dae %#x", want.Name, dialArg.mark, c.soMarkFromDae)
		}
		if got := dialArg.bestTarget.String(); got != "8.8.8.8:53" {
			t.Fatalf("%s: target = %s", want.Name, got)
		}
	}

	_, err := c.chooseBestDnsDialerSnapshot(context.Background(), snapshot, newUpstream("missing"))
	if err == nil || !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("unknown bound outbound: err = %v", err)
	}
}

// Two aliases of one address bound to different groups must neither share a
// cached dial decision nor share cached answers.
func TestDnsUpstreamOutboundScopesCaches(t *testing.T) {
	snapshot := DnsRequestSnapshot{
		RealSrc: netip.MustParseAddrPort("192.168.1.10:53000"),
		RealDst: netip.MustParseAddrPort("192.168.1.1:53"),
	}
	hk := &dns.Upstream{Scheme: dns.UpstreamScheme_UDP, Hostname: "8.8.8.8", Port: 53,
		Ip46: &netutils.Ip46{Ip4: netip.MustParseAddr("8.8.8.8")}, Outbound: "hk_group"}
	us := *hk
	us.Outbound = "us_group"
	plain := *hk
	plain.Outbound = ""

	hkKey, _ := buildDnsDialerSnapshotKeyForSnapshot(snapshot, hk)
	usKey, _ := buildDnsDialerSnapshotKeyForSnapshot(snapshot, &us)
	if hkKey == usKey {
		t.Fatal("dial snapshot key ignores the bound outbound")
	}

	c := &DnsController{}
	hkScope := c.responseCacheKey("example.com.1", nil, 1, hk)
	usScope := c.responseCacheKey("example.com.1", nil, 2, &us)
	plainScope := c.responseCacheKey("example.com.1", nil, 3, &plain)
	if hkScope == usScope {
		t.Fatal("response cache scope ignores the bound outbound")
	}
	if plainScope != "example.com.1|upstream@udp://8.8.8.8:53" {
		t.Fatalf("unbound upstream scope changed: %q", plainScope)
	}
}
