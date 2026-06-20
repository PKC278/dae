/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
)

func domainRoutingBitmap(words ...uint32) []uint32 {
	bitmap := make([]uint32, len(bpfDomainRouting{}.Bitmap))
	copy(bitmap, words)
	return bitmap
}

func domainRoutingACache(ownerKey string, ip string, bitmap []uint32) *DnsCache {
	return &DnsCache{
		RouteOwnerKey: ownerKey,
		DomainBitmap:  bitmap,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "shared.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(ip).To4(),
			},
		},
	}
}

func TestDomainRoutingTrackerMergesSharedIPAcrossOwners(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{
		domainRouting: newDomainRoutingTracker(),
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	cacheA := domainRoutingACache("cache-a", "203.0.113.10", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("cache-b", "203.0.113.10", domainRoutingBitmap(0x2))
	ip := netip.MustParseAddr("203.0.113.10")
	ip16 := ip.As16()
	ipKey := common.Ipv6ByteSliceToUint32Array(ip16[:])

	if err := core.BatchUpdateDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheA): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheB): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip): %v", err)
	}
	if got.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap[0] = %#x, want %#x", got.Bitmap[0], uint32(0x3))
	}
	if got.Ambiguous == 0 {
		t.Fatal("shared IP with different unknown domain decisions should be marked ambiguous")
	}

	if err := core.BatchRemoveDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(cacheA): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip after remove A): %v", err)
	}
	if got.Bitmap[0] != 0x2 {
		t.Fatalf("bitmap after removing A = %#x, want %#x", got.Bitmap[0], uint32(0x2))
	}
	if got.Ambiguous != 0 {
		t.Fatal("single remaining owner should not be ambiguous")
	}

	if err := core.BatchRemoveDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(cacheB): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(shared ip after remove B) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}

func TestDomainRoutingTrackerKeepsFastPathForSameDecision(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	tracker := newDomainRoutingTracker()
	tracker.setDecisionFromMergedBitmap(func([]uint32) domainRoutingDecision {
		return domainRoutingDecision{Valid: true, Outbound: 10}
	})
	core := &controlPlaneCore{
		domainRouting: tracker,
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	cacheA := domainRoutingACache("cache-a", "203.0.113.10", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("cache-b", "203.0.113.10", domainRoutingBitmap(0x2))
	cacheA.DomainRoutingDecision = domainRoutingDecision{Valid: true, Outbound: 10}
	cacheB.DomainRoutingDecision = domainRoutingDecision{Valid: true, Outbound: 10}
	ip := netip.MustParseAddr("203.0.113.10")
	ip16 := ip.As16()
	ipKey := common.Ipv6ByteSliceToUint32Array(ip16[:])

	if err := core.BatchUpdateDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheA): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheB): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip): %v", err)
	}
	if got.Bitmap[0] != 0x3 {
		t.Fatalf("merged bitmap[0] = %#x, want %#x", got.Bitmap[0], uint32(0x3))
	}
	if got.Ambiguous != 0 {
		t.Fatal("shared IP with same domain routing decision should stay on fast path")
	}
}

func TestDomainRoutingTrackerMarksSyntheticMergedRuleAmbiguous(t *testing.T) {
	matcher := &RoutingMatcher{compiledMatches: []compiledRoutingMatch{
		{
			matchType: consts.MatchType_DomainSet,
			outbound:  consts.OutboundLogicalAnd,
		},
		{
			matchType: consts.MatchType_DomainSet,
			outbound:  consts.OutboundUserDefinedMin,
		},
		{
			matchType: consts.MatchType_Fallback,
			outbound:  consts.OutboundDirect,
		},
	}}
	tracker := newDomainRoutingTracker()
	tracker.setDecisionFromMergedBitmap(matcher.domainRoutingDecisionFromBitmap)
	bitmapA := domainRoutingBitmap(0x1)
	bitmapB := domainRoutingBitmap(0x2)
	decisionA := matcher.domainRoutingDecisionFromBitmap(bitmapA)
	decisionB := matcher.domainRoutingDecisionFromBitmap(bitmapB)
	if !decisionA.Valid || !equalDomainRoutingDecision(decisionA, decisionB) {
		t.Fatalf("individual decisions should both use fallback: A=%+v B=%+v", decisionA, decisionB)
	}

	var routeA, routeB bpfDomainRouting
	copy(routeA.Bitmap[:], bitmapA)
	copy(routeB.Bitmap[:], bitmapB)
	merged := tracker.mergeDomainRoutingOwnerBitmaps(map[string]domainRoutingOwnerRoute{
		"cache-a": {bitmap: routeA, decision: decisionA},
		"cache-b": {bitmap: routeB, decision: decisionB},
	})
	if merged.Bitmap[0] != 0x3 || merged.Ambiguous == 0 {
		t.Fatalf("synthetic merged rule = bitmap %#x ambiguous %d, want bitmap %#x ambiguous 1", merged.Bitmap[0], merged.Ambiguous, uint32(0x3))
	}
}

func TestDomainRoutingTrackerMergeKeepsFastPathWhenMergedDecisionMatches(t *testing.T) {
	matcher := &RoutingMatcher{compiledMatches: []compiledRoutingMatch{
		{
			matchType: consts.MatchType_DomainSet,
			outbound:  consts.OutboundUserDefinedMin,
		},
		{
			matchType: consts.MatchType_DomainSet,
			outbound:  consts.OutboundUserDefinedMin,
		},
		{
			matchType: consts.MatchType_Fallback,
			outbound:  consts.OutboundDirect,
		},
	}}
	tracker := newDomainRoutingTracker()
	tracker.setDecisionFromMergedBitmap(matcher.domainRoutingDecisionFromBitmap)
	var routeA, routeB bpfDomainRouting
	routeA.Bitmap[0] = 0x1
	routeB.Bitmap[0] = 0x2
	decisionA := matcher.domainRoutingDecisionFromBitmap(routeA.Bitmap[:])
	decisionB := matcher.domainRoutingDecisionFromBitmap(routeB.Bitmap[:])
	merged := tracker.mergeDomainRoutingOwnerBitmaps(map[string]domainRoutingOwnerRoute{
		"cache-a": {bitmap: routeA, decision: decisionA},
		"cache-b": {bitmap: routeB, decision: decisionB},
	})
	if merged.Bitmap[0] != 0x3 || merged.Ambiguous != 0 {
		t.Fatalf("same-decision merge = bitmap %#x ambiguous %d, want bitmap %#x ambiguous 0", merged.Bitmap[0], merged.Ambiguous, uint32(0x3))
	}
}

func TestDomainRoutingTrackerMarksDifferentDecisionsAmbiguous(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{
		domainRouting: newDomainRoutingTracker(),
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	cacheA := domainRoutingACache("cache-a", "203.0.113.10", domainRoutingBitmap(0x1))
	cacheB := domainRoutingACache("cache-b", "203.0.113.10", domainRoutingBitmap(0x2))
	cacheA.DomainRoutingDecision = domainRoutingDecision{Valid: true, Outbound: 0}
	cacheB.DomainRoutingDecision = domainRoutingDecision{Valid: true, Outbound: 10}
	ip := netip.MustParseAddr("203.0.113.10")
	ip16 := ip.As16()
	ipKey := common.Ipv6ByteSliceToUint32Array(ip16[:])

	if err := core.BatchUpdateDomainRouting(cacheA); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheA): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(cacheB); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(cacheB): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared ip): %v", err)
	}
	if got.Ambiguous == 0 {
		t.Fatal("shared IP with different domain routing decisions should be ambiguous")
	}
}

func TestDomainRoutingTrackerIncludesFallbackOnlyOwnerInConflictDetection(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{domainRouting: newDomainRoutingTracker()}
	core.bpf.Store(&bpfObjects{bpfMaps: bpfMaps{DomainRoutingMap: domainMap}})

	fallbackCache := domainRoutingACache("fallback-owner", "203.0.113.30", domainRoutingBitmap())
	fallbackCache.DomainRoutingDecision = domainRoutingDecision{Valid: true, Outbound: uint8(0)}
	proxyCache := domainRoutingACache("proxy-owner", "203.0.113.30", domainRoutingBitmap(0x1))
	proxyCache.DomainRoutingDecision = domainRoutingDecision{Valid: true, Outbound: uint8(10)}
	ip := netip.MustParseAddr("203.0.113.30")
	ip16 := ip.As16()
	ipKey := common.Ipv6ByteSliceToUint32Array(ip16[:])

	if err := core.BatchUpdateDomainRouting(fallbackCache); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(fallbackCache): %v", err)
	}
	var got bpfDomainRouting
	if err := domainMap.Lookup(&ipKey, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("fallback-only IP lookup err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
	if err := core.BatchUpdateDomainRouting(proxyCache); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(proxyCache): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(shared fallback IP): %v", err)
	}
	if got.Bitmap[0] != 0x1 || got.Ambiguous == 0 {
		t.Fatalf("shared fallback IP = bitmap %#x ambiguous %d, want bitmap %#x ambiguous 1", got.Bitmap[0], got.Ambiguous, uint32(0x1))
	}

	if err := core.BatchRemoveDomainRouting(fallbackCache); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(fallbackCache): %v", err)
	}
	if err := domainMap.Lookup(&ipKey, &got); err != nil {
		t.Fatalf("Lookup(after fallback removal): %v", err)
	}
	if got.Ambiguous != 0 {
		t.Fatal("single proxy owner should not remain ambiguous")
	}
}

func TestDomainRoutingTrackerReplacesOwnerSnapshotWithoutLeakingRefs(t *testing.T) {
	domainMap := newJanitorTestMap(t, "domain_routing_map")
	core := &controlPlaneCore{
		domainRouting: newDomainRoutingTracker(),
	}
	core.bpf.Store(&bpfObjects{
		bpfMaps: bpfMaps{
			DomainRoutingMap: domainMap,
		},
	})

	first := &DnsCache{
		RouteOwnerKey: "cache-owner",
		DomainBitmap:  domainRoutingBitmap(0x4),
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "replace.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.20").To4(),
			},
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   "replace.test.",
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.21").To4(),
			},
		},
	}
	second := domainRoutingACache("cache-owner", "203.0.113.20", domainRoutingBitmap(0x4))

	ip20Addr := netip.MustParseAddr("203.0.113.20")
	ip20Bytes := ip20Addr.As16()
	ip20 := common.Ipv6ByteSliceToUint32Array(ip20Bytes[:])
	ip21Addr := netip.MustParseAddr("203.0.113.21")
	ip21Bytes := ip21Addr.As16()
	ip21 := common.Ipv6ByteSliceToUint32Array(ip21Bytes[:])

	if err := core.BatchUpdateDomainRouting(first); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(first): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(second); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(second): %v", err)
	}
	if err := core.BatchUpdateDomainRouting(second); err != nil {
		t.Fatalf("BatchUpdateDomainRouting(second repeat): %v", err)
	}

	var got bpfDomainRouting
	if err := domainMap.Lookup(&ip20, &got); err != nil {
		t.Fatalf("Lookup(ip20): %v", err)
	}
	if got.Bitmap[0] != 0x4 {
		t.Fatalf("bitmap for ip20 = %#x, want %#x", got.Bitmap[0], uint32(0x4))
	}
	if err := domainMap.Lookup(&ip21, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(ip21) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}

	if err := core.BatchRemoveDomainRouting(second); err != nil {
		t.Fatalf("BatchRemoveDomainRouting(second): %v", err)
	}
	if err := domainMap.Lookup(&ip20, &got); !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("Lookup(ip20 after remove) err = %v, want %v", err, ebpf.ErrKeyNotExist)
	}
}
