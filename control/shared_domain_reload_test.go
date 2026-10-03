/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func buildSharedDomainReloadMatcher(t *testing.T, aOutbound string) *RoutingMatcher {
	t.Helper()
	var rules []*config_parser.RoutingRule
	for _, pair := range [][2]string{{"b.test", "proxy"}, {"a.test", aOutbound}} {
		rules = append(rules, &config_parser.RoutingRule{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: "full", Val: pair[0]}},
			}},
			Outbound: config_parser.Function{Name: pair[1]},
		})
	}
	program, err := routing.NewNormalizedProgram(rules, config.FunctionOrString("direct"))
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewRoutingMatcherBuilderFromProgram(logrus.New(), program,
		map[string]uint8{"direct": uint8(consts.OutboundDirect), "proxy": uint8(consts.OutboundUserDefinedMin)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	matcher, err := builder.BuildUserspace()
	if err != nil {
		t.Fatal(err)
	}
	return matcher
}

func TestSharedDomainReloadProjection(t *testing.T) {
	testSharedDomainReloadProjection(t, false)
}

func TestSharedDomainReloadProjectionRealMap(t *testing.T) {
	testSharedDomainReloadProjection(t, true)
}

func testSharedDomainReloadProjection(t *testing.T, realMap bool) {
	for _, ip := range []string{"203.0.113.10", "2001:db8::10"} {
		for _, mode := range []string{"restore", "reproject", "stream_changed", "stream_unchanged"} {
			t.Run(ip+"/"+mode, func(t *testing.T) {
				oldMatcher := buildSharedDomainReloadMatcher(t, "proxy")
				newMatcher := buildSharedDomainReloadMatcher(t, "direct")
				wantAmbiguous := uint8(1)
				if mode == "stream_unchanged" {
					newMatcher = oldMatcher
					wantAmbiguous = 0
				}
				oldCP := &ControlPlane{controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: oldMatcher}}
				core := &controlPlaneCore{}
				objects := &bpfObjects{}
				if realMap {
					objects.DomainRoutingMap = newJanitorTestMap(t, "domain_routing_map")
				}
				core.bpf.Store(objects)
				core.setDomainRoutingDecisionFn(newMatcher.domainRoutingDecisionFromBitmap)
				newCP := &ControlPlane{core: core, controlPlaneGenerationState: controlPlaneGenerationState{routingMatcher: newMatcher}}
				now := time.Now()
				caches := make(map[string]*DnsCache)
				for _, domain := range []string{"a.test.", "b.test."} {
					answer := domainRoutingACache(domain+":1", ip, nil).Answer
					answer[0].Header().Name = domain
					if net.ParseIP(ip).To4() == nil {
						header := *answer[0].Header()
						header.Rrtype = dnsmessage.TypeAAAA
						answer = []dnsmessage.RR{&dnsmessage.AAAA{Hdr: header, AAAA: net.ParseIP(ip)}}
					}
					cache, err := oldCP.dnsControllerOption().NewCache(domain, answer, nil, nil, now.Add(time.Hour), now.Add(time.Hour))
					if err != nil {
						t.Fatal(err)
					}
					cache.RouteOwnerKey = domain
					cache.RouteProjectionEpoch = 1
					caches[domain] = cache
				}
				controller := newTestDnsController()
				t.Cleanup(func() { _ = controller.Close() })
				setTestDnsControllerRuntime(controller, func(rt *dnsControllerRuntimeState) {
					rt.routeProjectionEpoch = 2
					rt.projectCacheRoute = newCP.dnsControllerOption().ProjectCacheRoute
					rt.cacheAccessCallback = newCP.dnsControllerOption().CacheAccessCallback
				})
				switch mode {
				case "restore":
					count, err := controller.RestoreReloadCacheAndProject(caches, nil, now)
					if err != nil || count != len(caches) {
						t.Fatalf("restore count=%d err=%v", count, err)
					}
				case "reproject":
					for key, cache := range caches {
						controller.storeDnsCache(key, cache)
					}
					controller.reprojectCachedRoutes(controller.runtime())
					controller.dnsCache.Range(func(_, value any) bool {
						if err := core.BatchUpdateDomainRouting(value.(*DnsCache)); err != nil {
							t.Fatal(err)
						}
						return true
					})
				default:
					count, err := newCP.projectDnsReloadCacheStream(func(visit func(string, *DnsCache) error) error {
						for key, cache := range caches {
							if err := visit(key, cache); err != nil {
								return err
							}
						}
						return nil
					}, mode == "stream_unchanged")
					if err != nil || count != len(caches) {
						t.Fatalf("stream count=%d err=%v", count, err)
					}
				}
				if err := controller.Close(); err != nil {
					t.Fatal(err)
				}
				tracker := core.domainRoutingTrackerForSlot(0)
				tracker.mu.Lock()
				defer tracker.mu.Unlock()
				if len(tracker.ips) != 1 || len(tracker.owners) != 2 {
					t.Fatalf("IP count=%d owner count=%d", len(tracker.ips), len(tracker.owners))
				}
				for key, state := range tracker.ips {
					if state.merged.Ambiguous != wantAmbiguous {
						t.Errorf("Ambiguous=%d, want %d", state.merged.Ambiguous, wantAmbiguous)
					}
					if realMap {
						var got bpfDomainRouting
						if err := objects.DomainRoutingMap.Lookup(bpfRoutingEpochIp{Slot: 0, Addr: key}, &got); err != nil {
							t.Fatal(err)
						}
						if got != state.merged {
							t.Errorf("kernel routing=%+v, want %+v", got, state.merged)
						}
					}
				}
				for domain, snapshot := range tracker.owners {
					_, expected := newMatcher.DomainRoutingDecision(domain)
					if !equalDomainRoutingDecision(snapshot.decision, expected) {
						t.Errorf("%s decision=%+v, want %+v", domain, snapshot.decision, expected)
					}
					if caches[domain].DomainRoutingDecision.Outbound != uint8(consts.OutboundUserDefinedMin) {
						t.Errorf("%s source cache was modified", domain)
					}
				}
			})
		}
	}
}
