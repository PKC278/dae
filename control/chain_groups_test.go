/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

// chainedGroup builds a group holding one node chained through chainGroup, or
// a plain node when chainGroup is empty.
func chainedGroup(t *testing.T, name, chainGroup string) *outbound.DialerGroup {
	t.Helper()
	log := logrus.New()
	option := dialer.NewGlobalOption(&config.Global{}, log)
	raw, property := dialer.NewDirectDialer(option, true)
	property.ChainGroup = chainGroup
	d := dialer.NewDialerContext(t.Context(), raw, option, dialer.InstanceOption{DisableCheck: true}, property)
	return outbound.NewDialerGroup(option, name, []*dialer.Dialer{d}, []*dialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool, *dialer.NetworkType, bool) {})
}

func TestIncludeChainCarriersFollowsTheChainToItsEnd(t *testing.T) {
	outbounds := []*outbound.DialerGroup{
		chainedGroup(t, "landing", "front"),
		chainedGroup(t, "front", "entry"),
		chainedGroup(t, "entry", ""),
		chainedGroup(t, "unused", ""),
	}
	referenced := map[string]struct{}{"landing": {}}
	includeChainCarriers(referenced, outbounds)

	for _, name := range []string{"landing", "front", "entry"} {
		if _, ok := referenced[name]; !ok {
			t.Errorf("group %q is not referenced, want it health-checked as part of the chain", name)
		}
	}
	if _, ok := referenced["unused"]; ok {
		t.Error("group \"unused\" is referenced, want it left out")
	}
}

func TestIncludeChainCarriersIgnoresChainsOfUnreferencedGroups(t *testing.T) {
	outbounds := []*outbound.DialerGroup{
		chainedGroup(t, "landing", "front"),
		chainedGroup(t, "front", ""),
		chainedGroup(t, "direct", ""),
	}
	referenced := map[string]struct{}{"direct": {}}
	includeChainCarriers(referenced, outbounds)

	if len(referenced) != 1 {
		t.Fatalf("referenced = %v, want only direct", referenced)
	}
}

func TestValidateChainGroupGraphAcceptsALayeredChain(t *testing.T) {
	edges := map[string][]chainGroupEdge{
		"landing": {{target: "front", node: "A"}},
		"front":   {{target: "entry", node: "B"}},
	}
	if err := validateChainGroupGraph(edges); err != nil {
		t.Fatalf("validateChainGroupGraph() error = %v, want nil", err)
	}
}

func TestValidateChainGroupGraphRejectsAGroupChainedThroughItself(t *testing.T) {
	edges := map[string][]chainGroupEdge{
		"front": {{target: "front", node: "A"}},
	}
	err := validateChainGroupGraph(edges)
	if err == nil {
		t.Fatal("validateChainGroupGraph() error = nil, want a loop report")
	}
	if !strings.Contains(err.Error(), "front -> front") || !strings.Contains(err.Error(), `"A"`) {
		t.Fatalf("validateChainGroupGraph() error = %v, want the loop and the node that closes it", err)
	}
}

func TestValidateChainGroupGraphRejectsALongerLoop(t *testing.T) {
	edges := map[string][]chainGroupEdge{
		"landing": {{target: "front", node: "A"}},
		"front":   {{target: "landing", node: "B"}},
	}
	err := validateChainGroupGraph(edges)
	if err == nil {
		t.Fatal("validateChainGroupGraph() error = nil, want a loop report")
	}
	if !strings.Contains(err.Error(), `front -> landing (through node "B") -> front (through node "A")`) {
		t.Fatalf("validateChainGroupGraph() error = %v, want the whole loop", err)
	}
}
