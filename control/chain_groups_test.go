/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strings"
	"testing"
)

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
