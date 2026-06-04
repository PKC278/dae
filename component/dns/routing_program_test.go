/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestNewNormalizedRequestRoutingProgramSplitsInternalSelectors(t *testing.T) {
	program, err := NewNormalizedRequestRoutingProgram([]*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{Name: "qname"}},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "sub"}},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "node"}},
		},
		{
			AndFunctions: []*config_parser.Function{{Name: "subnode"}},
		},
	}, "asis")
	if err != nil {
		t.Fatalf("NewNormalizedRequestRoutingProgram() error = %v", err)
	}
	if got := len(program.Rules); got != 1 {
		t.Fatalf("len(program.Rules) = %d, want 1", got)
	}
	if got := len(program.SubscriptionRules); got != 1 {
		t.Fatalf("len(program.SubscriptionRules) = %d, want 1", got)
	}
	if got := len(program.NodeRules); got != 1 {
		t.Fatalf("len(program.NodeRules) = %d, want 1", got)
	}
	if got := len(program.SubNodeRules); got != 1 {
		t.Fatalf("len(program.SubNodeRules) = %d, want 1", got)
	}
}

func TestNewNormalizedRequestRoutingProgramExpandsQNameRuleSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("+.example.com\n192.0.2.0/24\n"))
	}))
	defer server.Close()

	program, err := NewNormalizedRequestRoutingProgram([]*config_parser.RoutingRule{
		testRequestRule(
			"asis",
			testFunction("qname", testParam("rule-set", "cn")),
		),
	}, "asis",
		&routing.DatReaderOptimizer{
			RuleProviders:   map[string]string{"cn": server.URL},
			RuleProviderDir: t.TempDir(),
		},
	)
	if err != nil {
		t.Fatalf("NewNormalizedRequestRoutingProgram() error = %v", err)
	}
	if got := len(program.Rules); got != 1 {
		t.Fatalf("len(program.Rules) = %d, want 1", got)
	}
	params := program.Rules[0].AndFunctions[0].Params
	if len(params) != 1 {
		t.Fatalf("len(params) = %d, want 1: %#v", len(params), params)
	}
	if params[0].Key != string(consts.RoutingDomainKey_Suffix) || params[0].Val != "example.com" {
		t.Fatalf("unexpected param: %#v", params[0])
	}
}
