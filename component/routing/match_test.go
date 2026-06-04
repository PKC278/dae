/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

func TestMatchRulesReportsRuleProviderDomainSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("+.apple.com\n192.0.2.0/24\n"))
	}))
	defer server.Close()

	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   "domain",
			Params: []*config_parser.Param{{Key: "rule-set", Val: "cn"}},
		}},
		Outbound: config_parser.Function{Name: "direct"},
	}}
	report, err := MatchRules(rules, "proxy", MatchInput{
		Raw:      "domain:www.apple.com",
		Scope:    "routing",
		Function: &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "www.apple.com"}}},
	}, MatchOption{
		Logger:          logrus.New(),
		RuleProviders:   map[string]string{"cn": server.URL},
		RuleProviderDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("MatchRules failed: %v", err)
	}
	if report.Hit == nil {
		t.Fatal("expected hit")
	}
	if report.Hit.Source.Kind != "rule_provider" || report.Hit.Source.Name != "cn" {
		t.Fatalf("unexpected source: %#v", report.Hit.Source)
	}
	if report.Hit.Source.Pattern != "+.apple.com" {
		t.Fatalf("unexpected pattern: %q", report.Hit.Source.Pattern)
	}
	if report.Hit.Action != "direct" {
		t.Fatalf("unexpected action: %q", report.Hit.Action)
	}
}

func TestFormatMatchRuleSpacesRuleArrow(t *testing.T) {
	rule := &config_parser.RoutingRule{
		AndFunctions: []*config_parser.Function{{
			Name: "domain",
			Params: []*config_parser.Param{
				{Key: "rule-set", Val: "apple"},
				{Key: "geosite", Val: "microsoft"},
			},
		}},
		Outbound: config_parser.Function{Name: "direct"},
	}

	got := formatMatchRule(rule)
	want := "domain(rule-set:apple,geosite:microsoft) -> direct"
	if got != want {
		t.Fatalf("formatMatchRule() = %q, want %q", got, want)
	}
}

func TestMatchRulesReportsRuleProviderIPSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("1.1.8.0/24\n+.apple.com\n"))
	}))
	defer server.Close()

	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   "ip",
			Params: []*config_parser.Param{{Key: "rule-set", Val: "cn_ip"}},
		}},
		Outbound: config_parser.Function{Name: "direct"},
	}}
	report, err := MatchRules(rules, "proxy", MatchInput{
		Raw:      "ipcidr:1.1.8.0/25",
		Scope:    "routing",
		Function: &config_parser.Function{Name: "ip", Params: []*config_parser.Param{{Val: "1.1.8.0/25"}}},
	}, MatchOption{
		Logger:          logrus.New(),
		RuleProviders:   map[string]string{"cn_ip": server.URL},
		RuleProviderDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("MatchRules failed: %v", err)
	}
	if report.Hit == nil {
		t.Fatal("expected hit")
	}
	if report.Hit.Source.Kind != "rule_provider" || report.Hit.Source.Name != "cn_ip" {
		t.Fatalf("unexpected source: %#v", report.Hit.Source)
	}
	if report.Hit.Source.Pattern != "1.1.8.0/24" {
		t.Fatalf("unexpected pattern: %q", report.Hit.Source.Pattern)
	}
}

func TestMatchRulesMatchesInlineProcessName(t *testing.T) {
	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   "pname",
			Params: []*config_parser.Param{{Val: "NetworkManager"}},
		}},
		Outbound: config_parser.Function{Name: "direct"},
	}}
	report, err := MatchRules(rules, "proxy", MatchInput{
		Raw:      "pname(NetworkManager)",
		Scope:    "routing",
		Function: &config_parser.Function{Name: "pname", Params: []*config_parser.Param{{Val: "NetworkManager"}}},
	}, MatchOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("MatchRules failed: %v", err)
	}
	if report.Hit == nil {
		t.Fatal("expected hit")
	}
	if report.Hit.Source.Kind != "inline" || report.Hit.Source.Pattern != "NetworkManager" {
		t.Fatalf("unexpected source: %#v", report.Hit.Source)
	}
}

func TestMatchRulesMatchesInlinePortRange(t *testing.T) {
	rules := []*config_parser.RoutingRule{{
		AndFunctions: []*config_parser.Function{{
			Name:   "port",
			Params: []*config_parser.Param{{Val: "8000-9000"}},
		}},
		Outbound: config_parser.Function{Name: "direct"},
	}}
	report, err := MatchRules(rules, "proxy", MatchInput{
		Raw:      "port(8443)",
		Scope:    "routing",
		Function: &config_parser.Function{Name: "port", Params: []*config_parser.Param{{Val: "8443"}}},
	}, MatchOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("MatchRules failed: %v", err)
	}
	if report.Hit == nil {
		t.Fatal("expected hit")
	}
}

func TestMatchRulesContinuesAfterPartialHitUntilFullHit(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{Name: "l4proto", Params: []*config_parser.Param{{Val: "udp"}}},
				{Name: "port", Params: []*config_parser.Param{{Val: "443"}}},
				{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "apple.com"}}},
			},
			Outbound: config_parser.Function{Name: "block"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "apple.com"}}},
			},
			Outbound: config_parser.Function{Name: "direct"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "apple.com"}}},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}
	report, err := MatchRules(rules, "proxy", MatchInput{
		Raw:      "domain:apple.com",
		Scope:    "routing",
		Function: &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: "apple.com"}}},
	}, MatchOption{Logger: logrus.New()})
	if err != nil {
		t.Fatalf("MatchRules failed: %v", err)
	}
	if len(report.Hits) != 2 {
		t.Fatalf("len(report.Hits) = %d, want 2", len(report.Hits))
	}
	if !report.Hits[0].Partial || report.Hits[0].Action != "block" {
		t.Fatalf("unexpected first hit: %#v", report.Hits[0])
	}
	if report.Hits[1].Partial || report.Hits[1].Action != "direct" {
		t.Fatalf("unexpected second hit: %#v", report.Hits[1])
	}
}
