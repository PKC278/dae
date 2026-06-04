/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	matchCmd = &cobra.Command{
		Use:   "match -c CONFIG [domain:example.com|qname:example.com|ip:1.1.1.1|ipcidr:1.1.1.0/24|pname(NetworkManager)]",
		Short: "Test routing rule matches for a target function.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			if err := runMatch(cfgFile, args[0]); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(matchCmd)
	matchCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
}

func runMatch(cfgFile string, rawTarget string) error {
	conf, _, err := readConfig(cfgFile)
	if err != nil {
		return err
	}
	input, err := parseMatchInput(rawTarget)
	if err != nil {
		return err
	}
	ruleProviders, err := config.KeyableStringMap(conf.RuleProvider)
	if err != nil {
		return fmt.Errorf("rule_provider: %w", err)
	}
	ruleProviderDir := filepath.Join(filepath.Dir(cfgFile), "rules")
	if err = routing.DownloadRuleProviders(ruleProviders, ruleProviderDir); err != nil {
		return err
	}

	log := logrus.New()
	log.SetOutput(os.Stderr)
	log.SetLevel(logrus.WarnLevel)
	opt := routing.MatchOption{
		Logger:          log,
		LocationFinder:  assets.NewLocationFinder([]string{filepath.Dir(cfgFile)}),
		RuleProviders:   ruleProviders,
		RuleProviderDir: ruleProviderDir,
	}
	var report *routing.MatchReport
	switch input.Scope {
	case "routing":
		report, err = routing.MatchRules(conf.Routing.Rules, conf.Routing.Fallback, input, opt)
	case "dns_request":
		report, err = routing.MatchRules(conf.Dns.Routing.Request.Rules, conf.Dns.Routing.Request.Fallback, input, opt)
	default:
		err = fmt.Errorf("unsupported match scope: %v", input.Scope)
	}
	if err != nil {
		return err
	}
	printMatchReport(report)
	return nil
}

func parseMatchInput(raw string) (routing.MatchInput, error) {
	if strings.Contains(raw, "(") {
		return parseMatchFunctionInput(raw)
	}
	return parseLegacyMatchInput(raw)
}

func parseLegacyMatchInput(raw string) (routing.MatchInput, error) {
	key, value, ok := strings.Cut(raw, ":")
	if !ok || key == "" || value == "" {
		return routing.MatchInput{}, fmt.Errorf("target must be like domain:example.com, qname:example.com, ip:1.1.1.1, ipcidr:1.1.1.0/24, or pname(NetworkManager)")
	}
	input := routing.MatchInput{Raw: raw, Scope: "routing"}
	switch key {
	case string(routing.MatchTargetDomain):
		input.Function = &config_parser.Function{Name: "domain", Params: []*config_parser.Param{{Key: "suffix", Val: strings.TrimSuffix(value, ".")}}}
		return input, nil
	case string(routing.MatchTargetQName):
		input.Scope = "dns_request"
		input.Function = &config_parser.Function{Name: "qname", Params: []*config_parser.Param{{Key: "suffix", Val: strings.TrimSuffix(value, ".")}}}
		return input, nil
	case string(routing.MatchTargetIP):
		if _, err := netip.ParseAddr(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid ip target %q: %w", value, err)
		}
		input.Function = &config_parser.Function{Name: "ip", Params: []*config_parser.Param{{Val: value}}}
		return input, nil
	case string(routing.MatchTargetIPCIDR):
		if _, err := netip.ParsePrefix(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid ipcidr target %q: %w", value, err)
		}
		input.Function = &config_parser.Function{Name: "ip", Params: []*config_parser.Param{{Val: value}}}
		return input, nil
	default:
		return routing.MatchInput{}, fmt.Errorf("unsupported target type %q", key)
	}
}

func parseMatchFunctionInput(raw string) (routing.MatchInput, error) {
	sections, err := config_parser.Parse("routing { " + raw + " -> direct }")
	if err != nil {
		return routing.MatchInput{}, fmt.Errorf("failed to parse match target: %w", err)
	}
	if len(sections) != 1 || len(sections[0].Items) != 1 {
		return routing.MatchInput{}, fmt.Errorf("failed to parse match target")
	}
	rule, ok := sections[0].Items[0].Value.(*config_parser.RoutingRule)
	if !ok || len(rule.AndFunctions) != 1 {
		return routing.MatchInput{}, fmt.Errorf("match target must be exactly one function")
	}
	f := rule.AndFunctions[0]
	if f.Not {
		return routing.MatchInput{}, fmt.Errorf("match target cannot use negation")
	}
	scope := "routing"
	if f.Name == "qname" {
		scope = "dns_request"
	}
	if !matchFunctionAllowed(scope, f.Name) {
		return routing.MatchInput{}, fmt.Errorf("unsupported match function %q", f.Name)
	}
	return routing.MatchInput{
		Raw:      raw,
		Scope:    scope,
		Function: f,
	}, nil
}

func matchFunctionAllowed(scope string, name string) bool {
	switch scope {
	case "dns_request":
		return name == "qname" || name == "qtype"
	case "routing":
		switch name {
		case "domain", "ip", "sip", "port", "sport", "l4proto", "ipversion", "mac", "pname", "dscp", "dip", "dport":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func printMatchReport(report *routing.MatchReport) {
	fmt.Printf("target: %s\n", report.Target)
	fmt.Printf("scope: %s\n\n", report.Scope)
	if len(report.Hits) == 0 {
		fmt.Println("matched: none")
		fmt.Printf("fallback: %s\n", report.Fallback)
		return
	}
	for i, hit := range report.Hits {
		if len(report.Hits) == 1 {
			fmt.Println("matched:")
		} else {
			fmt.Printf("matched[%d]:\n", i+1)
		}
		fmt.Printf("  rule: %s\n", hit.Rule)
		printMatchSource(hit.Source)
		fmt.Printf("  %s: %s\n", report.Action, hit.Action)
		if hit.Partial {
			fmt.Println("  note: rule also contains conditions not checked by this target")
		}
		if i != len(report.Hits)-1 {
			fmt.Println()
		}
	}
	if report.Hit != nil && report.Hit.Partial {
		fmt.Println()
		fmt.Println("fully_matched: none")
		fmt.Printf("fallback: %s\n", report.Fallback)
	}
}

func printMatchSource(source routing.MatchSource) {
	if source.Kind == "" {
		return
	}
	if source.Name == "" {
		fmt.Printf("  source: %s\n", source.Kind)
	} else {
		fmt.Printf("  source: %s %s\n", source.Kind, source.Name)
	}
	if source.File != "" {
		fmt.Printf("  file: %s\n", source.File)
	}
	if source.Pattern != "" {
		fmt.Printf("  pattern: %s\n", source.Pattern)
	}
	if source.Normalized != "" {
		fmt.Printf("  normalized: %s\n", source.Normalized)
	}
}
