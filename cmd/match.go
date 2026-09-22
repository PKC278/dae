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
	"regexp"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	matchCmd = &cobra.Command{
		Use:   "match -c CONFIG [function:value|dns.response.function:value]",
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
	case "dns_response":
		report, err = routing.MatchRules(conf.Dns.Routing.Response.Rules, conf.Dns.Routing.Response.Fallback, input, opt)
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
	return parseColonMatchInput(raw)
}

func parseColonMatchInput(raw string) (routing.MatchInput, error) {
	key, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
	if !ok || key == "" || value == "" {
		return routing.MatchInput{}, fmt.Errorf("target must be like domain:example.com, qname:example.com, ip:1.1.1.1, ipcidr:1.1.1.0/24, pname:NetworkManager, mac:02:42:ac:11:00:02, or dns.response.upstream:googledns")
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	explicitScope, key, err := parseMatchKeyScope(key)
	if err != nil {
		return routing.MatchInput{}, err
	}

	input := routing.MatchInput{Raw: raw, Scope: "routing"}
	if explicitScope != "" {
		input.Scope = explicitScope
	}
	switch key {
	case string(routing.MatchTargetDomain):
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		return parseDomainLikeMatchInput(input, consts.Function_Domain, value)
	case string(routing.MatchTargetQName):
		if explicitScope == "" {
			input.Scope = "dns_request"
		}
		return parseDomainLikeMatchInput(input, consts.Function_QName, value)
	case string(routing.MatchTargetIP):
		if explicitScope == "dns_request" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		if isReferenceMatchValue(value) {
			return routing.MatchInput{}, fmt.Errorf("unsupported reference target %q", key+":"+value)
		}
		if _, err := netip.ParseAddr(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid ip target %q: %w", value, err)
		}
		input.Function = &config_parser.Function{Name: consts.Function_Ip, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case string(routing.MatchTargetIPCIDR):
		if explicitScope == "dns_request" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		if isReferenceMatchValue(value) {
			return routing.MatchInput{}, fmt.Errorf("unsupported reference target %q", key+":"+value)
		}
		if _, err := netip.ParsePrefix(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid ipcidr target %q: %w", value, err)
		}
		input.Function = &config_parser.Function{Name: consts.Function_Ip, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case "dip", "sip":
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		if isReferenceMatchValue(value) {
			return routing.MatchInput{}, fmt.Errorf("unsupported reference target %q", key+":"+value)
		}
		if _, err := parseAddrOrPrefix(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid %s target %q: %w", key, value, err)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case "port", "dport", "sport":
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		if _, err := common.ParsePortRange(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid %s target %q: %w", key, value, err)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case consts.Function_L4Proto:
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		switch strings.ToLower(value) {
		case "tcp", "udp":
		default:
			return routing.MatchInput{}, fmt.Errorf("invalid l4proto target %q", value)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: strings.ToLower(value)}}}
		return finalizeMatchInput(input)
	case consts.Function_IpVersion:
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		switch value {
		case "4", "6":
		default:
			return routing.MatchInput{}, fmt.Errorf("invalid ipversion target %q", value)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case consts.Function_Mac:
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		if _, err := common.ParseMac(value); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid mac target %q: %w", value, err)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case consts.Function_ProcessName:
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case consts.Function_Dscp:
		if explicitScope != "" && explicitScope != "routing" {
			return routing.MatchInput{}, fmt.Errorf("unsupported target type %q in scope %q", key, explicitScope)
		}
		if _, err := strconv.ParseUint(value, 0, 8); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid dscp target %q: %w", value, err)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	case consts.Function_QType:
		if explicitScope == "" {
			input.Scope = "dns_request"
		}
		qtype := strings.ToLower(value)
		if _, err := strconv.ParseUint(value, 0, 16); err == nil {
			qtype = value
		} else if _, ok := dnsmessage.StringToType[strings.ToUpper(value)]; !ok {
			return routing.MatchInput{}, fmt.Errorf("invalid qtype target %q", value)
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: qtype}}}
		return finalizeMatchInput(input)
	case consts.Function_Upstream:
		if explicitScope == "" {
			input.Scope = "dns_response"
		}
		input.Function = &config_parser.Function{Name: key, Params: []*config_parser.Param{{Val: value}}}
		return finalizeMatchInput(input)
	default:
		return routing.MatchInput{}, fmt.Errorf("unsupported target type %q", key)
	}
}

func parseMatchKeyScope(key string) (scope string, name string, err error) {
	switch {
	case strings.HasPrefix(key, "routing."):
		return "routing", strings.TrimPrefix(key, "routing."), nil
	case strings.HasPrefix(key, "dns_request."):
		return "dns_request", strings.TrimPrefix(key, "dns_request."), nil
	case strings.HasPrefix(key, "dns.request."):
		return "dns_request", strings.TrimPrefix(key, "dns.request."), nil
	case strings.HasPrefix(key, "dns_response."):
		return "dns_response", strings.TrimPrefix(key, "dns_response."), nil
	case strings.HasPrefix(key, "dns.response."):
		return "dns_response", strings.TrimPrefix(key, "dns.response."), nil
	default:
		return "", key, nil
	}
}

func finalizeMatchInput(input routing.MatchInput) (routing.MatchInput, error) {
	if input.Function == nil {
		return routing.MatchInput{}, fmt.Errorf("match target function is nil")
	}
	if !matchFunctionAllowed(input.Scope, input.Function.Name) {
		return routing.MatchInput{}, fmt.Errorf("unsupported match function %q in scope %q", input.Function.Name, input.Scope)
	}
	return input, nil
}

func parseDomainLikeMatchInput(input routing.MatchInput, name string, value string) (routing.MatchInput, error) {
	key, val := splitDomainMatchValue(value)
	if isReferenceMatchKey(key) {
		return routing.MatchInput{}, fmt.Errorf("unsupported reference target %q", name+":"+value)
	}
	if key == "" {
		key = string(consts.RoutingDomainKey_Suffix)
	}
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Suffix, consts.RoutingDomainKey_Full, consts.RoutingDomainKey_Keyword:
	case consts.RoutingDomainKey_Regex:
		if _, err := regexp.Compile(val); err != nil {
			return routing.MatchInput{}, fmt.Errorf("invalid %s regex target %q: %w", name, val, err)
		}
	default:
		return routing.MatchInput{}, fmt.Errorf("unsupported %s target key %q", name, key)
	}
	if key == string(consts.RoutingDomainKey_Suffix) || key == string(consts.RoutingDomainKey_Full) {
		val = strings.TrimSuffix(val, ".")
	}
	input.Function = &config_parser.Function{Name: name, Params: []*config_parser.Param{{Key: key, Val: val}}}
	return finalizeMatchInput(input)
}

func splitDomainMatchValue(value string) (key string, val string) {
	key, val, ok := strings.Cut(value, ":")
	if !ok {
		return "", value
	}
	switch key {
	case string(consts.RoutingDomainKey_Suffix),
		string(consts.RoutingDomainKey_Full),
		string(consts.RoutingDomainKey_Keyword),
		string(consts.RoutingDomainKey_Regex),
		"rule-set", "geosite", "geoip", "ext":
		return key, val
	default:
		return "", value
	}
}

func isReferenceMatchValue(value string) bool {
	key, _, ok := strings.Cut(value, ":")
	return ok && isReferenceMatchKey(key)
}

func isReferenceMatchKey(key string) bool {
	switch key {
	case "rule-set", "geosite", "geoip", "ext":
		return true
	default:
		return false
	}
}

func parseAddrOrPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
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
	case "dns_response":
		switch name {
		case "qname", "qtype", "ip", "upstream":
			return true
		default:
			return false
		}
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
