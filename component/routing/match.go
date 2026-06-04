/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

type MatchTargetType string

const (
	MatchTargetDomain MatchTargetType = "domain"
	MatchTargetQName  MatchTargetType = "qname"
	MatchTargetIP     MatchTargetType = "ip"
	MatchTargetIPCIDR MatchTargetType = "ipcidr"
)

type MatchSource struct {
	Kind       string
	Name       string
	File       string
	Pattern    string
	Normalized string
}

type MatchHit struct {
	Rule    string
	Source  MatchSource
	Action  string
	Partial bool
}

type MatchReport struct {
	Target   string
	Scope    string
	Action   string
	Fallback string
	Hits     []*MatchHit
	Hit      *MatchHit
}

type MatchOption struct {
	Logger          *logrus.Logger
	LocationFinder  *assets.LocationFinder
	RuleProviders   map[string]string
	RuleProviderDir string
}

type sourcedParam struct {
	param  *config_parser.Param
	source MatchSource
}

type MatchInput struct {
	Raw      string
	Scope    string
	Function *config_parser.Function
}

func MatchRules(
	rules []*config_parser.RoutingRule,
	fallback config.FunctionOrString,
	input MatchInput,
	opt MatchOption,
) (*MatchReport, error) {
	if input.Function == nil {
		return nil, fmt.Errorf("match input function is nil")
	}
	inputFunc := cloneMatchFunction(input.Function)
	normalizeMatchFunction(inputFunc)
	scope, actionLabel, err := matchScopeSpec(input.Scope)
	if err != nil {
		return nil, err
	}
	fallbackFunc, err := config.ParseFunctionOrString(fallback)
	if err != nil {
		return nil, err
	}
	report := &MatchReport{
		Target:   input.Raw,
		Scope:    scope,
		Action:   actionLabel,
		Fallback: fallbackFunc.String(true, false, true),
	}
	optimizer := &DatReaderOptimizer{
		LocationFinder:  opt.LocationFinder,
		Logger:          opt.Logger,
		RuleProviders:   opt.RuleProviders,
		RuleProviderDir: opt.RuleProviderDir,
	}

	normalizedRules, err := (&AliasOptimizer{}).Optimize(DeepCloneRules(rules))
	if err != nil {
		return nil, err
	}
	for _, rule := range normalizedRules {
		hit, ok, err := matchRuleTarget(rule, inputFunc, optimizer)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		hit.Rule = formatMatchRule(rule)
		hit.Action = rule.Outbound.String(true, false, true)
		report.Hits = append(report.Hits, hit)
		report.Hit = hit
		if !hit.Partial {
			return report, nil
		}
	}
	return report, nil
}

func formatMatchRule(rule *config_parser.RoutingRule) string {
	outbound := rule.Outbound.String(true, false, true)
	ruleText := rule.String(false, true, false)
	compactSuffix := "->" + outbound
	if strings.HasSuffix(ruleText, compactSuffix) {
		return strings.TrimSuffix(ruleText, compactSuffix) + " -> " + outbound
	}
	return ruleText
}

func cloneMatchFunction(f *config_parser.Function) *config_parser.Function {
	out := &config_parser.Function{Name: f.Name, Not: f.Not}
	if len(f.Params) > 0 {
		out.Params = make([]*config_parser.Param, 0, len(f.Params))
		for _, param := range f.Params {
			cp := *param
			out.Params = append(out.Params, &cp)
		}
	}
	return out
}

func normalizeMatchFunction(function *config_parser.Function) {
	switch function.Name {
	case "dport":
		function.Name = consts.Function_Port
	case "dip":
		function.Name = consts.Function_Ip
	}
	if function.Name != consts.Function_Domain && function.Name != consts.Function_QName {
		return
	}
	for _, param := range function.Params {
		switch param.Key {
		case "", "domain":
			param.Key = string(consts.RoutingDomainKey_Suffix)
		case "contains":
			param.Key = string(consts.RoutingDomainKey_Keyword)
		}
	}
}

func matchScopeSpec(scope string) (scopeName, actionLabel string, err error) {
	switch scope {
	case "routing":
		return "routing", "outbound", nil
	case "dns_request":
		return "dns_request", "upstream", nil
	default:
		return "", "", fmt.Errorf("unsupported match scope: %v", scope)
	}
}

func matchRuleTarget(rule *config_parser.RoutingRule, target *config_parser.Function, optimizer *DatReaderOptimizer) (*MatchHit, bool, error) {
	var (
		seenTargetFunction bool
		partial            bool
		firstSource        *MatchSource
	)
	for _, f := range rule.AndFunctions {
		if f.Name != target.Name {
			partial = true
			continue
		}
		seenTargetFunction = true
		params, err := expandSourcedParams(f, optimizer)
		if err != nil {
			return nil, false, err
		}
		funcHit := false
		var hitSource *MatchSource
		for _, param := range params {
			ok, err := sourcedParamMatches(param, f.Name, target)
			if err != nil {
				return nil, false, err
			}
			if ok {
				funcHit = true
				source := param.source
				hitSource = &source
				break
			}
		}
		if f.Not {
			funcHit = !funcHit
			if funcHit && hitSource == nil && len(params) > 0 {
				source := params[0].source
				hitSource = &source
			}
		}
		if !funcHit {
			return nil, false, nil
		}
		if firstSource == nil && hitSource != nil {
			firstSource = hitSource
		}
	}
	if !seenTargetFunction {
		return nil, false, nil
	}
	hit := &MatchHit{Partial: partial}
	if firstSource != nil {
		hit.Source = *firstSource
	}
	return hit, true, nil
}

func expandSourcedParams(f *config_parser.Function, optimizer *DatReaderOptimizer) ([]sourcedParam, error) {
	out := make([]sourcedParam, 0, len(f.Params))
	for _, param := range f.Params {
		params, err := expandSourcedParam(f.Name, param, optimizer)
		if err != nil {
			return nil, err
		}
		out = append(out, params...)
	}
	return out, nil
}

func expandSourcedParam(functionName string, param *config_parser.Param, optimizer *DatReaderOptimizer) ([]sourcedParam, error) {
	switch param.Key {
	case "rule-set":
		return expandRuleSetSourcedParams(functionName, param.Val, optimizer)
	case "geosite":
		return expandGeoSiteSourcedParams("geosite", param.Val, optimizer)
	case "geoip":
		return expandGeoIPSourcedParams("geoip", param.Val, optimizer)
	case "ext":
		fields := strings.SplitN(param.Val, ":", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("bad extension file extraction: %v", param.Val)
		}
		switch functionName {
		case consts.Function_Domain, consts.Function_QName:
			return expandGeoSiteSourcedParams(fields[0], fields[1], optimizer)
		case consts.Function_Ip, consts.Function_SourceIp:
			return expandGeoIPSourcedParams(fields[0], fields[1], optimizer)
		default:
			return nil, fmt.Errorf("unsupported extension file extraction in function %v", functionName)
		}
	default:
		return []sourcedParam{{
			param: param,
			source: MatchSource{
				Kind:       "inline",
				Pattern:    param.String(true, false),
				Normalized: normalizeParam(param),
			},
		}}, nil
	}
}

func expandRuleSetSourcedParams(functionName string, name string, optimizer *DatReaderOptimizer) ([]sourcedParam, error) {
	content, err := optimizer.loadRuleProviderContent(name)
	if err != nil {
		return nil, err
	}
	lines := parseRuleProviderLines(content)
	out := make([]sourcedParam, 0, len(lines))
	for _, line := range lines {
		var (
			param *config_parser.Param
			ok    bool
		)
		switch functionName {
		case consts.Function_Domain, consts.Function_QName:
			param, ok = parseRuleProviderDomain(line)
		case consts.Function_Ip:
			param, ok = parseRuleProviderIPCIDR(line)
		default:
			return nil, fmt.Errorf("rule-set is unsupported in function %v", functionName)
		}
		if !ok {
			continue
		}
		out = append(out, sourcedParam{
			param: param,
			source: MatchSource{
				Kind:       "rule_provider",
				Name:       name,
				File:       optimizer.ruleProviderPath(name),
				Pattern:    line,
				Normalized: normalizeParam(param),
			},
		})
	}
	return out, nil
}

func expandGeoSiteSourcedParams(filename, code string, optimizer *DatReaderOptimizer) ([]sourcedParam, error) {
	params, err := optimizer.loadGeoSite(filename, code)
	if err != nil {
		return nil, err
	}
	file := filename
	if !strings.HasSuffix(file, ".dat") {
		file += ".dat"
	}
	out := make([]sourcedParam, 0, len(params))
	for _, param := range params {
		out = append(out, sourcedParam{
			param: param,
			source: MatchSource{
				Kind:       "geosite",
				Name:       code,
				File:       file,
				Pattern:    param.Val,
				Normalized: normalizeParam(param),
			},
		})
	}
	return out, nil
}

func expandGeoIPSourcedParams(filename, code string, optimizer *DatReaderOptimizer) ([]sourcedParam, error) {
	params, err := optimizer.loadGeoIp(filename, code)
	if err != nil {
		return nil, err
	}
	file := filename
	if !strings.HasSuffix(file, ".dat") {
		file += ".dat"
	}
	out := make([]sourcedParam, 0, len(params))
	for _, param := range params {
		out = append(out, sourcedParam{
			param: param,
			source: MatchSource{
				Kind:       "geoip",
				Name:       code,
				File:       file,
				Pattern:    param.Val,
				Normalized: normalizeParam(param),
			},
		})
	}
	return out, nil
}

func normalizeParam(param *config_parser.Param) string {
	if param.Key == "" {
		return param.Val
	}
	return param.Key + ":" + param.Val
}

func sourcedParamMatches(param sourcedParam, functionName string, target *config_parser.Function) (bool, error) {
	switch functionName {
	case consts.Function_Domain, consts.Function_QName:
		for _, targetParam := range target.Params {
			if ok, err := domainParamMatches(param.param, targetParam.Val); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	case consts.Function_Ip, consts.Function_SourceIp:
		return ipTargetParamMatches(param.param, target)
	case consts.Function_Port, consts.Function_SourcePort:
		return portTargetParamMatches(param.param, target)
	case consts.Function_L4Proto, consts.Function_IpVersion, consts.Function_ProcessName, consts.Function_Dscp:
		return stringTargetParamMatches(param.param, target), nil
	case consts.Function_Mac:
		return macTargetParamMatches(param.param, target)
	default:
		return false, fmt.Errorf("unsupported match function: %v", functionName)
	}
}

func domainParamMatches(param *config_parser.Param, domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	value := strings.ToLower(strings.TrimSuffix(param.Val, "."))
	switch consts.RoutingDomainKey(param.Key) {
	case consts.RoutingDomainKey_Suffix:
		if strings.HasPrefix(value, ".") {
			return strings.HasSuffix(domain, value), nil
		}
		return domain == value || strings.HasSuffix(domain, "."+value), nil
	case consts.RoutingDomainKey_Full:
		return domain == value, nil
	case consts.RoutingDomainKey_Keyword:
		return strings.Contains(domain, value), nil
	case consts.RoutingDomainKey_Regex:
		re, err := regexp.Compile(param.Val)
		if err != nil {
			return false, err
		}
		return re.MatchString(domain), nil
	default:
		return false, fmt.Errorf("unsupported domain key: %v", param.Key)
	}
}

func ipTargetParamMatches(param *config_parser.Param, target *config_parser.Function) (bool, error) {
	rulePrefix, err := parseMatchPrefix(param.Val)
	if err != nil {
		return false, err
	}
	for _, targetParam := range target.Params {
		if strings.Contains(targetParam.Val, "/") {
			targetPrefix, err := parseMatchPrefix(targetParam.Val)
			if err != nil {
				return false, err
			}
			if prefixesOverlap(rulePrefix, targetPrefix) {
				return true, nil
			}
			continue
		}
		addr, err := netip.ParseAddr(targetParam.Val)
		if err != nil {
			return false, err
		}
		if rulePrefix.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

func portTargetParamMatches(param *config_parser.Param, target *config_parser.Function) (bool, error) {
	ruleRange, err := common.ParsePortRange(param.Val)
	if err != nil {
		return false, err
	}
	for _, targetParam := range target.Params {
		targetRange, err := common.ParsePortRange(targetParam.Val)
		if err != nil {
			return false, err
		}
		if ruleRange[0] <= targetRange[1] && targetRange[0] <= ruleRange[1] {
			return true, nil
		}
	}
	return false, nil
}

func stringTargetParamMatches(param *config_parser.Param, target *config_parser.Function) bool {
	for _, targetParam := range target.Params {
		if strings.EqualFold(param.Val, targetParam.Val) {
			return true
		}
	}
	return false
}

func macTargetParamMatches(param *config_parser.Param, target *config_parser.Function) (bool, error) {
	ruleMac, err := common.ParseMac(param.Val)
	if err != nil {
		return false, err
	}
	for _, targetParam := range target.Params {
		targetMac, err := common.ParseMac(targetParam.Val)
		if err != nil {
			return false, err
		}
		if ruleMac == targetMac {
			return true, nil
		}
	}
	return false, nil
}

func parseMatchPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
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

func prefixesOverlap(a, b netip.Prefix) bool {
	a = a.Masked()
	b = b.Masked()
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
