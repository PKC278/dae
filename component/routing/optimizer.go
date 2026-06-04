/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

type RulesOptimizer interface {
	Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error)
}

func DeepCloneRules(rules []*config_parser.RoutingRule) (newRules []*config_parser.RoutingRule) {
	if rules == nil {
		return nil
	}
	return deepcopy.Copy(rules).([]*config_parser.RoutingRule)
}

func ApplyRulesOptimizers(rules []*config_parser.RoutingRule, optimizers ...RulesOptimizer) ([]*config_parser.RoutingRule, error) {
	rules = DeepCloneRules(rules)
	var err error
	for _, opt := range optimizers {
		if rules, err = opt.Optimize(rules); err != nil {
			return nil, err
		}
	}
	return rules, err
}

type AliasOptimizer struct {
}

func (o *AliasOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, function := range rule.AndFunctions {
			switch function.Name {
			case "dport":
				function.Name = consts.Function_Port
			case "dip":
				function.Name = consts.Function_Ip
			}
			for _, param := range function.Params {
				if function.Name == consts.Function_Domain {
					// Rewrite to authoritative key name.
					switch param.Key {
					case "", "domain":
						param.Key = string(consts.RoutingDomainKey_Suffix)
					case "contains":
						param.Key = string(consts.RoutingDomainKey_Keyword)
					default:
					}
				}
			}
		}
	}
	return rules, nil
}

type MergeAndSortRulesOptimizer struct {
}

func (o *MergeAndSortRulesOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	// Sort AndFunctions by FunctionName.
	for _, rule := range rules {
		sort.SliceStable(rule.AndFunctions, func(i, j int) bool {
			return rule.AndFunctions[i].Name < rule.AndFunctions[j].Name
		})
	}
	// Merge singleton rules with the same outbound.
	var newRules []*config_parser.RoutingRule
	mergingRule := rules[0]
	for i := 1; i < len(rules); i++ {
		if len(mergingRule.AndFunctions) == 1 &&
			len(rules[i].AndFunctions) == 1 &&
			mergingRule.AndFunctions[0].Name == rules[i].AndFunctions[0].Name &&
			mergingRule.AndFunctions[0].Not == rules[i].AndFunctions[0].Not &&
			rules[i].Outbound.String(true, false, true) == mergingRule.Outbound.String(true, false, true) {
			mergingRule.AndFunctions[0].Params = append(mergingRule.AndFunctions[0].Params, rules[i].AndFunctions[0].Params...)
		} else {
			newRules = append(newRules, mergingRule)
			mergingRule = rules[i]
		}
	}
	newRules = append(newRules, mergingRule)
	// Sort ParamList.
	for i := range newRules {
		for _, function := range newRules[i].AndFunctions {
			if function.Name == consts.Function_Ip || function.Name == consts.Function_SourceIp {
				// Sort by IPv4, IPv6, vals.
				sort.SliceStable(function.Params, func(i, j int) bool {
					vi, vj := 4, 4
					if strings.Contains(function.Params[i].Val, ":") {
						vi = 6
					}
					if strings.Contains(function.Params[j].Val, ":") {
						vj = 6
					}
					if vi == vj {
						return function.Params[i].Val < function.Params[j].Val
					}
					return vi < vj
				})
			} else {
				// Sort by keys, vals.
				sort.SliceStable(function.Params, func(i, j int) bool {
					if function.Params[i].Key == function.Params[j].Key {
						return function.Params[i].Val < function.Params[j].Val
					}
					return function.Params[i].Key < function.Params[j].Key
				})
			}
		}
	}
	return newRules, nil
}

type DeduplicateParamsOptimizer struct {
}

func deduplicateParams(list []*config_parser.Param) []*config_parser.Param {
	res := make([]*config_parser.Param, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v.String(true, false)]; ok {
			continue
		}
		m[v.String(true, false)] = struct{}{}
		res = append(res, v)
	}
	return res
}

func (o *DeduplicateParamsOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			f.Params = deduplicateParams(f.Params)
		}
	}
	return rules, nil
}

type DatReaderOptimizer struct {
	LocationFinder                 *assets.LocationFinder
	Logger                         *logrus.Logger
	RuleProviders                  map[string]string
	RuleProviderDir                string
	RuleProviderHTTPClientResolver RuleProviderHTTPClientResolver
	RuleProviderDownloadDisabled   bool
	SkipUnavailableRuleProviders   bool
	mu                             sync.Mutex
	// Cached params are immutable by contract once stored.
	// cloneParams only copies the slice container while sharing *Param objects.
	// Downstream optimizers must not mutate Param fields.
	geoSiteCache      map[string][]*config_parser.Param
	geoIpCache        map[string][]*config_parser.Param
	ruleProviderCache map[string][]byte
}

var ErrRuleProviderUnavailable = errors.New("rule provider unavailable")

type RuleProviderHTTPClientResolver func(name string, rawURL string) (*http.Client, error)

func cloneParams(params []*config_parser.Param) []*config_parser.Param {
	if len(params) == 0 {
		return nil
	}
	out := make([]*config_parser.Param, len(params))
	copy(out, params)
	return out
}

func (o *DatReaderOptimizer) initCacheLocked() {
	if o.geoSiteCache == nil {
		o.geoSiteCache = make(map[string][]*config_parser.Param)
	}
	if o.geoIpCache == nil {
		o.geoIpCache = make(map[string][]*config_parser.Param)
	}
	if o.ruleProviderCache == nil {
		o.ruleProviderCache = make(map[string][]byte)
	}
}

func (o *DatReaderOptimizer) ruleProviderDir() string {
	if o.RuleProviderDir != "" {
		return o.RuleProviderDir
	}
	return "rules"
}

func (o *DatReaderOptimizer) storeRuleProviderContent(name string, content []byte) error {
	dir := o.ruleProviderDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create rule provider directory %q: %w", dir, err)
	}
	path := filepath.Join(dir, name+".list")
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp rule provider file %q: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp rule provider file %q: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp rule provider file %q: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("store rule provider file %q: %w", path, err)
	}
	return nil
}

type DownloadRuleProviderOptions struct {
	Dir                string
	HTTPClientResolver RuleProviderHTTPClientResolver
}

func DownloadRuleProviders(ruleProviders map[string]string, dir string) error {
	return DownloadRuleProvidersWithOptions(ruleProviders, DownloadRuleProviderOptions{Dir: dir})
}

func DownloadRuleProvidersWithOptions(ruleProviders map[string]string, opt DownloadRuleProviderOptions) error {
	if len(ruleProviders) == 0 {
		return nil
	}
	names := make([]string, 0, len(ruleProviders))
	for name := range ruleProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	optimizer := &DatReaderOptimizer{
		RuleProviders:                  ruleProviders,
		RuleProviderDir:                opt.Dir,
		RuleProviderHTTPClientResolver: opt.HTTPClientResolver,
	}
	for _, name := range names {
		if _, err := optimizer.loadRuleProviderContent(name); err != nil {
			return err
		}
	}
	return nil
}

func (o *DatReaderOptimizer) ruleProviderPath(name string) string {
	return filepath.Join(o.ruleProviderDir(), name+".list")
}

func readTextRuleProviderFile(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if !isTextRuleProviderContent(b) {
		return nil, false
	}
	return b, true
}

func isTextRuleProviderContent(content []byte) bool {
	return utf8.Valid(content) && !strings.ContainsRune(string(content), '\x00')
}

func (o *DatReaderOptimizer) downloadAndStoreRuleProviderContent(name string) ([]byte, error) {
	url, ok := o.RuleProviders[name]
	if !ok {
		return nil, fmt.Errorf("rule provider %q is not defined", name)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if o.RuleProviderHTTPClientResolver != nil {
		var err error
		client, err = o.RuleProviderHTTPClientResolver(name, url)
		if err != nil {
			return nil, fmt.Errorf("resolve HTTP client for rule provider %q: %w", name, err)
		}
		if client == nil {
			client = &http.Client{Timeout: 30 * time.Second}
		}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download rule provider %q: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download rule provider %q: unexpected HTTP status %s", name, resp.Status)
	}

	const maxRuleProviderSize = 64 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleProviderSize+1))
	if err != nil {
		return nil, fmt.Errorf("read rule provider %q: %w", name, err)
	}
	if len(b) > maxRuleProviderSize {
		return nil, fmt.Errorf("rule provider %q is too large", name)
	}
	if err = o.storeRuleProviderContent(name, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o *DatReaderOptimizer) loadRuleProviderContent(name string) ([]byte, error) {
	if _, ok := o.RuleProviders[name]; !ok {
		return nil, fmt.Errorf("rule provider %q is not defined", name)
	}

	o.mu.Lock()
	o.initCacheLocked()
	if cached, ok := o.ruleProviderCache[name]; ok {
		o.mu.Unlock()
		return cached, nil
	}
	o.mu.Unlock()

	if b, ok := readTextRuleProviderFile(o.ruleProviderPath(name)); ok {
		o.mu.Lock()
		o.initCacheLocked()
		o.ruleProviderCache[name] = b
		o.mu.Unlock()
		return b, nil
	}

	if o.RuleProviderDownloadDisabled {
		return nil, fmt.Errorf("%w: %q", ErrRuleProviderUnavailable, name)
	}

	b, err := o.downloadAndStoreRuleProviderContent(name)
	if err != nil {
		return nil, err
	}

	o.mu.Lock()
	o.initCacheLocked()
	o.ruleProviderCache[name] = b
	o.mu.Unlock()
	return b, nil
}

func parseRuleProviderLines(content []byte) []string {
	lines := strings.Split(string(content), "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.EqualFold(line, "payload:") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		}
		line = trimRuleProviderInlineComment(line)
		line = trimRuleProviderQuotes(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		values = append(values, line)
	}
	return values
}

func trimRuleProviderInlineComment(line string) string {
	var quote rune
	for i, r := range line {
		switch r {
		case '\'', '"':
			switch quote {
			case 0:
				quote = r
			case r:
				quote = 0
			}
		case '#':
			if quote == 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}

func trimRuleProviderQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	if (value[0] == '\'' && value[len(value)-1] == '\'') ||
		(value[0] == '"' && value[len(value)-1] == '"') {
		return value[1 : len(value)-1]
	}
	return value
}

func parseRuleProviderDomain(value string) (*config_parser.Param, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || isRuleProviderIPCIDR(value) || strings.Contains(value, ",") {
		return nil, false
	}
	switch {
	case strings.HasPrefix(value, "+."):
		return &config_parser.Param{Key: string(consts.RoutingDomainKey_Suffix), Val: strings.TrimPrefix(value, "+.")}, true
	case strings.HasPrefix(value, "."):
		return &config_parser.Param{Key: string(consts.RoutingDomainKey_Suffix), Val: value}, true
	case strings.Contains(value, "*"):
		return &config_parser.Param{Key: string(consts.RoutingDomainKey_Regex), Val: clashWildcardToRegex(value)}, true
	default:
		return &config_parser.Param{Key: string(consts.RoutingDomainKey_Full), Val: value}, true
	}
}

func parseRuleProviderIPCIDR(value string) (*config_parser.Param, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, false
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return &config_parser.Param{Val: value}, true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is4() {
			return &config_parser.Param{Val: netip.PrefixFrom(addr, 32).String()}, true
		}
		return &config_parser.Param{Val: netip.PrefixFrom(addr, 128).String()}, true
	}
	return nil, false
}

func isRuleProviderIPCIDR(value string) bool {
	if _, ok := parseRuleProviderIPCIDR(value); ok {
		return true
	}
	return false
}

func clashWildcardToRegex(value string) string {
	if value == "*" {
		return `^[^.]+$`
	}
	parts := strings.Split(value, "*")
	var b strings.Builder
	b.WriteString("^")
	for i, part := range parts {
		if i > 0 {
			b.WriteString(`[^.]+`)
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString("$")
	return b.String()
}

func (o *DatReaderOptimizer) loadRuleProvider(functionName string, name string) ([]*config_parser.Param, error) {
	content, err := o.loadRuleProviderContent(name)
	if err != nil {
		return nil, err
	}
	lines := parseRuleProviderLines(content)
	params := make([]*config_parser.Param, 0, len(lines))
	switch functionName {
	case consts.Function_Domain, consts.Function_QName:
		for _, line := range lines {
			if param, ok := parseRuleProviderDomain(line); ok {
				params = append(params, param)
			}
		}
	case consts.Function_Ip, consts.Function_SourceIp:
		for _, line := range lines {
			if param, ok := parseRuleProviderIPCIDR(line); ok {
				params = append(params, param)
			}
		}
	default:
		return nil, fmt.Errorf("rule-set is unsupported in function %v", functionName)
	}
	return params, nil
}

func (o *DatReaderOptimizer) loadGeoSite(filename string, code string) (params []*config_parser.Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}

	cacheKey := strings.ToLower(filename + ":" + code)
	o.mu.Lock()
	o.initCacheLocked()
	if cached, ok := o.geoSiteCache[cacheKey]; ok {
		o.mu.Unlock()
		return cloneParams(cached), nil
	}
	o.mu.Unlock()

	filePath, err := o.LocationFinder.GetLocationAsset(o.Logger, filename)
	if err != nil {
		o.Logger.Debugf("Failed to read geosite \"%v:%v\": %v", filename, code, err)
		return nil, err
	}
	o.Logger.Debugf("Read geosite \"%v:%v\" from %v", filename, code, filePath)
	code, attr, _ := strings.Cut(code, "@")
	geoSite, err := geodata.UnmarshalGeoSite(o.Logger, filePath, code)
	if err != nil {
		return nil, err
	}
	for _, item := range geoSite.Domain {
		if attr != "" {
			// Filter by attr.
			attrHit := false
			for _, itemAttr := range item.Attribute {
				if strings.EqualFold(itemAttr.Key, attr) {
					attrHit = true
					break
				}
			}
			if !attrHit {
				continue
			}
		}

		switch item.Type {
		case geodata.Domain_Full:
			// Full.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Full),
				Val: item.Value,
			})
		case geodata.Domain_RootDomain:
			// Suffix.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Suffix),
				Val: item.Value,
			})
		case geodata.Domain_Plain:
			// Keyword.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Keyword),
				Val: item.Value,
			})
		case geodata.Domain_Regex:
			// Regex.
			params = append(params, &config_parser.Param{
				Key: string(consts.RoutingDomainKey_Regex),
				Val: item.Value,
			})
		}
	}

	o.mu.Lock()
	o.initCacheLocked()
	o.geoSiteCache[cacheKey] = cloneParams(params)
	o.mu.Unlock()

	return params, nil
}

func (o *DatReaderOptimizer) loadGeoIp(filename string, code string) (params []*config_parser.Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}

	cacheKey := strings.ToLower(filename + ":" + code)
	o.mu.Lock()
	o.initCacheLocked()
	if cached, ok := o.geoIpCache[cacheKey]; ok {
		o.mu.Unlock()
		return cloneParams(cached), nil
	}
	o.mu.Unlock()

	filePath, err := o.LocationFinder.GetLocationAsset(o.Logger, filename)
	if err != nil {
		o.Logger.Debugf("Failed to read geoip \"%v:%v\": %v", filename, code, err)
		return nil, err
	}
	o.Logger.Debugf("Read geoip \"%v:%v\" from %v", filename, code, filePath)
	geoIp, err := geodata.UnmarshalGeoIp(o.Logger, filePath, code)
	if err != nil {
		return nil, err
	}
	if geoIp.InverseMatch {
		return nil, fmt.Errorf("not support inverse match yet")
	}
	for _, item := range geoIp.Cidr {
		ip, ok := netip.AddrFromSlice(item.Ip)
		if !ok {
			return nil, fmt.Errorf("bad geoip file: %v", filename)
		}
		params = append(params, &config_parser.Param{
			Key: "",
			Val: netip.PrefixFrom(ip, int(item.Prefix)).String(),
		})
	}

	o.mu.Lock()
	o.initCacheLocked()
	o.geoIpCache[cacheKey] = cloneParams(params)
	o.mu.Unlock()

	return params, nil
}

func (o *DatReaderOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	// Process rules in parallel for better performance.
	// Limit concurrency to avoid overwhelming the system.
	type ruleResult struct {
		index int
		rule  *config_parser.RoutingRule
		err   error
	}

	numWorkers := min(len(rules), 4)

	sem := make(chan struct{}, numWorkers)
	results := make(chan ruleResult, len(rules))
	var wg sync.WaitGroup

	for i, rule := range rules {
		wg.Add(1)
		go func(idx int, r *config_parser.RoutingRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Process this rule's functions
			dropRule := false
			for _, f := range r.AndFunctions {
				var newParams []*config_parser.Param
				var loadErr error
				for _, param := range f.Params {
					// Parse this param and replace it with more.
					var params []*config_parser.Param
					switch param.Key {
					case "geosite":
						params, loadErr = o.loadGeoSite("geosite", param.Val)
					case "geoip":
						params, loadErr = o.loadGeoIp("geoip", param.Val)
					case "rule-set":
						params, loadErr = o.loadRuleProvider(f.Name, param.Val)
					case "ext":
						fields := strings.SplitN(param.Val, ":", 2)
						if len(fields) != 2 {
							loadErr = fmt.Errorf("bad extension file extraction: %v", param.Val)
							break
						}
						switch f.Name {
						case consts.Function_Domain, consts.Function_QName:
							params, loadErr = o.loadGeoSite(fields[0], fields[1])
						case consts.Function_Ip:
							params, loadErr = o.loadGeoIp(fields[0], fields[1])
						default:
							loadErr = fmt.Errorf("unsupported extension file extraction in function %v", f.Name)
						}
					default:
						// Keep this param.
						params = []*config_parser.Param{param}
					}
					if loadErr != nil {
						if o.SkipUnavailableRuleProviders && errors.Is(loadErr, ErrRuleProviderUnavailable) {
							loadErr = nil
							params = nil
						} else {
							results <- ruleResult{idx, nil, loadErr}
							return
						}
					}
					newParams = append(newParams, params...)
				}
				if len(f.Params) > 0 && len(newParams) == 0 {
					dropRule = true
					break
				}
				f.Params = newParams
			}
			if dropRule {
				results <- ruleResult{idx, nil, nil}
				return
			}
			results <- ruleResult{idx, r, nil}
		}(i, rule)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	orderedRules := make([]*config_parser.RoutingRule, len(rules))
	for result := range results {
		if result.err != nil {
			return nil, result.err
		}
		orderedRules[result.index] = result.rule
	}
	newRules := make([]*config_parser.RoutingRule, 0, len(orderedRules))
	for _, rule := range orderedRules {
		if rule == nil {
			continue
		}
		newRules = append(newRules, rule)
	}

	return newRules, nil
}
