/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const downloadRoutingConfig = `
global {}
rule_provider {
  viaproxy: 'https://proxied.example/rules.list'
  viadirect: 'https://plain.example/rules.list'
}
routing {
  domain(suffix: plain.example) -> direct
  domain(suffix: proxied.example) -> node_selection
  fallback: direct
}
dns {
  upstream { localdns: 'udp://127.0.0.1:53' }
}
`

// downloadRoutingFixture builds the pieces downloadRuleProvidersThroughRouting
// needs: outbound groups named direct/block/node_selection, each backed by a
// direct dialer that this test never actually dials through.
func downloadRoutingFixture(t *testing.T) (*logrus.Logger, *config.Config, map[string]string, map[string]uint8, []*outbound.DialerGroup) {
	t.Helper()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	sections, err := config_parser.Parse(downloadRoutingConfig)
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)

	ruleProviderMap, err := config.KeyableStringMap(conf.RuleProvider)
	require.NoError(t, err)

	option := dialer.NewGlobalOption(&conf.Global, log)
	newGroup := func(name string) *outbound.DialerGroup {
		raw, property := dialer.NewDirectDialer(option, true)
		d := dialer.NewDialerContext(t.Context(), raw, option,
			dialer.InstanceOption{DisableCheck: true}, property)
		return outbound.NewDialerGroup(option, name, []*dialer.Dialer{d},
			[]*dialer.Annotation{{}},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, func(bool, *dialer.NetworkType, bool) {})
	}
	outbounds := []*outbound.DialerGroup{
		newGroup(consts.OutboundDirect.String()),
		newGroup(consts.OutboundBlock.String()),
		newGroup("node_selection"),
	}
	name2id := map[string]uint8{}
	for i, o := range outbounds {
		name2id[o.Name] = uint8(i)
	}
	return log, conf, ruleProviderMap, name2id, outbounds
}

// A rule provider whose host matches a rule pointing at a node group must be
// downloaded through that group, not directly.
func TestRuleProviderDownloadFollowsRoutingToNode(t *testing.T) {
	log, conf, ruleProviderMap, name2id, outbounds := downloadRoutingFixture(t)
	dir := t.TempDir()

	matcher, err := buildRuleProviderDownloadMatcher(log,
		assets.NewLocationFinder([]string{dir}), &conf.Routing,
		ruleProviderMap, dir, name2id)
	require.NoError(t, err)

	for _, tc := range []struct{ name, url, wantOutbound string }{
		{"viaproxy", "https://proxied.example/rules.list", "node_selection"},
		{"viadirect", "https://plain.example/rules.list", consts.OutboundDirect.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, outboundName, err := ruleProviderHTTPClientFromRouting(
				log, tc.name, tc.url, matcher, outbounds, &conf.Global, nil)
			require.NoError(t, err)
			require.NotNil(t, client)
			require.Equal(t, tc.wantOutbound, outboundName)
		})
	}
}

// The routing program used to pick a download outbound is compiled on demand.
// Routing at an outbound that does not exist makes that compile fail, which
// makes "was it compiled?" observable: a warm cache must download nothing and
// therefore never compile it, while a cold cache must compile it and surface
// the failure.
const unbuildableMatcherConfig = `
global {}
rule_provider { onlyone: 'https://proxied.example/rules.list' }
routing {
  domain(suffix: proxied.example) -> nonexistent_outbound
  fallback: direct
}
dns { upstream { localdns: 'udp://127.0.0.1:53' } }
`

func unbuildableMatcherFixture(t *testing.T) (*logrus.Logger, *config.Config, map[string]string, map[string]uint8) {
	t.Helper()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	sections, err := config_parser.Parse(unbuildableMatcherConfig)
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)
	ruleProviderMap, err := config.KeyableStringMap(conf.RuleProvider)
	require.NoError(t, err)
	return log, conf, ruleProviderMap, map[string]uint8{
		consts.OutboundDirect.String(): 0,
		consts.OutboundBlock.String():  1,
	}
}

func TestRuleProviderDownloadMatcherNotBuiltWhenCacheWarm(t *testing.T) {
	log, conf, ruleProviderMap, name2id := unbuildableMatcherFixture(t)
	dir := t.TempDir()
	for name := range ruleProviderMap {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".list"),
			[]byte("+.cached.example\n"), 0644))
	}

	downloaded, err := downloadRuleProvidersThroughRouting(log,
		assets.NewLocationFinder([]string{dir}), &conf.Routing,
		ruleProviderMap, dir, name2id, nil, &conf.Global, nil, false, false, false)
	require.NoError(t, err, "warm cache must not compile the download matcher")
	require.False(t, downloaded, "warm cache must not trigger any download")
}

func TestRuleProviderDownloadMatcherBuiltWhenCacheCold(t *testing.T) {
	log, conf, ruleProviderMap, name2id := unbuildableMatcherFixture(t)
	dir := t.TempDir()

	downloaded, err := downloadRuleProvidersThroughRouting(log,
		assets.NewLocationFinder([]string{dir}), &conf.Routing,
		ruleProviderMap, dir, name2id, nil, &conf.Global, nil, false, false, false)
	require.Error(t, err, "cold cache must compile the download matcher")
	require.Contains(t, err.Error(), "build rule provider download router")
	require.True(t, downloaded, "a cold cache must report a download attempt")
}

// A stale-but-present cache refreshed against an unreachable host must not fail
// the build: the cached copies stay usable, so dae starts on slightly old rules
// rather than not at all.
func TestBestEffortRefreshToleratesDownloadFailure(t *testing.T) {
	log, conf, ruleProviderMap, name2id, outbounds := downloadRoutingFixture(t)
	dir := t.TempDir()
	for name := range ruleProviderMap {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".list"),
			[]byte("+.cached.example\n"), 0644))
	}

	downloaded, err := downloadRuleProvidersThroughRouting(log,
		assets.NewLocationFinder([]string{dir}), &conf.Routing,
		ruleProviderMap, dir, name2id, outbounds, &conf.Global, nil,
		true /* force */, false /* ignoreErrors */, true /* bestEffort */)
	require.NoError(t, err, "a best-effort refresh must not fail the build")
	require.True(t, downloaded)

	// The cached copies must survive a failed refresh.
	for name := range ruleProviderMap {
		b, readErr := os.ReadFile(filepath.Join(dir, name+".list"))
		require.NoError(t, readErr)
		require.Equal(t, "+.cached.example\n", string(b))
	}
}

// Without the best-effort flag the same failure is still fatal, which is what
// keeps a genuinely missing rule set from being silently skipped.
func TestForcedRefreshWithoutBestEffortStillFails(t *testing.T) {
	log, conf, ruleProviderMap, name2id, outbounds := downloadRoutingFixture(t)
	dir := t.TempDir()
	for name := range ruleProviderMap {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".list"),
			[]byte("+.cached.example\n"), 0644))
	}

	_, err := downloadRuleProvidersThroughRouting(log,
		assets.NewLocationFinder([]string{dir}), &conf.Routing,
		ruleProviderMap, dir, name2id, outbounds, &conf.Global, nil,
		true /* force */, false /* ignoreErrors */, false /* bestEffort */)
	require.Error(t, err)
}
