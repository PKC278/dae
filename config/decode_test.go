/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestNewUsesExplicitSectionDecoders(t *testing.T) {
	sections, err := config_parser.Parse(`
global {
  log_level: info
  so_mark_from_dae: 1234
}

subscription {
  "https://example.com/sub"
}

node {
  "ss://example"
}

group {
  proxy {
    policy: random
    filter: name(keyword: hk)
  }
}

rule_provider {
  cn: "https://example.com/cn.list"
}

routing {
  domain(rule-set:cn) -> direct
  pname(NetworkManager) -> direct
  fallback: proxy
}

dns {
  ipversion_prefer: 6
  upstream {
    google:"8.8.8.8:53"
  }
  routing {
    request {
      qname(geosite:geolocation-!cn) -> proxy
      fallback: direct
    }
    response {
      fallback: proxy
    }
  }
}
`)
	require.NoError(t, err)

	conf, err := New(sections)
	require.NoError(t, err)
	require.True(t, conf.Global.SoMarkFromDaeSet)
	require.Len(t, conf.Subscription, 1)
	require.Len(t, conf.Node, 1)
	require.Len(t, conf.Group, 1)
	require.Equal(t, "proxy", conf.Group[0].Name)
	require.Equal(t, []KeyableString{"cn:https://example.com/cn.list"}, conf.RuleProvider)
	require.Equal(t, 6, conf.Dns.IpVersionPrefer)
	require.NotNil(t, conf.Routing.Fallback)
	require.NotNil(t, conf.Dns.Routing.Request.Fallback)
	require.NotNil(t, conf.Dns.Routing.Response.Fallback)
}

func TestGlobalMemoryDefaults(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
  fallback: direct
}
`)
	require.NoError(t, err)

	conf, err := New(sections)
	require.NoError(t, err)
	require.True(t, conf.Global.DisableTHP)
	require.EqualValues(t, 262144, conf.Global.BpfConnStateMapSize)
}

func TestDecodeConfigSectionRejectsUnknownSection(t *testing.T) {
	conf := &Config{}
	err := decodeConfigSection(conf, "unknown", &config_parser.Section{Name: "unknown"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown section")
}

func TestRuleProviderRejectsDuplicateName(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
rule_provider {
  cn: "https://example.com/cn.list"
  cn: "https://example.com/cn2.list"
}
routing {}
`)
	require.NoError(t, err)

	_, err = New(sections)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicated key")
}

func TestRuleProviderUpdateIntervalSupportsSecondsAndDays(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "seconds", raw: "30s", want: 30 * time.Second},
		{name: "days", raw: "2d", want: 48 * time.Hour},
		{name: "disabled", raw: "0", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sections, err := config_parser.Parse(`
global {
  rule_provider_update_interval: ` + tc.raw + `
}
routing {}
`)
			require.NoError(t, err)

			conf, err := New(sections)
			require.NoError(t, err)
			require.Equal(t, tc.want, conf.Global.RuleProviderUpdateInterval)
		})
	}
}

func TestRuleProviderUpdateIntervalDefaultsToDisabled(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {}
`)
	require.NoError(t, err)

	conf, err := New(sections)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), conf.Global.RuleProviderUpdateInterval)
}

func TestRuleProviderUpdateIntervalRejectsUnsupportedUnit(t *testing.T) {
	sections, err := config_parser.Parse(`
global {
  rule_provider_update_interval: 1m
}
routing {}
`)
	require.NoError(t, err)

	_, err = New(sections)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected s or d")
}
