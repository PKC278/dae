/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func parseDnsSection(t *testing.T, dnsBlock string) *config.Dns {
	t.Helper()
	sections, err := config_parser.Parse("global {}\ndns {\n" + dnsBlock + "\n}\nrouting {\n fallback: direct\n}\n")
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)
	return &conf.Dns
}

func TestParseUpstreamDeclaration(t *testing.T) {
	decl, err := ParseUpstreamDeclaration("hk:tcp+udp://8.8.8.8:53 [outbound:hk_group]")
	require.NoError(t, err)
	require.Equal(t, &UpstreamDeclaration{Tag: "hk", Link: "tcp+udp://8.8.8.8:53", Outbound: "hk_group"}, decl)

	decl, err = ParseUpstreamDeclaration("v6:udp://[2001:db8::1]")
	require.NoError(t, err)
	require.Equal(t, &UpstreamDeclaration{Tag: "v6", Link: "udp://[2001:db8::1]"}, decl)

	_, err = ParseUpstreamDeclaration("hk:udp://8.8.8.8 [via:hk_group]")
	require.ErrorIs(t, err, ErrBadUpstreamFormat)
	require.ErrorContains(t, err, `unknown annotation "via"`)

	_, err = ParseUpstreamDeclaration("hk:udp://8.8.8.8 [outbound:a,outbound:b]")
	require.ErrorContains(t, err, "duplicated annotation")

	_, err = ParseUpstreamDeclaration("udp://8.8.8.8")
	require.ErrorIs(t, err, ErrBadUpstreamFormat)
}

func TestValidateUpstreamOutbounds(t *testing.T) {
	groups := map[string]bool{"direct": true, "block": true, "hk_group": true}
	exists := func(name string) bool { return groups[name] }

	ok := parseDnsSection(t, `upstream {
    hk: 'udp://8.8.8.8:53' [outbound: hk_group]
    local: 'udp://223.5.5.5:53' [outbound: direct]
    plain: 'udp://1.1.1.1:53'
}`)
	require.NoError(t, ValidateUpstreamOutbounds(ok, exists))

	missing := parseDnsSection(t, `upstream {
    us: 'udp://8.8.8.8:53' [outbound: us_group]
}`)
	require.ErrorContains(t, ValidateUpstreamOutbounds(missing, exists), `outbound (group) "us_group" not found`)

	block := parseDnsSection(t, `upstream {
    bad: 'udp://8.8.8.8:53' [outbound: block]
}`)
	require.ErrorContains(t, ValidateUpstreamOutbounds(block, exists), "use reject")
}

// The same address declared under two aliases must stay two upstreams, each
// carrying its own outbound, so request routing can send different qnames
// through different groups.
func TestNewBindsUpstreamOutbound(t *testing.T) {
	dnsCfg := parseDnsSection(t, `upstream {
    google_hk: 'tcp+udp://8.8.8.8:53' [outbound: hk_group]
    google_us: 'tcp+udp://8.8.8.8:53' [outbound: us_group]
    google: 'tcp+udp://8.8.8.8:53'
}
routing {
    request {
        qname(suffix: netflix.com) -> google_us
        qname(suffix: example.com) -> google
        fallback: google_hk
    }
}`)
	s, err := New(dnsCfg, &NewOption{
		Logger:                logrus.New(),
		UpstreamReadyCallback: func(*Upstream) error { return nil },
	})
	require.NoError(t, err)
	require.Len(t, s.upstream, 3)

	ctx := context.Background()
	cases := []struct {
		qname    string
		outbound string
	}{
		{"www.netflix.com.", "us_group"},
		{"www.example.com.", ""},
		{"www.google.com.", "hk_group"},
	}
	for _, c := range cases {
		_, upstream, err := s.RequestSelect(ctx, c.qname, 1)
		require.NoError(t, err, c.qname)
		require.NotNil(t, upstream, c.qname)
		require.Equal(t, "tcp+udp://8.8.8.8:53", upstream.String(), c.qname)
		require.Equal(t, c.outbound, upstream.Outbound, c.qname)
	}
}
