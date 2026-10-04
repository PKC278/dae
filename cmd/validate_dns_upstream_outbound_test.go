/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestValidateDnsUpstreamOutbounds(t *testing.T) {
	parse := func(t *testing.T, outbound string) *config.Config {
		t.Helper()
		sections, err := config_parser.Parse(`
global {}
dns {
  upstream {
    google: 'udp://8.8.8.8:53' [outbound: ` + outbound + `]
  }
}
group {
  hk_group {
    policy: min
  }
}
routing {
  fallback: direct
}
`)
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		return conf
	}

	require.NoError(t, validateDnsUpstreamOutbounds(parse(t, "hk_group")))
	require.NoError(t, validateDnsUpstreamOutbounds(parse(t, "direct")))
	require.ErrorContains(t, validateDnsUpstreamOutbounds(parse(t, "us_group")), `"us_group" not found`)
	require.ErrorContains(t, validateDnsUpstreamOutbounds(parse(t, "block")), "not allowed")
}
