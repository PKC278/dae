/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

const sharedMatcherConfig = `
global {}
routing { fallback: direct }
dns {
  upstream {
    remotedns: 'udp://1.1.1.1:53'
    localdns: 'udp://127.0.0.1:53'
  }
  routing {
    request {
      qname(rule-set:proxied) -> remotedns
      qname(suffix: intranet.example) -> localdns
      fallback: asis
    }
  }
}
`

func newSharedMatcherOption(t *testing.T, dir string) *NewOption {
	t.Helper()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	return &NewOption{
		Logger:          log,
		LocationFinder:  assets.NewLocationFinder([]string{dir}),
		RuleProviders:   map[string]string{"proxied": "https://example.invalid/proxied"},
		RuleProviderDir: dir,
	}
}

// A reused request matcher must route exactly like a freshly compiled one;
// ControlPlane shares daedns's matcher with Dns whenever no rule provider was
// downloaded between the two builds.
func TestSharedRequestMatcherRoutesIdentically(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proxied.list"),
		[]byte("+.proxied.example\nfull:exact.example\n"), 0644))

	sections, err := config_parser.Parse(sharedMatcherConfig)
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)

	built, err := New(&conf.Dns, newSharedMatcherOption(t, dir))
	require.NoError(t, err)
	require.NotNil(t, built.reqMatcher)

	opt := newSharedMatcherOption(t, dir)
	opt.RequestMatcher = built.reqMatcher
	shared, err := New(&conf.Dns, opt)
	require.NoError(t, err)
	require.Same(t, built.reqMatcher, shared.reqMatcher, "matcher should be reused, not rebuilt")

	for _, qname := range []string{
		"sub.proxied.example",
		"proxied.example",
		"exact.example",
		"notexact.example",
		"host.intranet.example",
		"unrelated.example",
	} {
		wantIdx, wantErr := built.reqMatcher.Match(qname, 1)
		gotIdx, gotErr := shared.reqMatcher.Match(qname, 1)
		require.Equal(t, wantErr, gotErr, "qname %q", qname)
		require.Equal(t, wantIdx, gotIdx, "qname %q", qname)
	}
}

// Sharing a matcher must not bypass upstream validation, which is what
// guarantees the two upstream tag -> index maps agree.
func TestSharedRequestMatcherStillValidatesUpstreams(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "proxied.list"), []byte("+.proxied.example\n"), 0644))

	sections, err := config_parser.Parse(sharedMatcherConfig)
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)

	built, err := New(&conf.Dns, newSharedMatcherOption(t, dir))
	require.NoError(t, err)

	untagged := conf.Dns
	untagged.Upstream = []config.KeyableString{"udp://1.1.1.1:53"}
	opt := newSharedMatcherOption(t, dir)
	opt.RequestMatcher = built.reqMatcher
	_, err = New(&untagged, opt)
	require.ErrorIs(t, err, ErrBadUpstreamFormat)
}
