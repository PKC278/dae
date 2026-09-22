/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import "testing"

func TestSplitChainGroupHop(t *testing.T) {
	for _, c := range []struct {
		name      string
		link      string
		wantRest  string
		wantGroup string
	}{
		{
			name:     "plain link is untouched",
			link:     "vless://uuid@example.com:443#exit",
			wantRest: "vless://uuid@example.com:443#exit",
		},
		{
			name:     "node chain without a group is untouched",
			link:     "vless://uuid@example.com:443 -> socks5://127.0.0.1:1080",
			wantRest: "vless://uuid@example.com:443 -> socks5://127.0.0.1:1080",
		},
		{
			name:      "group hop is removed from the link",
			link:      "vless://uuid@example.com:443#exit -> group://front",
			wantRest:  "vless://uuid@example.com:443#exit",
			wantGroup: "front",
		},
		{
			name:      "tag survives the split",
			link:      "landing: vless://uuid@example.com:443 -> group://front",
			wantRest:  "landing:vless://uuid@example.com:443",
			wantGroup: "front",
		},
		{
			name:      "group name is unescaped",
			link:      "vless://uuid@example.com:443 -> group://my%20front",
			wantRest:  "vless://uuid@example.com:443",
			wantGroup: "my front",
		},
		{
			name:      "node chain keeps its own hops",
			link:      "vless://uuid@example.com:443 -> socks5://127.0.0.1:1080 -> group://front",
			wantRest:  "vless://uuid@example.com:443 -> socks5://127.0.0.1:1080",
			wantGroup: "front",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			rest, group, err := splitChainGroupHop(c.link)
			if err != nil {
				t.Fatalf("splitChainGroupHop(%q) error = %v", c.link, err)
			}
			if rest != c.wantRest || group != c.wantGroup {
				t.Fatalf("splitChainGroupHop(%q) = (%q, %q), want (%q, %q)", c.link, rest, group, c.wantRest, c.wantGroup)
			}
		})
	}
}

func TestSplitChainGroupHopRejectsUnusableChains(t *testing.T) {
	for _, c := range []struct {
		name string
		link string
	}{
		{name: "group without a node", link: "group://front"},
		{name: "group before the node it carries", link: "group://front -> vless://uuid@example.com:443"},
		{name: "two groups in one chain", link: "vless://uuid@example.com:443 -> group://a -> group://b"},
		{name: "group without a name", link: "vless://uuid@example.com:443 -> group://"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := splitChainGroupHop(c.link); err == nil {
				t.Fatalf("splitChainGroupHop(%q) error = nil, want error", c.link)
			}
		})
	}
}

func TestAppendChainGroupHopRoundTrips(t *testing.T) {
	const link = "vless://uuid@example.com:443#exit"
	for _, group := range []string{"front", "my front"} {
		rest, got, err := splitChainGroupHop(appendChainGroupHop(link, group))
		if err != nil {
			t.Fatalf("splitChainGroupHop() error = %v", err)
		}
		if rest != link || got != group {
			t.Fatalf("round trip of group %q = (%q, %q), want (%q, %q)", group, rest, got, link, group)
		}
	}
	if got := appendChainGroupHop(link, ""); got != link {
		t.Fatalf("appendChainGroupHop(link, \"\") = %q, want %q", got, link)
	}
}
