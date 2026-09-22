/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

// errChainProbe stands in for whatever the group would have dialed.
var errChainProbe = errors.New("chain probe")

func TestChainGroupDialerDelegatesToTheRegisteredGroup(t *testing.T) {
	registry := NewChainGroupRegistry()
	var gotNetwork, gotAddr string
	registry.Register("front", func(ctx context.Context, network, addr string) (netproxy.Conn, error) {
		gotNetwork, gotAddr = network, addr
		return nil, nil
	})

	d := newChainGroupDialer(registry, "front")
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:443"); err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if gotNetwork != "tcp" || gotAddr != "example.com:443" {
		t.Fatalf("group received (%q, %q), want (\"tcp\", \"example.com:443\")", gotNetwork, gotAddr)
	}
	if !registry.Has("front") || registry.Has("absent") {
		t.Fatal("Has() disagrees with what was registered")
	}
}

func TestChainGroupDialerReportsAnUnknownGroup(t *testing.T) {
	d := newChainGroupDialer(NewChainGroupRegistry(), "front")
	_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "front") {
		t.Fatalf("DialContext() error = %v, want an error naming the group", err)
	}
}

func TestChainGroupDialerStopsAnEndlessChain(t *testing.T) {
	registry := NewChainGroupRegistry()
	d := newChainGroupDialer(registry, "front")
	registry.Register("front", func(ctx context.Context, network, addr string) (netproxy.Conn, error) {
		return d.DialContext(ctx, network, addr)
	})

	_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil || !strings.Contains(err.Error(), "maximum depth") {
		t.Fatalf("DialContext() error = %v, want the depth bound to stop the chain", err)
	}
}

func TestNodeLinkEndingInAGroupIsCarriedByThatGroup(t *testing.T) {
	option := NewGlobalOption(&config.Global{}, logrus.StandardLogger())
	var dialedThrough string
	option.ChainGroups.Register("front", func(ctx context.Context, network, addr string) (netproxy.Conn, error) {
		dialedThrough = addr
		return nil, errChainProbe
	})

	d, err := NewFromLinkContext(context.Background(), option, InstanceOption{DisableCheck: true},
		"landing: socks5://127.0.0.1:1080 -> group://front", "")
	if err != nil {
		t.Fatalf("NewFromLinkContext() error = %v", err)
	}
	defer func() { _ = d.Close() }()

	property := d.Property()
	if property.Name != "landing" || property.ChainGroup != "front" {
		t.Fatalf("property = (name %q, chain group %q), want (\"landing\", \"front\")", property.Name, property.ChainGroup)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, errChainProbe) {
		t.Fatalf("DialContext() error = %v, want the group's error", err)
	}
	if dialedThrough != "127.0.0.1:1080" {
		t.Fatalf("group was asked to reach %q, want the node's own server", dialedThrough)
	}
}

func TestChainedNodeLinkRebuildsTheWholeChain(t *testing.T) {
	option := NewGlobalOption(&config.Global{}, logrus.StandardLogger())
	d, err := NewFromLinkContext(context.Background(), option, InstanceOption{DisableCheck: true},
		"landing: socks5://127.0.0.1:1080 -> group://front", "")
	if err != nil {
		t.Fatalf("NewFromLinkContext() error = %v", err)
	}
	defer func() { _ = d.Close() }()

	clone := d.CloneWithGlobalOptionContext(context.Background(), option)
	defer func() { _ = clone.Close() }()
	if clone.Property().ChainGroup != "front" {
		t.Fatalf("clone chain group = %q, want %q", clone.Property().ChainGroup, "front")
	}
}
