/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

// ChainGroupScheme marks a chain hop that resolves to a dialer group instead of
// a fixed server.
const ChainGroupScheme = "group"

// maxChainDepth bounds how many group hops a single connection may traverse.
// The configuration graph is checked for cycles before any dial, so reaching
// this bound means a chain resolved into a loop anyway; failing the dial is
// preferable to recursing until the stack is exhausted.
const maxChainDepth = 8

// ChainDialFunc routes one connection through a group's current selection.
type ChainDialFunc func(ctx context.Context, network, addr string) (netproxy.Conn, error)

// ChainGroupRegistry resolves the group named by a chain hop. Node dialers are
// built before any group exists, so a chained node holds the group's name and
// looks the group up at dial time instead of capturing it at construction.
type ChainGroupRegistry struct {
	mu     sync.RWMutex
	groups map[string]ChainDialFunc
}

func NewChainGroupRegistry() *ChainGroupRegistry {
	return &ChainGroupRegistry{groups: make(map[string]ChainDialFunc)}
}

func (r *ChainGroupRegistry) Register(name string, dial ChainDialFunc) {
	if r == nil || dial == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = make(map[string]ChainDialFunc)
	}
	r.groups[name] = dial
}

// Has reports whether name resolves to a registered group.
func (r *ChainGroupRegistry) Has(name string) bool {
	_, ok := r.lookup(name)
	return ok
}

func (r *ChainGroupRegistry) lookup(name string) (ChainDialFunc, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	dial, ok := r.groups[name]
	return dial, ok
}

type chainDepthKey struct{}

// chainGroupDialer is the base dialer of a chained node: every connection to
// that node's own server is carried by whichever dialer the named group
// currently selects.
type chainGroupDialer struct {
	registry *ChainGroupRegistry
	group    string
}

func newChainGroupDialer(registry *ChainGroupRegistry, group string) netproxy.Dialer {
	return &chainGroupDialer{registry: registry, group: group}
}

func (d *chainGroupDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	depth, _ := ctx.Value(chainDepthKey{}).(int)
	if depth >= maxChainDepth {
		return nil, fmt.Errorf("chain proxy through group %q exceeded the maximum depth of %v", d.group, maxChainDepth)
	}
	dial, ok := d.registry.lookup(d.group)
	if !ok {
		return nil, fmt.Errorf("chain proxy references group %q, which does not exist", d.group)
	}
	return dial(context.WithValue(ctx, chainDepthKey{}, depth+1), network, addr)
}
