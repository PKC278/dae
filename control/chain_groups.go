/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"sort"
	"strings"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// chainGroupEdge records that one group reaches another because a node it
// contains is chained through that other group.
type chainGroupEdge struct {
	target string
	node   string
}

// validateChainGroups rejects the chain configurations a node cannot survive:
// a group that does not exist, and a chain that loops back into a group
// carrying it. A loop would otherwise only surface as a dial that recurses
// until it hits the depth bound, and a missing group as a node that silently
// never connects.
func validateChainGroups(outbounds []*outbound.DialerGroup, allDialers []*dialer.Dialer) error {
	known := make(map[string]struct{}, len(outbounds))
	for _, group := range outbounds {
		known[group.Name] = struct{}{}
	}

	for _, d := range allDialers {
		property := d.Property()
		if property == nil || property.ChainGroup == "" {
			continue
		}
		if _, ok := known[property.ChainGroup]; !ok {
			return fmt.Errorf("node %q is chained through group %q, which is not defined", property.Name, property.ChainGroup)
		}
	}

	edges := make(map[string][]chainGroupEdge)
	for _, group := range outbounds {
		for _, d := range group.Dialers {
			property := d.Property()
			if property == nil || property.ChainGroup == "" {
				continue
			}
			edges[group.Name] = append(edges[group.Name], chainGroupEdge{
				target: property.ChainGroup,
				node:   property.Name,
			})
		}
	}
	return validateChainGroupGraph(edges)
}

// validateChainGroupGraph reports the first chain loop it finds. Group names
// are visited in a stable order so the same configuration always names the
// same loop.
func validateChainGroupGraph(edges map[string][]chainGroupEdge) error {
	const (
		_ = iota // unvisited
		onStack
		done
	)
	state := make(map[string]int, len(edges))
	var path []string
	var via []string

	var visit func(group string) error
	visit = func(group string) error {
		switch state[group] {
		case done:
			return nil
		case onStack:
			return fmt.Errorf("chain proxy loops back into a group that carries it: %v", describeChainLoop(path, via, group))
		}
		state[group] = onStack
		path = append(path, group)
		for _, edge := range sortedEdges(edges[group]) {
			via = append(via, edge.node)
			if err := visit(edge.target); err != nil {
				return err
			}
			via = via[:len(via)-1]
		}
		path = path[:len(path)-1]
		state[group] = done
		return nil
	}

	for _, group := range sortedKeys(edges) {
		if err := visit(group); err != nil {
			return err
		}
	}
	return nil
}

// describeChainLoop renders the closed walk that ends back at group, naming the
// node that creates each hop so the loop points at something editable.
func describeChainLoop(path []string, via []string, group string) string {
	start := 0
	for i, name := range path {
		if name == group {
			start = i
			break
		}
	}
	var b strings.Builder
	b.WriteString(path[start])
	for i := start; i < len(path); i++ {
		next := group
		if i+1 < len(path) {
			next = path[i+1]
		}
		fmt.Fprintf(&b, " -> %v (through node %q)", next, via[i])
	}
	return b.String()
}

func sortedEdges(edges []chainGroupEdge) []chainGroupEdge {
	sorted := append([]chainGroupEdge(nil), edges...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].target != sorted[j].target {
			return sorted[i].target < sorted[j].target
		}
		return sorted[i].node < sorted[j].node
	})
	return sorted
}

func sortedKeys(edges map[string][]chainGroupEdge) []string {
	keys := make([]string, 0, len(edges))
	for key := range edges {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
