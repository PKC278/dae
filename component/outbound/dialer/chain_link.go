/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"net/url"
	"strings"

	outboundcommon "github.com/daeuniverse/outbound/common"
)

const chainGroupPrefix = ChainGroupScheme + "://"

// splitChainGroupHop separates a "group://<name>" hop from a node link. The
// remaining link is what the protocol parsers see; the group name is resolved
// at dial time.
//
// Chain links layer left to right: "A -> B" reaches A through B, so the group
// hop is the rightmost element, the one that carries every hop before it.
func splitChainGroupHop(link string) (rest string, group string, err error) {
	tag, linklike := outboundcommon.GetTagFromLinkLikePlaintext(link)
	hops := strings.Split(linklike, "->")
	groupAt := -1
	for i, hop := range hops {
		if !strings.HasPrefix(strings.TrimSpace(hop), chainGroupPrefix) {
			continue
		}
		if groupAt >= 0 {
			return "", "", fmt.Errorf("a node link may chain through at most one group")
		}
		groupAt = i
	}
	if groupAt < 0 {
		return link, "", nil
	}
	group, err = parseChainGroupName(hops[groupAt])
	if err != nil {
		return "", "", err
	}
	if len(hops) == 1 {
		return "", "", fmt.Errorf("%v%v has no node in front of it; write 'node_link -> %v%v'",
			chainGroupPrefix, group, chainGroupPrefix, group)
	}
	if groupAt != len(hops)-1 {
		return "", "", fmt.Errorf("%v%v must be the last hop of the chain, because a group carries the hops written before it",
			chainGroupPrefix, group)
	}
	rest = strings.TrimSpace(strings.Join(hops[:groupAt], "->"))
	if tag != "" {
		rest = tag + ":" + rest
	}
	return rest, group, nil
}

func parseChainGroupName(hop string) (string, error) {
	raw := strings.TrimSpace(hop)
	name, err := url.PathUnescape(strings.Trim(strings.TrimPrefix(raw, chainGroupPrefix), "/"))
	if err != nil {
		return "", fmt.Errorf("invalid group name in %q: %w", raw, err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%q does not name a group", raw)
	}
	return name, nil
}

// appendChainGroupHop restores the hop that splitChainGroupHop removed, so the
// stored link still rebuilds the whole chain when the dialer is cloned.
func appendChainGroupHop(link string, group string) string {
	if group == "" {
		return link
	}
	return link + " -> " + chainGroupPrefix + url.PathEscape(group)
}
