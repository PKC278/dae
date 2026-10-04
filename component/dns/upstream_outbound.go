/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

const upstreamAnnotationOutbound = "outbound"

// UpstreamDeclaration is one parsed dns.upstream entry.
type UpstreamDeclaration struct {
	Tag      string
	Link     string
	Outbound string
}

// ParseUpstreamDeclaration splits `tag: 'link' [outbound: group]` into its
// parts. The outbound name is only checked for presence here; whether the
// group exists depends on the group section, see ValidateUpstreamOutbounds.
func ParseUpstreamDeclaration(raw config.KeyableString) (*UpstreamDeclaration, error) {
	tag, afterTag := common.GetTagFromLinkLikePlaintext(string(raw))
	if tag == "" {
		return nil, fmt.Errorf("%w: '%v' has no tag", ErrBadUpstreamFormat, raw)
	}
	link, annotation, err := config.SplitKeyableAnnotation(afterTag)
	if err != nil {
		return nil, fmt.Errorf("%w: upstream %v: %w", ErrBadUpstreamFormat, strconv.Quote(tag), err)
	}
	decl := &UpstreamDeclaration{Tag: tag, Link: link}
	for _, a := range annotation {
		switch a.Key {
		case upstreamAnnotationOutbound:
			if decl.Outbound != "" {
				return nil, fmt.Errorf("%w: upstream %v: duplicated annotation %v", ErrBadUpstreamFormat, strconv.Quote(tag), strconv.Quote(a.Key))
			}
			decl.Outbound = a.Val
		default:
			return nil, fmt.Errorf("%w: upstream %v: unknown annotation %v", ErrBadUpstreamFormat, strconv.Quote(tag), strconv.Quote(a.Key))
		}
	}
	return decl, nil
}

// ValidateUpstreamOutbounds checks that every `outbound` annotation in
// dns.upstream names a defined group. exists reports whether a group name is
// defined. block is refused because refusing a query is expressed by `reject`
// in dns.routing.request, not by dialing a black hole.
func ValidateUpstreamOutbounds(dnsCfg *config.Dns, exists func(name string) bool) error {
	if dnsCfg == nil {
		return nil
	}
	for _, raw := range dnsCfg.Upstream {
		decl, err := ParseUpstreamDeclaration(raw)
		if err != nil {
			return err
		}
		if decl.Outbound == "" {
			continue
		}
		if decl.Outbound == consts.OutboundBlock.String() {
			return fmt.Errorf("dns upstream %v: outbound %v is not allowed; use reject in dns.routing.request instead", strconv.Quote(decl.Tag), strconv.Quote(decl.Outbound))
		}
		if !exists(decl.Outbound) {
			return fmt.Errorf("dns upstream %v: outbound (group) %v not found; please define it in section \"group\"", strconv.Quote(decl.Tag), strconv.Quote(decl.Outbound))
		}
	}
	return nil
}
