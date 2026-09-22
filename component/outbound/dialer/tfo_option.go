/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strconv"
	"strings"

	outboundcommon "github.com/daeuniverse/outbound/common"
	outboundurl "github.com/daeuniverse/outbound/common/url"
)

func parseNodeTFO(link string) (bool, error) {
	_, link = outboundcommon.GetTagFromLinkLikePlaintext(link)
	firstHop, _, _ := strings.Cut(link, "->")
	firstHop = strings.TrimSpace(firstHop)
	if firstHop == "" {
		return false, nil
	}
	u, err := outboundurl.Parse(firstHop)
	if err != nil {
		return false, err
	}
	values, ok := u.Query()["tfo"]
	if !ok {
		return false, nil
	}
	if len(values) == 0 || values[len(values)-1] == "" {
		return true, nil
	}
	enabled, err := strconv.ParseBool(values[len(values)-1])
	if err != nil {
		return false, fmt.Errorf("invalid tfo value %q", values[len(values)-1])
	}
	return enabled, nil
}
