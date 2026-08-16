/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"github.com/daeuniverse/outbound/dialer"

	// outbound's dialer/v2ray registers its own "vless" handler. Importing it
	// here makes Go initialise it before this package, so the replacement below
	// is ordered by an import edge rather than by where the two packages happen
	// to appear in someone else's import list.
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
)

// dae implements VLESS on top of mihomo rather than using the one shipped by
// the outbound module, so the protocol tracks upstream by bumping a dependency
// instead of by porting code.
func init() {
	dialer.FromLinkRegister("vless", NewVless)
}
