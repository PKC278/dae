//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import "syscall"

func tcpFastOpenControl(_ syscall.RawConn) error {
	return nil
}
