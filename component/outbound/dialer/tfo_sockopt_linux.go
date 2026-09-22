//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func tcpFastOpenControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting TCP_FASTOPEN_CONNECT socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}
