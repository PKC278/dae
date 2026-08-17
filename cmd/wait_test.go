/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/stretchr/testify/require"
)

func TestWaitStartupCompletionReturnsReadyMessage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.progress")
	require.NoError(t, writeSignalProgressFile(path, consts.ReloadDone, "dae is now proxying traffic (ready in 4.2s)"))

	code, content, err := waitStartupCompletion(path, time.Millisecond, time.Second)
	require.NoError(t, err)
	require.Equal(t, byte(consts.ReloadDone), code)
	require.Contains(t, content, "now proxying traffic")
}

// A supervisor can hand back control before dae has written the file at all;
// waiting must ride that out rather than erroring.
func TestWaitStartupCompletionToleratesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.progress")
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = writeSignalProgressFile(path, consts.ReloadDone, "ready")
	}()

	code, content, err := waitStartupCompletion(path, 5*time.Millisecond, 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, byte(consts.ReloadDone), code)
	require.Equal(t, "ready", content)
}

// The whole reason Run() stamps ReloadProcessing up front: without it a waiter
// would read the previous run's result and report success immediately.
func TestWaitStartupCompletionIgnoresInProgressState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.progress")
	require.NoError(t, writeSignalProgressFile(path, consts.ReloadProcessing, "Starting dae..."))

	_, _, err := waitStartupCompletion(path, 5*time.Millisecond, 80*time.Millisecond)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out")

	// Once startup finishes, the same wait resolves.
	require.NoError(t, writeSignalProgressFile(path, consts.ReloadDone, "ready in 4.2s"))
	code, content, err := waitStartupCompletion(path, 5*time.Millisecond, time.Second)
	require.NoError(t, err)
	require.Equal(t, byte(consts.ReloadDone), code)
	require.Equal(t, "ready in 4.2s", content)
}

func TestWaitStartupCompletionReportsFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.progress")
	require.NoError(t, writeSignalProgressFile(path, consts.ReloadError, "dae failed to start; see the log for details"))

	code, content, err := waitStartupCompletion(path, time.Millisecond, time.Second)
	require.NoError(t, err)
	require.Equal(t, byte(consts.ReloadError), code)
	require.Contains(t, content, "failed to start")
}
