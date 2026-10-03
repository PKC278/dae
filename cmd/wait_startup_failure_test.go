/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/stretchr/testify/require"
)

func TestWaitReportsConfigurationFailureBeforeRunnerStarts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("run requires root")
	}
	if progressPath := os.Getenv("DAE_TEST_STARTUP_PROGRESS"); progressPath != "" {
		setRunSignalProgress = func(code byte, content string) error {
			return writeSignalProgressFile(progressPath, code, content)
		}
		cfgFile = filepath.Join(filepath.Dir(progressPath), "missing.dae")
		disableAuthSudo = true
		runCmd.Run(runCmd, nil)
		return
	}
	path := filepath.Join(t.TempDir(), "dae.progress")
	require.NoError(t, writeSignalProgressFile(path, consts.ReloadDone, "old startup"))
	executable, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(executable, "-test.run=^TestWaitReportsConfigurationFailureBeforeRunnerStarts$")
	child.Env = append(os.Environ(), "DAE_TEST_STARTUP_PROGRESS="+path)
	output, err := child.CombinedOutput()
	require.Error(t, err, string(output))
	code, content, err := waitStartupCompletion(path, time.Millisecond, time.Second)
	require.NoError(t, err)
	require.Equal(t, byte(consts.ReloadError), code)
	require.Contains(t, content, "missing.dae")
}
