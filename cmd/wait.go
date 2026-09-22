/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
)

const (
	waitPollInterval      = 200 * time.Millisecond
	defaultWaitReadyLimit = 120 * time.Second
)

// waitStartupCompletion blocks until the running dae reports that it finished
// starting. Unlike waitReloadCompletion it tolerates a missing progress file,
// because a supervisor may hand back control before dae has written one.
func waitStartupCompletion(path string, pollInterval, timeout time.Duration) (code byte, content string, err error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		code, content, err = readSignalProgressFile(path)
		switch {
		case err == nil:
			if code == consts.ReloadDone || code == consts.ReloadError {
				return code, content, nil
			}
		case !os.IsNotExist(err):
			return 0, "", err
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, "", fmt.Errorf("timed out after %v waiting for dae to become ready", timeout)
		}
		time.Sleep(pollInterval)
	}
}

var (
	waitTimeout time.Duration
	waitCmd     = &cobra.Command{
		Use:   "wait",
		Short: "To block until dae has finished starting, then report the result.",
		Run: func(cmd *cobra.Command, args []string) {
			code, content, err := waitStartupCompletion(SignalProgressFilePath, waitPollInterval, waitTimeout)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if content == "" {
				content = "OK"
			}
			fmt.Println(content)
			if code == consts.ReloadError {
				os.Exit(1)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(waitCmd)
	waitCmd.PersistentFlags().DurationVar(&waitTimeout, "timeout", defaultWaitReadyLimit,
		"How long to wait for dae to become ready. Zero waits indefinitely.")
}
