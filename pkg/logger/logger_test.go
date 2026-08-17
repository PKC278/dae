/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

func newTestLogger(level string) (*logrus.Logger, *bytes.Buffer) {
	log := logrus.New()
	SetLogger(log, level, true, nil)
	buf := &bytes.Buffer{}
	SetOutput(log, buf)
	return log, buf
}

func TestMilestoneVisibleAtErrorLevel(t *testing.T) {
	log, buf := newTestLogger("error")
	log.Infoln("suppressed info line")
	Milestone(log, "dae is now proxying traffic (ready in %v)", "4.2s")

	out := buf.String()
	if strings.Contains(out, "suppressed info line") {
		t.Fatalf("info line should have been filtered at error level, got: %q", out)
	}
	if !strings.Contains(out, "dae is now proxying traffic (ready in 4.2s)") {
		t.Fatalf("milestone should be emitted at error level, got: %q", out)
	}
}

func TestMilestoneEmittedOnceAtInfoLevel(t *testing.T) {
	log, buf := newTestLogger("info")
	Milestone(log, "ready")

	if got := strings.Count(buf.String(), "ready"); got != 1 {
		t.Fatalf("milestone should be emitted exactly once, got %d: %q", got, buf.String())
	}
}

func TestMilestoneNilLoggerIsNoop(t *testing.T) {
	Milestone(nil, "ready")
}

// Milestone bypasses the mutex logrus takes for its own entries, so it must not
// corrupt output when racing with ordinary logging.
func TestMilestoneConcurrentWithLogrusWrites(t *testing.T) {
	log, buf := newTestLogger("error")

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Milestone(log, "milestone-line")
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Errorln("error-line")
		}()
	}
	wg.Wait()

	if got := strings.Count(buf.String(), "milestone-line"); got != 8 {
		t.Fatalf("expected 8 milestone lines, got %d: %q", got, buf.String())
	}
}
