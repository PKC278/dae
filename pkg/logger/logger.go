/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

func SetLogger(log *logrus.Logger, logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(&prefixed.TextFormatter{
		DisableTimestamp: disableTimestamp,
		FullTimestamp:    true,
		ForceFormatting:  true,
		TimestampFormat:  "2006-01-02 15:04:05",
	})
	if logFileOpt != nil {
		setLockedOutput(log, logFileOpt)
	} else {
		setLockedOutput(log, log.Out)
	}
}

// SetOutput redirects log while keeping the lock Milestone relies on. Callers
// must use it instead of logrus.Logger.SetOutput.
func SetOutput(log *logrus.Logger, w io.Writer) {
	setLockedOutput(log, w)
}

// lockedWriter guards the log output with a lock Milestone can also take.
// logrus serializes its own entries on a mutex we cannot reach, so without a
// shared lock at the writer a milestone line could interleave mid-entry.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// setLockedOutput points log at w through a lockedWriter, reusing an existing
// one so that reconfiguring a logger never nests writers.
func setLockedOutput(log *logrus.Logger, w io.Writer) {
	if lw, ok := w.(*lockedWriter); ok {
		log.SetOutput(lw)
		return
	}
	if lw, ok := log.Out.(*lockedWriter); ok {
		lw.mu.Lock()
		lw.w = w
		lw.mu.Unlock()
		return
	}
	log.SetOutput(&lockedWriter{w: w})
}

// milestoneMu keeps two concurrent milestones apart on loggers that were not
// configured through SetLogger and so have no lockedWriter.
var milestoneMu sync.Mutex

// Milestone reports a one-shot lifecycle event that must stay visible at every
// log_level. Without it an operator running `log_level: error` gets a silent
// process and no way to tell whether dae ever came up.
func Milestone(log *logrus.Logger, format string, args ...any) {
	if log == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if log.IsLevelEnabled(logrus.InfoLevel) {
		log.Infoln(msg)
		return
	}
	entry := logrus.NewEntry(log)
	entry.Level = logrus.InfoLevel
	entry.Time = time.Now()
	entry.Message = msg
	serialized, err := log.Formatter.Format(entry)
	if err != nil {
		return
	}
	milestoneMu.Lock()
	defer milestoneMu.Unlock()
	_, _ = log.Out.Write(serialized)
}
