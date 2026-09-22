/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// A probe triggered by a real connection failure must not spend the full
// periodic budget: it runs once with the shorter resuscitation deadline, while
// the periodic check keeps both attempts and the long deadline.
func TestDialerCheck_ResuscitationProbeIsShortAndSingleAttempt(t *testing.T) {
	d := newNamedTestDialer(t, "probe-budget")
	networkType := newTestNetworkType()

	var budgets []time.Duration
	opt := &CheckOption{
		networkType: networkType,
		CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("probe context carries no deadline")
				return false, errors.New("no deadline")
			}
			budgets = append(budgets, time.Until(deadline).Round(time.Second))
			return false, errors.New("simulated probe failure")
		},
	}

	if _, err := d.check(opt, true, nil); err == nil {
		t.Fatal("expected the probe to fail")
	}
	if len(budgets) != 1 {
		t.Fatalf("resuscitation attempts = %d, want 1", len(budgets))
	}
	if budgets[0] != ResuscitationTimeout {
		t.Fatalf("resuscitation budget = %v, want %v", budgets[0], ResuscitationTimeout)
	}

	budgets = nil
	if _, err := d.check(opt, false, nil); err == nil {
		t.Fatal("expected the probe to fail")
	}
	if len(budgets) != 2 {
		t.Fatalf("periodic attempts = %d, want 2", len(budgets))
	}
	for i, budget := range budgets {
		if budget != Timeout {
			t.Fatalf("periodic budget[%d] = %v, want %v", i, budget, Timeout)
		}
	}
}

func TestDialer_ReportDialFailureNeedsAClusterOfFailures(t *testing.T) {
	d := newNamedTestDialer(t, "dial-failure-window")

	// One destination failing repeatedly, but spread out: each failure lands in
	// a fresh window and never earns a probe.
	for range 10 {
		d.ReportDialFailure(consts.L4ProtoStr_TCP)
		d.dialFailures[0].mu.Lock()
		d.dialFailures[0].first = time.Now().Add(-2 * DialFailureWindow)
		d.dialFailures[0].mu.Unlock()
	}
	if got := len(d.checkTcpCh); got != 0 {
		t.Fatalf("probes after sparse failures = %d, want 0", got)
	}

	// A node that is actually down fails everything at once and fills the window.
	for range DialFailureThreshold {
		d.ReportDialFailure(consts.L4ProtoStr_TCP)
	}
	if got := len(d.checkTcpCh); got != 1 {
		t.Fatalf("probes after clustered failures = %d, want 1", got)
	}
}

func TestDialer_ReportDialFailureResetsAfterTriggering(t *testing.T) {
	d := newNamedTestDialer(t, "dial-failure-reset")

	for range DialFailureThreshold {
		d.ReportDialFailure(consts.L4ProtoStr_TCP)
	}
	d.dialFailures[0].mu.Lock()
	count := d.dialFailures[0].count
	d.dialFailures[0].mu.Unlock()
	if count != 0 {
		t.Fatalf("failure count after triggering = %d, want 0", count)
	}
}

func TestDialer_ReportDialFailureTracksProtocolsSeparately(t *testing.T) {
	d := newNamedTestDialer(t, "dial-failure-proto")

	// TCP failures must not push the UDP window towards its threshold.
	for range DialFailureThreshold {
		d.ReportDialFailure(consts.L4ProtoStr_TCP)
	}
	if got := len(d.checkDnsUdpCh); got != 0 {
		t.Fatalf("UDP probes after TCP-only failures = %d, want 0", got)
	}

	for range DialFailureThreshold {
		d.ReportDialFailure(consts.L4ProtoStr_UDP)
	}
	if got := len(d.checkDnsUdpCh); got != 1 {
		t.Fatalf("UDP probes after UDP failures = %d, want 1", got)
	}
}
