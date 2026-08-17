/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestAliveDialerSet_GetRandExcludedConcurrent(t *testing.T) {
	networkType := newTestNetworkType()
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}

	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		networkType,
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		[]*Annotation{{}, {}, {}},
		func(bool) {},
		true,
	)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(set)
	}
	t.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})

	excluded := dialers[0]
	errCh := make(chan error, 32)
	var wg sync.WaitGroup

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				selected := set.GetRandExcluded(excluded)
				if selected == nil {
					errCh <- fmt.Errorf("GetRandExcluded returned nil")
					return
				}
				if selected == excluded {
					errCh <- fmt.Errorf("GetRandExcluded returned the excluded dialer")
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
}

func newFallbackTestSet(t *testing.T, dialers []*Dialer) *AliveDialerSet {
	t.Helper()

	annotations := make([]*Annotation, len(dialers))
	for i := range annotations {
		annotations[i] = &Annotation{}
	}
	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		newTestNetworkType(),
		0,
		consts.DialerSelectionPolicy_Fallback,
		dialers,
		annotations,
		func(bool) {},
		true,
	)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(set)
	}
	t.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})
	return set
}

func TestAliveDialerSet_GetFirstAliveFollowsGroupOrder(t *testing.T) {
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}
	set := newFallbackTestSet(t, dialers)

	if got := set.GetFirstAlive(nil); got != dialers[0] {
		t.Fatalf("first alive = %v, want dialer-1", got)
	}

	set.NotifyLatencyChange(dialers[0], false)
	if got := set.GetFirstAlive(nil); got != dialers[1] {
		t.Fatalf("first alive after dialer-1 died = %v, want dialer-2", got)
	}

	set.NotifyLatencyChange(dialers[0], true)
	if got := set.GetFirstAlive(nil); got != dialers[0] {
		t.Fatalf("first alive after dialer-1 recovered = %v, want dialer-1", got)
	}
}

// Removal swaps the dead entry with the tail of aliveEntries, so the slice order
// stops matching the group order. The fallback candidate must still be the
// earliest declared dialer.
func TestAliveDialerSet_GetFirstAliveAfterSwapRemoval(t *testing.T) {
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
		newNamedTestDialer(t, "dialer-4"),
	}
	set := newFallbackTestSet(t, dialers)

	set.NotifyLatencyChange(dialers[0], false)
	set.NotifyLatencyChange(dialers[1], false)
	if got := set.GetFirstAlive(nil); got != dialers[2] {
		t.Fatalf("first alive = %v, want dialer-3", got)
	}

	set.NotifyLatencyChange(dialers[1], true)
	if got := set.GetFirstAlive(nil); got != dialers[1] {
		t.Fatalf("first alive after dialer-2 recovered = %v, want dialer-2", got)
	}
}

func TestAliveDialerSet_GetFirstAliveExcluded(t *testing.T) {
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
		newNamedTestDialer(t, "dialer-3"),
	}
	set := newFallbackTestSet(t, dialers)

	if got := set.GetFirstAlive(dialers[0]); got != dialers[1] {
		t.Fatalf("first alive excluding dialer-1 = %v, want dialer-2", got)
	}
	if got := set.GetFirstAlive(dialers[1]); got != dialers[0] {
		t.Fatalf("first alive excluding dialer-2 = %v, want dialer-1", got)
	}

	set.NotifyLatencyChange(dialers[1], false)
	set.NotifyLatencyChange(dialers[2], false)
	if got := set.GetFirstAlive(dialers[0]); got != nil {
		t.Fatalf("first alive excluding the only alive dialer = %v, want nil", got)
	}
}

func TestAliveDialerSet_SetSelectionPolicyToFallback(t *testing.T) {
	dialers := []*Dialer{
		newNamedTestDialer(t, "dialer-1"),
		newNamedTestDialer(t, "dialer-2"),
	}
	annotations := []*Annotation{{}, {}}
	set := NewAliveDialerSet(
		dialers[0].Log,
		"test-group",
		newTestNetworkType(),
		0,
		consts.DialerSelectionPolicy_Random,
		dialers,
		annotations,
		func(bool) {},
		true,
	)
	for _, d := range dialers {
		d.RegisterAliveDialerSet(set)
	}
	t.Cleanup(func() {
		for _, d := range dialers {
			d.UnregisterAliveDialerSet(set)
		}
	})

	if got := set.GetFirstAlive(nil); got != nil {
		t.Fatalf("random policy should not track a fallback candidate, got %v", got)
	}

	set.SetSelectionPolicy(consts.DialerSelectionPolicy_Fallback)
	if got := set.GetFirstAlive(nil); got != dialers[0] {
		t.Fatalf("first alive after switching to fallback = %v, want dialer-1", got)
	}
}
