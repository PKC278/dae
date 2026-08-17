/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/sirupsen/logrus"
)

const (
	testTcpCheckUrl = "https://connectivitycheck.gstatic.com/generate_204"
	testUdpCheckDns = "https://connectivitycheck.gstatic.com/generate_204"
)

var TestNetworkType = &dialer.NetworkType{
	L4Proto:   consts.L4ProtoStr_TCP,
	IpVersion: consts.IpVersionStr_4,
	IsDns:     false,
}

var TestDnsUdp4NetworkType = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	IsDns:           true,
	UdpHealthDomain: dialer.UdpHealthDomainDns,
}

var TestDataUdp4NetworkType = &dialer.NetworkType{
	L4Proto:         consts.L4ProtoStr_UDP,
	IpVersion:       consts.IpVersionStr_4,
	UdpHealthDomain: dialer.UdpHealthDomainData,
}

var log = logrus.New()

func init() {
	logger.SetLogger(log, "trace", false, nil)
}

func newDirectDialer(option *dialer.GlobalOption, fullcone bool) *dialer.Dialer {
	_d, p := dialer.NewDirectDialer(option, true)
	d := dialer.NewDialer(_d, option, dialer.InstanceOption{DisableCheck: false}, p)
	return d
}

func newEmptyAnnotations(n int) []*dialer.Annotation {
	annotations := make([]*dialer.Annotation, n)
	for i := range annotations {
		annotations[i] = &dialer.Annotation{}
	}
	return annotations
}

type noopTestDialer struct{}

func (noopTestDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("not implemented")
}

func newNoopDialer(option *dialer.GlobalOption) *dialer.Dialer {
	return dialer.NewDialer(
		noopTestDialer{},
		option,
		dialer.InstanceOption{DisableCheck: true},
		&dialer.Property{},
	)
}

func dialerSignalLen(t *testing.T, d *dialer.Dialer, field string) int {
	t.Helper()

	v := reflect.ValueOf(d).Elem().FieldByName(field)
	if !v.IsValid() {
		t.Fatalf("field %q not found", field)
	}
	if v.Kind() != reflect.Chan {
		t.Fatalf("field %q kind = %v, want chan", field, v.Kind())
	}
	return v.Len()
}

func newTestGroupForSelection(policy DialerSelectionPolicy) (*DialerGroup, []*dialer.Dialer) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	group := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)), policy, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	return group, dialers
}

func markDialersDead(set *dialer.AliveDialerSet, dialers ...*dialer.Dialer) {
	for _, d := range dialers {
		set.NotifyLatencyChange(d, false)
	}
}

func TestDialerGroup_Select_Fixed(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, true),
		newDirectDialer(option, false),
	}
	fixedIndex := 1
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: fixedIndex,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	for range 10 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}

	fixedIndex = 0
	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: fixedIndex,
	})
	for range 10 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[fixedIndex] {
			t.Fail()
		}
	}
}

func TestDialerGroup_Select_MinLastLatency(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinLastLatency,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	// Test 1000 times.
	for range 1000 {
		var minLatency time.Duration
		jMinLatency := -1
		for j, d := range dialers {
			// Simulate a latency test.
			var (
				latency time.Duration
				alive   bool
			)
			// 20% chance for timeout.
			if fastrand.Intn(5) == 0 {
				// Simulate a timeout test.
				latency = 1000 * time.Millisecond
				alive = false
			} else {
				// Simulate a normal test.
				latency = time.Duration(fastrand.Int63n(int64(1000 * time.Millisecond)))
				alive = true
			}
			d.MustGetLatencies10(TestNetworkType).AppendLatency(latency)
			if alive && (jMinLatency == -1 || latency < minLatency) {
				jMinLatency = j
				minLatency = latency
			}
			g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(d, alive)
		}
		d, _, err := g.Select(TestNetworkType, true)
		if jMinLatency == -1 {
			if !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("expected ErrNoAliveDialer, got: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if d != dialers[jMinLatency] {
			// Get index of d.
			indexD := -1
			for j := range dialers {
				if d == dialers[j] {
					indexD = j
					break
				}
			}
			t.Errorf("dialers[%v] expected, but dialers[%v] selected", jMinLatency, indexD)
		}
	}
}

func TestDialerGroup_Select_Random(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	count := make([]int, len(dialers))
	for range 100 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
}

func TestDialerGroup_Resuscitate_UDPTriggersDnsUdpAndTcp(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newNoopDialer(option)
	g := &DialerGroup{
		Dialers: []*dialer.Dialer{d},
	}

	g.resuscitate(TestDataUdp4NetworkType)

	if got := dialerSignalLen(t, d, "checkDnsUdpCh"); got != 1 {
		t.Fatalf("DNS-UDP resuscitation signals = %d, want 1", got)
	}
	if got := dialerSignalLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("TCP resuscitation signals = %d, want 1", got)
	}
}

func TestDialerGroup_Resuscitate_TCPTriggersOnlyTcp(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	d := newNoopDialer(option)
	g := &DialerGroup{
		Dialers: []*dialer.Dialer{d},
	}

	g.resuscitate(TestNetworkType)

	if got := dialerSignalLen(t, d, "checkDnsUdpCh"); got != 0 {
		t.Fatalf("DNS-UDP resuscitation signals = %d, want 0", got)
	}
	if got := dialerSignalLen(t, d, "checkTcpCh"); got != 1 {
		t.Fatalf("TCP resuscitation signals = %d, want 1", got)
	}
}

func TestDialerGroup_SetAlive(t *testing.T) {

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	zeroTarget := 3
	g.MustGetAliveDialerSet(TestNetworkType).NotifyLatencyChange(dialers[zeroTarget], false)
	count := make([]int, len(dialers))
	for range 100 {
		d, _, err := g.Select(TestNetworkType, false)
		if err != nil {
			t.Fatal(err)
		}
		for j, dd := range dialers {
			if d == dd {
				count[j]++
				break
			}
		}
	}
	for i, c := range count {
		if c == 0 && i != zeroTarget {
			t.Fail()
		}
		t.Logf("count[%v]: %v", i, c)
	}
	if count[zeroTarget] != 0 {
		t.Fail()
	}
}

func TestDialerGroup_SetSelectionPolicy_FixedToRandomCreatesAliveState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	if got := g.MustGetAliveDialerSet(TestNetworkType); got != nil {
		t.Fatal("fixed policy should not eagerly allocate alive-state sets")
	}

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	set := g.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("random policy should allocate alive-state sets on demand")
	}
	if got := set.Len(); got != len(dialers) {
		t.Fatalf("alive dialer count = %d, want %d", got, len(dialers))
	}
}

func TestDialerGroup_SetSelectionPolicy_FixedToRandomPreservesAliveState(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	dialers[1].ReportUnavailableForced(TestNetworkType, errors.New("forced dead for policy switch"))

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	set := g.MustGetAliveDialerSet(TestNetworkType)
	if set == nil {
		t.Fatal("random policy should allocate alive-state sets")
	}
	if got := set.Len(); got != 1 {
		t.Fatalf("alive dialer count = %d, want 1", got)
	}

	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error after preserving alive state: %v", err)
	}
	if selected != dialers[0] {
		t.Fatal("expected selection to skip dialer that was already dead before policy switch")
	}
}

func TestDialerGroup_SetSelectionPolicy_RecomputesMinLatencyOrdering(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Random,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(90 * time.Millisecond)
	dialers[0].MustGetLatencies10(TestNetworkType).AppendLatency(80 * time.Millisecond)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(50 * time.Millisecond)
	dialers[1].MustGetLatencies10(TestNetworkType).AppendLatency(40 * time.Millisecond)

	set := g.MustGetAliveDialerSet(TestNetworkType)
	set.NotifyLatencyChange(dialers[0], true)
	set.NotifyLatencyChange(dialers[1], true)

	g.SetSelectionPolicy(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_MinAverage10Latencies,
	})

	selected, _, err := g.Select(TestNetworkType, true)
	if err != nil {
		t.Fatalf("Select() error after policy update: %v", err)
	}
	if selected != dialers[1] {
		t.Fatal("expected lower-average-latency dialer after policy recompute")
	}
}

func TestDialerGroup_Select_DataUdpFallsBackToDnsUdp(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	markDialersDead(g.MustGetAliveDialerSet(TestDataUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers[0])
	markDialersDead(g.MustGetAliveDialerSet(TestNetworkType), dialers...)

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("expected DNS UDP fallback to select dialers[1], got another dialer")
	}
}

func TestDialerGroup_Select_DataUdpFallsBackToTcp(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy: consts.DialerSelectionPolicy_Random,
	})

	markDialersDead(g.MustGetAliveDialerSet(TestDataUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestDnsUdp4NetworkType), dialers...)
	markDialersDead(g.MustGetAliveDialerSet(TestNetworkType), dialers[1])

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[0] {
		t.Fatalf("expected TCP fallback to select dialers[0], got another dialer")
	}
}

func TestDialerGroup_Select_DataUdpFixedPolicyDoesNotFallback(t *testing.T) {
	g, dialers := newTestGroupForSelection(DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 1,
	})

	d, _, err := g.Select(TestDataUdp4NetworkType, true)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	if d != dialers[1] {
		t.Fatalf("expected fixed policy to keep selecting dialers[1], got another dialer")
	}
}

func TestDialerGroup_Select_Fallback(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Fallback,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})
	set := g.MustGetAliveDialerSet(TestNetworkType)

	assertSelected := func(want *dialer.Dialer, msg string) {
		t.Helper()
		for range 10 {
			d, _, err := g.Select(TestNetworkType, false)
			if err != nil {
				t.Fatalf("%v: %v", msg, err)
			}
			if d != want {
				t.Fatalf("%v: selected an unexpected dialer", msg)
			}
		}
	}

	assertSelected(dialers[0], "all alive")

	markDialersDead(set, dialers[0])
	assertSelected(dialers[1], "first dialer dead")

	markDialersDead(set, dialers[1])
	assertSelected(dialers[2], "first two dialers dead")

	set.NotifyLatencyChange(dialers[0], true)
	assertSelected(dialers[0], "first dialer recovered")
}

func TestDialerGroup_Select_FallbackExcludesFailedDialer(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Fallback,
		}, func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	d, _, err := g.SelectWithExclusion(TestNetworkType, false, dialers[0])
	if err != nil {
		t.Fatal(err)
	}
	if d != dialers[1] {
		t.Fatal("retry after a failed dial should pick the next dialer in group order")
	}
}

func newTestGroupWithAllDialersDead(t *testing.T, policy consts.DialerSelectionPolicy, count int) (*DialerGroup, []*dialer.Dialer) {
	t.Helper()

	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
	}
	dialers := make([]*dialer.Dialer, 0, count)
	for range count {
		dialers = append(dialers, newDirectDialer(option, false))
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{Policy: policy},
		func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	for _, d := range dialers {
		d.ReportUnavailableForced(TestNetworkType, errors.New("forced dead"))
		d.ReportUnavailableForced(&dialer.NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
		}, errors.New("forced dead"))
	}
	return g, dialers
}

// A dead group still hands back the preferred node rather than refusing: the
// node may have recovered since the last health check, and refusing guarantees
// a failed connection.
func TestDialerGroup_Select_FallbackLastResort(t *testing.T) {
	g, dialers := newTestGroupWithAllDialersDead(t, consts.DialerSelectionPolicy_Fallback, 3)

	d, _, err := g.Select(TestNetworkType, false)
	if err != nil {
		t.Fatalf("dead fallback group should still return a dialer, got err = %v", err)
	}
	if d != dialers[0] {
		t.Fatal("last resort should be the first dialer in group order")
	}
}

func TestDialerGroup_Select_FallbackLastResortSkipsExcluded(t *testing.T) {
	g, dialers := newTestGroupWithAllDialersDead(t, consts.DialerSelectionPolicy_Fallback, 3)

	d, _, err := g.SelectWithExclusion(TestNetworkType, false, dialers[0])
	if err != nil {
		t.Fatalf("dead fallback group should still return a dialer, got err = %v", err)
	}
	if d != dialers[1] {
		t.Fatal("last resort should skip the dialer that just failed")
	}

	// Nothing left to prefer once every candidate has been excluded.
	single, _ := newTestGroupWithAllDialersDead(t, consts.DialerSelectionPolicy_Fallback, 1)
	only := single.Dialers[0]
	d, _, err = single.SelectWithExclusion(TestNetworkType, false, only)
	if err != nil || d != only {
		t.Fatalf("single-dialer group should return its only dialer, got %v err = %v", d, err)
	}
}

// Other policies keep refusing: they have no declared preference order, so
// there is no meaningful node to fall back to.
func TestDialerGroup_Select_NoLastResortForUnorderedPolicies(t *testing.T) {
	for _, policy := range []consts.DialerSelectionPolicy{
		consts.DialerSelectionPolicy_Random,
		consts.DialerSelectionPolicy_MinLastLatency,
	} {
		t.Run(string(policy), func(t *testing.T) {
			g, _ := newTestGroupWithAllDialersDead(t, policy, 2)
			if _, _, err := g.Select(TestNetworkType, false); !errors.Is(err, ErrNoAliveDialer) {
				t.Fatalf("err = %v, want ErrNoAliveDialer", err)
			}
		})
	}
}

// A single-dialer group has nothing to choose between, so it keeps the
// pre-existing behaviour of returning that dialer under any policy.
func TestDialerGroup_Select_SingleDialerLastResortAnyPolicy(t *testing.T) {
	g, dialers := newTestGroupWithAllDialersDead(t, consts.DialerSelectionPolicy_Random, 1)

	d, _, err := g.Select(TestNetworkType, false)
	if err != nil {
		t.Fatalf("single-dialer group should not refuse, got err = %v", err)
	}
	if d != dialers[0] {
		t.Fatal("single-dialer group returned an unexpected dialer")
	}
}

// A deliberately lazy check schedule must not also delay recovery detection: the
// resuscitation rate limit only guards the worker pool, so it is capped
// independently of check_interval.
func TestDialerGroup_ResuscitateIntervalIsCapped(t *testing.T) {
	for _, tc := range []struct {
		name          string
		checkInterval time.Duration
		wantProbe     time.Duration
		wantLog       time.Duration
	}{
		{
			name:          "lazy schedule is capped",
			checkInterval: 30 * time.Minute,
			wantProbe:     maxResuscitateInterval,
			wantLog:       maxNoAliveLogInterval,
		},
		{
			name:          "eager schedule is left alone",
			checkInterval: 3 * time.Second,
			wantProbe:     3 * time.Second,
			wantLog:       15 * time.Second,
		},
		{
			name:          "log floor still applies",
			checkInterval: time.Second,
			wantProbe:     time.Second,
			wantLog:       10 * time.Second,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &DialerGroup{cachedMinCheckInterval: tc.checkInterval}
			if got := g.resuscitateInterval(); got != tc.wantProbe {
				t.Fatalf("resuscitateInterval() = %v, want %v", got, tc.wantProbe)
			}
			if got := g.noAliveLogInterval(); got != tc.wantLog {
				t.Fatalf("noAliveLogInterval() = %v, want %v", got, tc.wantLog)
			}
		})
	}
}

// The cap has to hold for a real group too, not just a hand-built struct.
func TestDialerGroup_ResuscitateIntervalCappedForRealGroup(t *testing.T) {
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     30 * time.Minute,
		CheckTolerance:    0,
	}
	dialers := []*dialer.Dialer{
		newDirectDialer(option, false),
		newDirectDialer(option, false),
	}
	g := NewDialerGroup(option, "test-group", dialers, newEmptyAnnotations(len(dialers)),
		DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fallback},
		func(alive bool, networkType *dialer.NetworkType, isInit bool) {})

	if got := g.MinCheckInterval(); got != 30*time.Minute {
		t.Fatalf("MinCheckInterval() = %v, want 30m", got)
	}
	if got := g.resuscitateInterval(); got != maxResuscitateInterval {
		t.Fatalf("resuscitateInterval() = %v, want %v", got, maxResuscitateInterval)
	}

	// A first probe goes through, an immediate second one is still rate-limited.
	if !g.Resuscitate(TestNetworkType) {
		t.Fatal("first resuscitation should be signaled")
	}
	if g.Resuscitate(TestNetworkType) {
		t.Fatal("second resuscitation within the interval should be rate-limited")
	}
}
