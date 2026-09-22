/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// An address claimed by domains whose rules disagree is routed to the control
// plane, which can only pick the right rule once the domain is known. That must
// be sniffed even under dial_mode ip, and the sniff-failure suppression cache
// must not skip it.
func TestControlPlaneRoutingOutboundAlwaysSniffs(t *testing.T) {
	cp := &ControlPlane{
		sniffingTimeout: 30 * time.Millisecond,
		controlPlaneGenerationState: controlPlaneGenerationState{
			dialMode: consts.DialMode_Ip,
		},
	}
	dst := netip.MustParseAddrPort("198.51.100.20:443")

	ambiguous := &bpfRoutingResult{Outbound: uint8(consts.OutboundControlPlaneRouting)}
	if !cp.shouldTryTcpSniff(dst, ambiguous) {
		t.Fatal("control-plane-routing outbound must be sniffed even under dial_mode ip")
	}

	direct := &bpfRoutingResult{Outbound: uint8(consts.OutboundDirect)}
	if cp.shouldTryTcpSniff(dst, direct) {
		t.Fatal("dial_mode ip must not sniff an ordinary flow")
	}

	key := newTcpSniffNegKey(dst, ambiguous)
	now := time.Now()
	for i := uint8(0); i < tcpSniffFailureThreshold; i++ {
		cp.noteTcpSniffFailure(key, now)
	}
	if !cp.shouldSkipTcpSniffByNegativeCache(key, now) {
		t.Fatal("negative cache should suppress after repeated failures")
	}
	if cp.shouldSkipTcpSniff(ambiguous, key, now) {
		t.Fatal("an ambiguous flow must not be suppressed by the negative cache")
	}
}
