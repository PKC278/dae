/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	ob "github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func newTestBlockOutboundGroup(t *testing.T) *ob.DialerGroup {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	option := &componentdialer.GlobalOption{
		Log:           logger,
		CheckInterval: time.Second,
	}
	blockDialer, blockProperty := componentdialer.NewBlockDialer(option, func() {})
	d := componentdialer.NewDialerContext(
		context.Background(),
		blockDialer,
		option,
		componentdialer.InstanceOption{DisableCheck: true},
		blockProperty,
	)
	return ob.NewDialerGroup(
		option,
		consts.OutboundBlock.String(),
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		ob.DialerSelectionPolicy{
			Policy:     consts.DialerSelectionPolicy_Fixed,
			FixedIndex: 0,
		},
		func(bool, *componentdialer.NetworkType, bool) {},
	)
}

func newUdpBlockSimulationControlPlane(t *testing.T) *ControlPlane {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	outbounds := make([]*ob.DialerGroup, int(consts.OutboundUserDefinedMin)+1)
	outbounds[consts.OutboundBlock] = newTestBlockOutboundGroup(t)
	return &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds: outbounds,
		},
	}
}

func TestHandlePkt_BlockOutboundTreatsClosedDialAsExpectedReject(t *testing.T) {
	oldPool := DefaultUdpEndpointPool
	DefaultUdpEndpointPool = NewUdpEndpointPool()
	defer func() {
		DefaultUdpEndpointPool.Reset()
		DefaultUdpEndpointPool = oldPool
	}()

	cp := newUdpBlockSimulationControlPlane(t)
	src := mustParseAddrPort("192.168.89.3:42687")
	dst := mustParseAddrPort("142.250.191.228:443")
	payload := []byte{0xc3, 0x00, 0x00, 0x01}
	flowDecision := ClassifyUdpFlow(src, dst, payload)
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundBlock),
	}

	if err := cp.handlePkt(nil, payload, src, dst, routingResult, flowDecision, false); err != nil {
		t.Fatalf("handlePkt() error = %v, want nil for normal block", err)
	}
	if got := countPooledUdpEndpoints(DefaultUdpEndpointPool); got != 0 {
		t.Fatalf("pooled UDP endpoints after block = %d, want 0", got)
	}
}
