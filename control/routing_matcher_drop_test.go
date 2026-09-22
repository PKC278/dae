/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newUdpBlockRule(outboundParam string) []*config_parser.RoutingRule {
	outbound := config_parser.Function{Name: consts.OutboundBlock.String()}
	if outboundParam != "" {
		outbound.Params = []*config_parser.Param{{Val: outboundParam}}
	}
	return []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name:   consts.Function_L4Proto,
					Params: []*config_parser.Param{{Val: "udp"}},
				},
			},
			Outbound: outbound,
		},
	}
}

func TestRoutingMatcherBlockDropParamReachesMatcher(t *testing.T) {
	program, err := routing.NewNormalizedProgram(
		newUdpBlockRule(consts.OutboundParam_Drop),
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	require.NoError(t, err)

	builder, err := NewRoutingMatcherBuilderFromProgram(
		logrus.New(),
		program,
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
		},
		nil,
	)
	require.NoError(t, err)

	matcher, err := builder.BuildUserspace()
	require.NoError(t, err)

	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	outbound, _, _, drop, err := matcher.MatchWithDrop(
		src.Addr().As16(),
		dst.Addr().As16(),
		src.Port(),
		dst.Port(),
		consts.IpVersion_4,
		consts.L4ProtoType_UDP,
		"",
		[16]uint8{},
		0,
		[16]uint8{},
	)
	require.NoError(t, err)
	require.Equal(t, consts.OutboundBlock, outbound)
	require.True(t, drop)
}

func TestRoutingMatcherBlockWithoutDropParamDoesNotDrop(t *testing.T) {
	program, err := routing.NewNormalizedProgram(
		newUdpBlockRule(""),
		config.FunctionOrString(consts.OutboundDirect.String()),
	)
	require.NoError(t, err)

	builder, err := NewRoutingMatcherBuilderFromProgram(
		logrus.New(),
		program,
		map[string]uint8{
			consts.OutboundDirect.String(): uint8(consts.OutboundDirect),
			consts.OutboundBlock.String():  uint8(consts.OutboundBlock),
		},
		nil,
	)
	require.NoError(t, err)

	matcher, err := builder.BuildUserspace()
	require.NoError(t, err)

	src := netip.MustParseAddrPort("192.0.2.10:12345")
	dst := netip.MustParseAddrPort("198.51.100.20:443")
	outbound, _, _, drop, err := matcher.MatchWithDrop(
		src.Addr().As16(),
		dst.Addr().As16(),
		src.Port(),
		dst.Port(),
		consts.IpVersion_4,
		consts.L4ProtoType_UDP,
		"",
		[16]uint8{},
		0,
		[16]uint8{},
	)
	require.NoError(t, err)
	require.Equal(t, consts.OutboundBlock, outbound)
	require.False(t, drop)
}

func TestDropParamOnlySupportedByBlock(t *testing.T) {
	_, err := routing.ParseOutbound(&config_parser.Function{
		Name:   consts.OutboundDirect.String(),
		Params: []*config_parser.Param{{Val: consts.OutboundParam_Drop}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "only supported by block")
}
