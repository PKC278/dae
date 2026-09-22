/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestParseOutboundBlockDrop(t *testing.T) {
	outbound, err := ParseOutbound(&config_parser.Function{
		Name: "block",
		Params: []*config_parser.Param{
			{Val: "drop"},
		},
	})

	require.NoError(t, err)
	require.Equal(t, "block", outbound.Name)
	require.True(t, outbound.Drop)
}

func TestParseOutboundDropOnlySupportsBlock(t *testing.T) {
	_, err := ParseOutbound(&config_parser.Function{
		Name: "direct",
		Params: []*config_parser.Param{
			{Val: "drop"},
		},
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "only supported by block")
}
