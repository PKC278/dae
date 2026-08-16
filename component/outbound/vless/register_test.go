/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package vless

import (
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"

	// vmess's protocol creator lives in its own package; import it so the link
	// below can be built end to end.
	_ "github.com/daeuniverse/outbound/protocol/vmess"
)

// dae replaces the "vless" link handler that outbound's dialer/v2ray registers.
// Assert the winner rather than trusting initialisation order to stay put: a
// regression here would silently route every VLESS node back to outbound's old
// implementation, and nothing else would fail.
func TestDaeImplementationWinsRegistration(t *testing.T) {
	const link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443" +
		"?security=tls&type=tcp&sni=example.com&flow=xtls-rprx-vision#node"

	d, property, err := dialer.NewNetproxyDialerFromLink(
		direct.SymmetricDirect, &dialer.ExtraOption{TlsImplementation: "tls"}, link)
	if err != nil {
		t.Fatalf("failed to build the vless dialer: %v", err)
	}
	if _, ok := d.(*Dialer); !ok {
		t.Fatalf("vless links resolved to %T; dae's implementation did not win", d)
	}
	if property.Protocol != "vless" {
		t.Errorf("Protocol = %q, want vless", property.Protocol)
	}
	if property.Name != "node" {
		t.Errorf("Name = %q, want node", property.Name)
	}
}

// The transports mihomo has no equivalent for still come from dae's side.
func TestMeekStillReachableThroughRegistration(t *testing.T) {
	const link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:443" +
		"?type=meek&url=https%3A%2F%2Fbackend.example%2Fp&sni=front.example#meek"

	d, _, err := dialer.NewNetproxyDialerFromLink(
		direct.SymmetricDirect, &dialer.ExtraOption{TlsImplementation: "tls"}, link)
	if err != nil {
		t.Fatalf("failed to build the meek vless dialer: %v", err)
	}
	if _, ok := d.(*Dialer); !ok {
		t.Fatalf("meek vless resolved to %T", d)
	}
}

// A vmess link must keep using outbound's handler.
func TestVmessUnaffected(t *testing.T) {
	d, _, err := dialer.NewNetproxyDialerFromLink(
		direct.SymmetricDirect, &dialer.ExtraOption{TlsImplementation: "tls"},
		"vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6IjEyNy4wLjAuMSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0")
	if err != nil {
		t.Fatalf("failed to build the vmess dialer: %v", err)
	}
	if _, ok := d.(*Dialer); ok {
		t.Fatal("vmess must not be routed to dae's vless implementation")
	}
}
