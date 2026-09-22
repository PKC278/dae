package vless

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/meek"

	mo "github.com/metacubex/mihomo/adapter/outbound"
)

func mustQuery(t *testing.T, rawQuery string) url.Values {
	t.Helper()
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestApplyTransportNetworkMapping(t *testing.T) {
	for _, c := range []struct {
		name  string
		query string
		want  string
	}{
		{"default is tcp", "", "tcp"},
		{"tcp stays tcp", "type=tcp", "tcp"},
		// A share link says "http" for HTTP/2, and spells the HTTP header
		// disguise as tcp+headerType=http.
		{"http means h2", "type=http", "h2"},
		{"tcp with http header disguise", "type=tcp&headerType=http", "http"},
		{"grpc", "type=grpc&serviceName=Gun", "grpc"},
		{"xhttp", "type=xhttp&path=/x", "xhttp"},
		// mihomo models HTTPUpgrade as a WebSocket variant.
		{"httpupgrade becomes ws", "type=httpupgrade&path=/u", "ws"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var opt mo.VlessOption
			if err := applyTransport(&opt, mustQuery(t, c.query)); err != nil {
				t.Fatal(err)
			}
			if opt.Network != c.want {
				t.Errorf("Network = %q, want %q", opt.Network, c.want)
			}
		})
	}
}

func TestApplyTransportHTTPUpgradeFlags(t *testing.T) {
	var opt mo.VlessOption
	if err := applyTransport(&opt, mustQuery(t, "type=httpupgrade&path=/u&ed=2048")); err != nil {
		t.Fatal(err)
	}
	if !opt.WSOpts.V2rayHttpUpgrade {
		t.Error("V2rayHttpUpgrade should be set")
	}
	if !opt.WSOpts.V2rayHttpUpgradeFastOpen {
		t.Error("ed should enable fast open for httpupgrade")
	}
	if opt.WSOpts.Path != "/u" {
		t.Errorf("Path = %q, want /u", opt.WSOpts.Path)
	}
}

func TestApplyTransportWebSocketEarlyData(t *testing.T) {
	var opt mo.VlessOption
	if err := applyTransport(&opt, mustQuery(t, "type=ws&path=/w&host=a.example&ed=2048")); err != nil {
		t.Fatal(err)
	}
	if opt.WSOpts.MaxEarlyData != 2048 {
		t.Errorf("MaxEarlyData = %d, want 2048", opt.WSOpts.MaxEarlyData)
	}
	if opt.WSOpts.EarlyDataHeaderName != "Sec-WebSocket-Protocol" {
		t.Errorf("unexpected early data header: %q", opt.WSOpts.EarlyDataHeaderName)
	}
	if opt.WSOpts.Headers["Host"] != "a.example" {
		t.Errorf("Host header = %q", opt.WSOpts.Headers["Host"])
	}

	var bad mo.VlessOption
	if err := applyTransport(&bad, mustQuery(t, "type=ws&ed=notanumber")); err == nil {
		t.Error("expected an error for a non-numeric ed")
	}
}

func TestApplyTransportRejectsUnknownNetwork(t *testing.T) {
	var opt mo.VlessOption
	if err := applyTransport(&opt, mustQuery(t, "type=carrierpigeon")); err == nil {
		t.Fatal("expected an error for an unknown transport")
	}
}

func TestApplyXHTTPExtra(t *testing.T) {
	var opt mo.VlessOption
	q := mustQuery(t, "type=xhttp&path=/x&extra="+url.QueryEscape(
		`{"noGRPCHeader":true,"xPaddingBytes":"100-1000","scMaxEachPostBytes":"1000000",
		  "xmux":{"maxConcurrency":"16","hKeepAlivePeriod":45,"maxConnections":4}}`))
	if err := applyTransport(&opt, q); err != nil {
		t.Fatal(err)
	}
	if !opt.XHTTPOpts.NoGRPCHeader {
		t.Error("noGRPCHeader should be set")
	}
	if opt.XHTTPOpts.XPaddingBytes != "100-1000" {
		t.Errorf("XPaddingBytes = %q", opt.XHTTPOpts.XPaddingBytes)
	}
	if opt.XHTTPOpts.ReuseSettings == nil {
		t.Fatal("xmux should produce reuse settings")
	}
	if opt.XHTTPOpts.ReuseSettings.MaxConcurrency != "16" {
		t.Errorf("MaxConcurrency = %q", opt.XHTTPOpts.ReuseSettings.MaxConcurrency)
	}
	// Numbers must survive the JSON round-trip as strings.
	if opt.XHTTPOpts.ReuseSettings.MaxConnections != "4" {
		t.Errorf("MaxConnections = %q, want \"4\"", opt.XHTTPOpts.ReuseSettings.MaxConnections)
	}
	if opt.XHTTPOpts.ReuseSettings.HKeepAlivePeriod != 45 {
		t.Errorf("HKeepAlivePeriod = %d, want 45", opt.XHTTPOpts.ReuseSettings.HKeepAlivePeriod)
	}

	var bad mo.VlessOption
	if err := applyTransport(&bad, mustQuery(t, "type=xhttp&extra=%7Bnot-json")); err == nil {
		t.Error("expected an error for malformed xhttp extra")
	}
}

func TestApplySecurity(t *testing.T) {
	extra := &dialer.ExtraOption{}

	var reality mo.VlessOption
	applySecurity(&reality, mustQuery(t,
		"security=reality&sni=a.example&pbk=PUBKEY&sid=beef&fp=firefox"), extra)
	if !reality.TLS {
		t.Error("reality implies TLS")
	}
	if reality.RealityOpts.PublicKey != "PUBKEY" || reality.RealityOpts.ShortID != "beef" {
		t.Errorf("unexpected reality opts: %+v", reality.RealityOpts)
	}
	if reality.ClientFingerprint != "firefox" {
		t.Errorf("ClientFingerprint = %q, want firefox", reality.ClientFingerprint)
	}
	if reality.ServerName != "a.example" {
		t.Errorf("ServerName = %q", reality.ServerName)
	}

	// A TLS link with no fp should still get a browser fingerprint, matching
	// mihomo's own converter.
	var tlsOnly mo.VlessOption
	applySecurity(&tlsOnly, mustQuery(t, "security=tls&alpn=h2,http/1.1&pcs=sha256:abc"), extra)
	if tlsOnly.ClientFingerprint != "chrome" {
		t.Errorf("ClientFingerprint = %q, want chrome", tlsOnly.ClientFingerprint)
	}
	if len(tlsOnly.ALPN) != 2 || tlsOnly.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v", tlsOnly.ALPN)
	}
	if tlsOnly.Fingerprint != "sha256:abc" {
		t.Errorf("cert pin = %q", tlsOnly.Fingerprint)
	}

	var plain mo.VlessOption
	applySecurity(&plain, mustQuery(t, "security=none"), extra)
	if plain.TLS {
		t.Error("security=none must not enable TLS")
	}
	if plain.ClientFingerprint != "" {
		t.Error("no TLS means no client fingerprint")
	}

	// dae's global AllowInsecure must reach the option.
	var insecure mo.VlessOption
	applySecurity(&insecure, mustQuery(t, "security=tls"), &dialer.ExtraOption{AllowInsecure: true})
	if !insecure.SkipCertVerify {
		t.Error("ExtraOption.AllowInsecure should set SkipCertVerify")
	}
}

func TestNewVlessRejectsBadLinks(t *testing.T) {
	for _, link := range []string{
		"vmess://something",
		"vless://uuid@host",          // no port
		"vless://uuid@host:notaport", // bad port
	} {
		if _, _, err := NewVless(&dialer.ExtraOption{}, nil, link); err == nil {
			t.Errorf("expected an error for %q", link)
		}
	}
}

// mihomo parses the padding range lazily, so an invalid value would otherwise
// only surface when a request is built. dae rejects the link instead.
func TestXPaddingBytesValidatedUpFront(t *testing.T) {
	var opt mo.VlessOption
	err := applyTransport(&opt, mustQuery(t, "type=xhttp&extra="+url.QueryEscape(
		`{"xPaddingBytes":"garbage"}`)))
	if err == nil {
		t.Fatal("expected an error for a malformed padding range")
	}

	var ok mo.VlessOption
	if err := applyTransport(&ok, mustQuery(t, "type=xhttp&extra="+url.QueryEscape(
		`{"xPaddingBytes":"100-1000"}`))); err != nil {
		t.Fatalf("a valid range must be accepted: %v", err)
	}
}

type stubDialer struct{}

func (stubDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("stub")
}

// tls_fragment is a documented dae-wide switch. VLESS now builds its TLS inside
// mihomo, so the fragmenter has to be injected underneath - assert it really is.
func TestBuildBaseDialerInjectsFragmentation(t *testing.T) {
	fragmenting := &dialer.ExtraOption{
		TlsFragment:         true,
		TlsFragmentLength:   "50-100",
		TlsFragmentInterval: "10-20",
	}

	var opt mo.VlessOption
	base, err := buildBaseDialer(stubDialer{}, &opt, mustQuery(t, "security=tls&type=tcp"), fragmenting)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.(*fragmentDialer); !ok {
		t.Fatalf("expected a FragmentDialer, got %T", base)
	}

	// Off by default.
	var plain mo.VlessOption
	base, err = buildBaseDialer(stubDialer{}, &plain, mustQuery(t, "security=tls&type=tcp"), &dialer.ExtraOption{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.(*fragmentDialer); ok {
		t.Error("fragmentation must stay off unless tls_fragment is set")
	}

	// A malformed range must fail the link rather than be ignored.
	var bad mo.VlessOption
	if _, err := buildBaseDialer(stubDialer{}, &bad, mustQuery(t, "security=tls"),
		&dialer.ExtraOption{TlsFragment: true, TlsFragmentLength: "oops", TlsFragmentInterval: "10-20"}); err == nil {
		t.Error("expected an error for a malformed tls_fragment_length")
	}
}

func TestBuildBaseDialerMeek(t *testing.T) {
	var opt mo.VlessOption
	opt.Server, opt.Port = "front.example", 443
	base, err := buildBaseDialer(stubDialer{}, &opt,
		mustQuery(t, "type=meek&url=https%3A%2F%2Fbackend.example%2Fpath&sni=front.example"),
		&dialer.ExtraOption{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.(*meek.Dialer); !ok {
		t.Fatalf("expected a meek dialer, got %T", base)
	}
	// meek terminates its own HTTPS, so mihomo must treat the stream as plain TCP.
	if opt.Network != "tcp" {
		t.Errorf("Network = %q, want tcp", opt.Network)
	}
	if opt.TLS {
		t.Error("mihomo must not add a second TLS layer on top of meek")
	}

	// meek without a url is not usable.
	var noURL mo.VlessOption
	if _, err := buildBaseDialer(stubDialer{}, &noURL, mustQuery(t, "type=meek"), &dialer.ExtraOption{}); err == nil {
		t.Error("expected an error when meek has no url")
	}
}

// Fragmentation sits below meek so that meek's own ClientHello is split too.
func TestBuildBaseDialerMeekOverFragment(t *testing.T) {
	var opt mo.VlessOption
	opt.Server, opt.Port = "front.example", 443
	base, err := buildBaseDialer(stubDialer{}, &opt,
		mustQuery(t, "type=meek&url=https%3A%2F%2Fbackend.example%2Fp"),
		&dialer.ExtraOption{TlsFragment: true, TlsFragmentLength: "50-100", TlsFragmentInterval: "10-20"})
	if err != nil {
		t.Fatal(err)
	}
	meekDialer, ok := base.(*meek.Dialer)
	if !ok {
		t.Fatalf("expected meek on top, got %T", base)
	}
	if _, ok := meekDialer.UnwrapDialer().(*fragmentDialer); !ok {
		t.Errorf("expected a FragmentDialer under meek, got %T", meekDialer.UnwrapDialer())
	}
}
