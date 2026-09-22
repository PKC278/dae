package dialer

import "testing"

func TestParseNodeTFODefaultsFalse(t *testing.T) {
	got, err := parseNodeTFO("vless://uuid@example.com:443?security=reality")
	if err != nil {
		t.Fatalf("parseNodeTFO() error = %v", err)
	}
	if got {
		t.Fatal("parseNodeTFO() = true, want false")
	}
}

func TestParseNodeTFOTrue(t *testing.T) {
	for _, link := range []string{
		"vless://uuid@example.com:443?security=reality&tfo=true",
		"vless://uuid@example.com:443?security=reality&tfo=1",
		"vless://uuid@example.com:443?security=reality&tfo",
		"USA_01:vless://uuid@example.com:443?security=reality&tfo=true",
	} {
		got, err := parseNodeTFO(link)
		if err != nil {
			t.Fatalf("parseNodeTFO(%q) error = %v", link, err)
		}
		if !got {
			t.Fatalf("parseNodeTFO(%q) = false, want true", link)
		}
	}
}

func TestParseNodeTFOFalse(t *testing.T) {
	got, err := parseNodeTFO("vless://uuid@example.com:443?security=reality&tfo=false")
	if err != nil {
		t.Fatalf("parseNodeTFO() error = %v", err)
	}
	if got {
		t.Fatal("parseNodeTFO() = true, want false")
	}
}

func TestParseNodeTFORejectsInvalidValue(t *testing.T) {
	if _, err := parseNodeTFO("vless://uuid@example.com:443?security=reality&tfo=maybe"); err == nil {
		t.Fatal("parseNodeTFO() error = nil, want error")
	}
}

func TestParseNodeTFOReadsFirstProxyChainHop(t *testing.T) {
	got, err := parseNodeTFO("vless://uuid@example.com:443?security=reality&tfo=true -> socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parseNodeTFO() error = %v", err)
	}
	if !got {
		t.Fatal("parseNodeTFO() = false, want true")
	}
}

func TestParseNodeTFOIgnoresLaterProxyChainHops(t *testing.T) {
	got, err := parseNodeTFO("socks5://127.0.0.1:1080 -> vless://uuid@example.com:443?security=reality&tfo=true")
	if err != nil {
		t.Fatalf("parseNodeTFO() error = %v", err)
	}
	if got {
		t.Fatal("parseNodeTFO() = true, want false")
	}
}

func TestNewNodeBaseDialerUsesTCPFastOpenDialerWhenEnabled(t *testing.T) {
	base := newNodeBaseDialer(&GlobalOption{}, true)
	wrapped, ok := base.(*defaultNetworkDialer)
	if !ok {
		t.Fatalf("newNodeBaseDialer() type = %T, want *defaultNetworkDialer", base)
	}
	if _, ok := wrapped.Dialer.(*tcpFastOpenDialer); !ok {
		t.Fatalf("wrapped dialer type = %T, want *tcpFastOpenDialer", wrapped.Dialer)
	}
}

func TestNeedsStickyIpCachingSupportsPortUnionDomain(t *testing.T) {
	if !needsStickyIpCaching("example.com:443,8443-8450") {
		t.Fatal("expected domain port-union address to require sticky IP caching")
	}
}

func TestNeedsStickyIpCachingSkipsPortUnionIP(t *testing.T) {
	if needsStickyIpCaching("203.0.113.10:443,8443-8450") {
		t.Fatal("expected IP port-union address to skip sticky IP caching")
	}
}

func TestNeedsStickyIpCachingSkipsBracketedIPv6(t *testing.T) {
	// IPv6 IP addresses (even with port-union) should not require sticky IP caching
	if needsStickyIpCaching("[2001:db8::1]:443,8443") {
		t.Fatal("expected IPv6 IP port-union address to skip sticky IP caching")
	}
}
