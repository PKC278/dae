package cmd

import (
	"strings"
	"testing"
)

func TestParseColonMatchInput(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantScope  string
		wantName   string
		wantKey    string
		wantVal    string
		wantErrSub string
	}{
		{
			name:      "domain_suffix_default",
			raw:       "domain:example.com.",
			wantScope: "routing",
			wantName:  "domain",
			wantKey:   "suffix",
			wantVal:   "example.com",
		},
		{
			name:      "domain_full_key",
			raw:       "domain:full:example.com",
			wantScope: "routing",
			wantName:  "domain",
			wantKey:   "full",
			wantVal:   "example.com",
		},
		{
			name:      "qname_regex_key",
			raw:       "qname:regex:^yes",
			wantScope: "dns_request",
			wantName:  "qname",
			wantKey:   "regex",
			wantVal:   "^yes",
		},
		{
			name:      "ip",
			raw:       "ip:1.1.1.1",
			wantScope: "routing",
			wantName:  "ip",
			wantVal:   "1.1.1.1",
		},
		{
			name:      "source_ipv6",
			raw:       "sip:2001:db8::1",
			wantScope: "routing",
			wantName:  "sip",
			wantVal:   "2001:db8::1",
		},
		{
			name:      "process_name",
			raw:       "pname:NetworkManager",
			wantScope: "routing",
			wantName:  "pname",
			wantVal:   "NetworkManager",
		},
		{
			name:      "mac_with_colons",
			raw:       "mac:EC:74:8C:97:36:6B",
			wantScope: "routing",
			wantName:  "mac",
			wantVal:   "EC:74:8C:97:36:6B",
		},
		{
			name:      "qtype_name",
			raw:       "qtype:https",
			wantScope: "dns_request",
			wantName:  "qtype",
			wantVal:   "https",
		},
		{
			name:      "qtype_number",
			raw:       "qtype:65",
			wantScope: "dns_request",
			wantName:  "qtype",
			wantVal:   "65",
		},
		{
			name:      "dns_response_ip",
			raw:       "dns.response.ip:1.1.1.1",
			wantScope: "dns_response",
			wantName:  "ip",
			wantVal:   "1.1.1.1",
		},
		{
			name:      "dns_response_upstream_default",
			raw:       "upstream:googledns",
			wantScope: "dns_response",
			wantName:  "upstream",
			wantVal:   "googledns",
		},
		{
			name:       "reject_domain_reference",
			raw:        "domain:geosite:cn",
			wantErrSub: "unsupported reference target",
		},
		{
			name:       "reject_ip_reference",
			raw:        "ip:geoip:private",
			wantErrSub: "unsupported reference target",
		},
		{
			name:       "reject_bad_mac",
			raw:        "mac:EC:74:8C:97:36",
			wantErrSub: "invalid mac target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseColonMatchInput(tt.raw)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("parseColonMatchInput() error = %v, want containing %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseColonMatchInput() error = %v", err)
			}
			if got.Scope != tt.wantScope {
				t.Fatalf("Scope = %q, want %q", got.Scope, tt.wantScope)
			}
			if got.Function == nil {
				t.Fatal("Function is nil")
			}
			if got.Function.Name != tt.wantName {
				t.Fatalf("Function.Name = %q, want %q", got.Function.Name, tt.wantName)
			}
			if len(got.Function.Params) != 1 {
				t.Fatalf("len(Function.Params) = %d, want 1", len(got.Function.Params))
			}
			param := got.Function.Params[0]
			if param.Key != tt.wantKey {
				t.Fatalf("Param.Key = %q, want %q", param.Key, tt.wantKey)
			}
			if param.Val != tt.wantVal {
				t.Fatalf("Param.Val = %q, want %q", param.Val, tt.wantVal)
			}
		})
	}
}
