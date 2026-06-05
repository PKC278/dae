/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestCloneParamsCopiesSliceButSharesParamObjects(t *testing.T) {
	p0 := &config_parser.Param{Key: "k0", Val: "v0"}
	params := []*config_parser.Param{p0, nil}
	cloned := cloneParams(params)

	if len(cloned) != len(params) {
		t.Fatalf("unexpected len: %d", len(cloned))
	}
	if cloned[0] != p0 {
		t.Fatalf("expected shared param pointer")
	}

	cloned[0] = nil
	if params[0] == nil {
		t.Fatalf("expected independent slice container")
	}
}

func TestPostDatReaderOptimizersDoNotMutateCachedParams(t *testing.T) {
	originKey := string(consts.RoutingDomainKey_Suffix)
	originVal := "example.com"
	cached := []*config_parser.Param{
		{Key: originKey, Val: originVal},
	}

	hit1 := cloneParams(cached)
	hit2 := cloneParams(cached)

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name: consts.Function_Domain,
					Params: []*config_parser.Param{
						hit1[0],
						{Key: string(consts.RoutingDomainKey_Keyword), Val: "example"},
					},
				},
			},
			Outbound: config_parser.Function{Name: "out"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{
					Name:   consts.Function_Domain,
					Params: []*config_parser.Param{hit2[0]},
				},
			},
			Outbound: config_parser.Function{Name: "out"},
		},
	}

	var err error
	rules, err = (&MergeAndSortRulesOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("MergeAndSortRulesOptimizer failed: %v", err)
	}
	_, err = (&DeduplicateParamsOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("DeduplicateParamsOptimizer failed: %v", err)
	}

	if cached[0].Key != originKey || cached[0].Val != originVal {
		t.Fatalf("cached param mutated: got %q:%q", cached[0].Key, cached[0].Val)
	}
}

func TestDatReaderOptimizerLoadsRuleProviderByFunctionType(t *testing.T) {
	ruleProviderDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`
# comment
payload:
- '+.example.com'
- '.subonly.example.net'
- '*.wild.example.org'
- 'books.example.test'
- '192.0.2.0/24'
198.51.100.1
`))
	}))
	defer server.Close()

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: "rule-set", Val: "cn"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Ip,
				Params: []*config_parser.Param{{Key: "rule-set", Val: "cn"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
	}

	got, err := (&DatReaderOptimizer{
		RuleProviders:   map[string]string{"cn": server.URL},
		RuleProviderDir: ruleProviderDir,
	}).Optimize(rules)
	if err != nil {
		t.Fatalf("Optimize failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ruleProviderDir, "cn.list")); err != nil {
		t.Fatalf("expected rule provider file to be stored: %v", err)
	}

	domainParams := got[0].AndFunctions[0].Params
	assertParamExists(t, domainParams, string(consts.RoutingDomainKey_Suffix), "example.com")
	assertParamExists(t, domainParams, string(consts.RoutingDomainKey_Suffix), ".subonly.example.net")
	assertParamExists(t, domainParams, string(consts.RoutingDomainKey_Regex), `^[^.]+\.wild\.example\.org$`)
	assertParamExists(t, domainParams, string(consts.RoutingDomainKey_Full), "books.example.test")
	assertParamMissing(t, domainParams, "", "192.0.2.0/24")
	assertParamMissing(t, domainParams, "", "198.51.100.1/32")

	ipParams := got[1].AndFunctions[0].Params
	assertParamExists(t, ipParams, "", "192.0.2.0/24")
	assertParamExists(t, ipParams, "", "198.51.100.1/32")
	assertParamMissing(t, ipParams, string(consts.RoutingDomainKey_Suffix), "example.com")
}

func TestDatReaderOptimizerDropsRuleWhenRuleProviderFunctionIsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name:   consts.Function_Domain,
					Params: []*config_parser.Param{{Key: "rule-set", Val: "iponly"}},
				},
				{
					Name:   consts.Function_Port,
					Params: []*config_parser.Param{{Val: "443"}},
				},
			},
			Outbound: config_parser.Function{Name: "direct"},
		},
	}

	got, err := (&DatReaderOptimizer{
		RuleProviders:   map[string]string{"iponly": server.URL},
		RuleProviderDir: t.TempDir(),
	}).Optimize(rules)
	if err != nil {
		t.Fatalf("Optimize failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected rule to be dropped, got %d rules", len(got))
	}
}

func TestDatReaderOptimizerSkipsUnavailableRuleProviderWhenConfigured(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: "rule-set", Val: "missing"}},
			}},
			Outbound: config_parser.Function{Name: "direct"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Port,
				Params: []*config_parser.Param{{Val: "443"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}

	got, err := (&DatReaderOptimizer{
		RuleProviders:                map[string]string{"missing": "https://example.com/missing.list"},
		RuleProviderDir:              t.TempDir(),
		RuleProviderDownloadDisabled: true,
		SkipUnavailableRuleProviders: true,
	}).Optimize(rules)
	if err != nil {
		t.Fatalf("Optimize failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("optimized rules = %d, want 1", len(got))
	}
	if got[0].Outbound.Name != "proxy" {
		t.Fatalf("remaining outbound = %q, want proxy", got[0].Outbound.Name)
	}
}

func TestDownloadRuleProvidersUsesExistingTextFile(t *testing.T) {
	ruleProviderDir := t.TempDir()
	path := filepath.Join(ruleProviderDir, "cn.list")
	if err := os.WriteFile(path, []byte("+.local.example\n"), 0644); err != nil {
		t.Fatalf("write existing provider: %v", err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("+.remote.example\n"))
	}))
	defer server.Close()

	if err := DownloadRuleProviders(map[string]string{"cn": server.URL}, ruleProviderDir); err != nil {
		t.Fatalf("DownloadRuleProviders failed: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("server requests = %d, want 0", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read provider file: %v", err)
	}
	if string(content) != "+.local.example\n" {
		t.Fatalf("provider file was overwritten: %q", content)
	}
}

func TestDownloadRuleProvidersOnlyDownloadsMissingProvider(t *testing.T) {
	ruleProviderDir := t.TempDir()
	existingPath := filepath.Join(ruleProviderDir, "existing.list")
	if err := os.WriteFile(existingPath, []byte("+.local.example\n"), 0644); err != nil {
		t.Fatalf("write existing provider: %v", err)
	}

	var existingRequests atomic.Int32
	var missingRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/existing":
			existingRequests.Add(1)
			_, _ = w.Write([]byte("+.remote-existing.example\n"))
		case "/missing":
			missingRequests.Add(1)
			_, _ = w.Write([]byte("+.remote-missing.example\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := DownloadRuleProviders(map[string]string{
		"existing": server.URL + "/existing",
		"missing":  server.URL + "/missing",
	}, ruleProviderDir); err != nil {
		t.Fatalf("DownloadRuleProviders failed: %v", err)
	}
	if got := existingRequests.Load(); got != 0 {
		t.Fatalf("existing provider requests = %d, want 0", got)
	}
	if got := missingRequests.Load(); got != 1 {
		t.Fatalf("missing provider requests = %d, want 1", got)
	}
	content, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatalf("read existing provider file: %v", err)
	}
	if string(content) != "+.local.example\n" {
		t.Fatalf("existing provider file was overwritten: %q", content)
	}
	missingContent, err := os.ReadFile(filepath.Join(ruleProviderDir, "missing.list"))
	if err != nil {
		t.Fatalf("read missing provider file: %v", err)
	}
	if string(missingContent) != "+.remote-missing.example\n" {
		t.Fatalf("missing provider content = %q", missingContent)
	}
}

func TestDownloadRuleProvidersLimitsConcurrentDownloads(t *testing.T) {
	ruleProviderDir := t.TempDir()
	var active atomic.Int32
	var maxActive atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(release)
		})
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := maxActive.Load()
			if current <= old || maxActive.CompareAndSwap(old, current) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		_, _ = w.Write([]byte("+.remote.example\n"))
	}))
	defer server.Close()

	ruleProviders := make(map[string]string)
	for i := range 8 {
		ruleProviders[fmt.Sprintf("p%d", i)] = server.URL
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- DownloadRuleProvidersWithOptions(ruleProviders, DownloadRuleProviderOptions{
			Dir:   ruleProviderDir,
			Force: true,
		})
	}()

	for range maxConcurrentRuleProviderDownloads {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for initial concurrent rule provider downloads")
		}
	}
	select {
	case <-entered:
		t.Fatalf("observed more than %d concurrent downloads", maxConcurrentRuleProviderDownloads)
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() {
		close(release)
	})
	if err := <-errCh; err != nil {
		t.Fatalf("DownloadRuleProvidersWithOptions failed: %v", err)
	}
	if got := maxActive.Load(); got > maxConcurrentRuleProviderDownloads {
		t.Fatalf("max concurrent downloads = %d, want <= %d", got, maxConcurrentRuleProviderDownloads)
	}
}

func TestDownloadRuleProvidersOverwritesNonTextFile(t *testing.T) {
	ruleProviderDir := t.TempDir()
	path := filepath.Join(ruleProviderDir, "cn.list")
	if err := os.WriteFile(path, []byte{0xff, 0x00, 0xfe}, 0644); err != nil {
		t.Fatalf("write existing provider: %v", err)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("+.remote.example\n"))
	}))
	defer server.Close()

	if err := DownloadRuleProviders(map[string]string{"cn": server.URL}, ruleProviderDir); err != nil {
		t.Fatalf("DownloadRuleProviders failed: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server requests = %d, want 1", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read provider file: %v", err)
	}
	if string(content) != "+.remote.example\n" {
		t.Fatalf("provider file was not overwritten: %q", content)
	}
}

func TestDownloadRuleProvidersForceRefreshesExistingTextFile(t *testing.T) {
	ruleProviderDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ruleProviderDir, "cn.list"), []byte("old.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ruleProviderDir, "fresh.list"), []byte("fresh-old.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(ruleProviderDir, "cn.list"), oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cn":
			_, _ = w.Write([]byte("new.example\n"))
		case "/fresh":
			_, _ = w.Write([]byte("fresh-new.example\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := DownloadRuleProvidersWithOptions(map[string]string{
		"cn":    server.URL + "/cn",
		"fresh": server.URL + "/fresh",
	}, DownloadRuleProviderOptions{
		Dir:   ruleProviderDir,
		Force: true,
	}); err != nil {
		t.Fatalf("DownloadRuleProvidersWithOptions failed: %v", err)
	}

	for name, want := range map[string]string{
		"cn":    "new.example\n",
		"fresh": "fresh-new.example\n",
	} {
		path := filepath.Join(ruleProviderDir, name+".list")
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s rule provider content = %q, want forced refresh", name, got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.ModTime().Before(before) {
			t.Fatalf("%s rule provider mtime = %v, want >= %v", name, info.ModTime(), before)
		}
	}
}

func TestDownloadRuleProvidersIgnoreErrorsContinuesOtherProviders(t *testing.T) {
	ruleProviderDir := t.TempDir()
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok.example\n"))
	}))
	defer okServer.Close()
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))
	defer badServer.Close()

	err := DownloadRuleProvidersWithOptions(map[string]string{
		"bad": badServer.URL,
		"ok":  okServer.URL,
	}, DownloadRuleProviderOptions{
		Dir:          ruleProviderDir,
		Force:        true,
		IgnoreErrors: true,
	})
	if err != nil {
		t.Fatalf("DownloadRuleProvidersWithOptions failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(ruleProviderDir, "ok.list"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok.example\n" {
		t.Fatalf("ok rule provider content = %q", got)
	}
}

func TestDownloadRuleProvidersUsesHTTPClientResolver(t *testing.T) {
	ruleProviderDir := t.TempDir()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("+.remote.example\n"))
	}))
	defer server.Close()

	var resolved atomic.Int32
	err := DownloadRuleProvidersWithOptions(map[string]string{"cn": server.URL}, DownloadRuleProviderOptions{
		Dir: ruleProviderDir,
		HTTPClientResolver: func(name string, rawURL string) (*http.Client, error) {
			resolved.Add(1)
			if name != "cn" {
				t.Fatalf("resolver name = %q, want cn", name)
			}
			if rawURL != server.URL {
				t.Fatalf("resolver URL = %q, want %q", rawURL, server.URL)
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("DownloadRuleProvidersWithOptions failed: %v", err)
	}
	if got := resolved.Load(); got != 1 {
		t.Fatalf("resolver calls = %d, want 1", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server requests = %d, want 1", got)
	}
}

func assertParamExists(t *testing.T, params []*config_parser.Param, key, val string) {
	t.Helper()
	for _, param := range params {
		if param.Key == key && param.Val == val {
			return
		}
	}
	t.Fatalf("missing param %q:%q in %#v", key, val, params)
}

func assertParamMissing(t *testing.T, params []*config_parser.Param, key, val string) {
	t.Helper()
	for _, param := range params {
		if param.Key == key && param.Val == val {
			t.Fatalf("unexpected param %q:%q in %#v", key, val, params)
		}
	}
}
