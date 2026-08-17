package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
)

func TestRuleProviderForceRefreshDueWhenAnyProviderExpired(t *testing.T) {
	ruleProviderDir := t.TempDir()
	now := time.Now()
	conf := &config.Config{
		Global: config.Global{RuleProviderUpdateInterval: 24 * time.Hour},
		RuleProvider: []config.KeyableString{
			"old:https://example.com/old.list",
			"fresh:https://example.com/fresh.list",
		},
	}

	oldPath := filepath.Join(ruleProviderDir, "old.list")
	freshPath := filepath.Join(ruleProviderDir, "fresh.list")
	if err := os.WriteFile(oldPath, []byte("old.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(freshPath, []byte("fresh.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldPath, now.Add(-25*time.Hour), now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(freshPath, now, now); err != nil {
		t.Fatal(err)
	}

	if !ruleProviderForceRefreshDue(conf, ruleProviderDir, now) {
		t.Fatalf("ruleProviderForceRefreshDue() = false, want true when one provider is expired")
	}
}

func TestRuleProviderForceRefreshDueIgnoresMissingProvider(t *testing.T) {
	ruleProviderDir := t.TempDir()
	now := time.Now()
	conf := &config.Config{
		Global: config.Global{RuleProviderUpdateInterval: 24 * time.Hour},
		RuleProvider: []config.KeyableString{
			"fresh:https://example.com/fresh.list",
			"missing:https://example.com/missing.list",
		},
	}

	freshPath := filepath.Join(ruleProviderDir, "fresh.list")
	if err := os.WriteFile(freshPath, []byte("fresh.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(freshPath, now, now); err != nil {
		t.Fatal(err)
	}

	if ruleProviderForceRefreshDue(conf, ruleProviderDir, now) {
		t.Fatalf("ruleProviderForceRefreshDue() = true, want false when only one provider is missing")
	}
}

func TestRuleProviderUpdateScheduleIsImmediateAndForcedWhenAnyProviderExpired(t *testing.T) {
	configDir := t.TempDir()
	oldCfgFile := cfgFile
	cfgFile = filepath.Join(configDir, "config.dae")
	t.Cleanup(func() { cfgFile = oldCfgFile })

	ruleProviderDir := filepath.Join(configDir, "rules")
	if err := os.MkdirAll(ruleProviderDir, 0755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	conf := &config.Config{
		Global: config.Global{RuleProviderUpdateInterval: 24 * time.Hour},
		RuleProvider: []config.KeyableString{
			"old:https://example.com/old.list",
			"fresh:https://example.com/fresh.list",
		},
	}

	oldPath := filepath.Join(ruleProviderDir, "old.list")
	freshPath := filepath.Join(ruleProviderDir, "fresh.list")
	if err := os.WriteFile(oldPath, []byte("old.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(freshPath, []byte("fresh.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldPath, now.Add(-25*time.Hour), now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(freshPath, now, now); err != nil {
		t.Fatal(err)
	}

	schedule := ruleProviderUpdateScheduleFromConfig(conf, true)
	if schedule.delay != time.Nanosecond {
		t.Fatalf("schedule delay = %v, want immediate update", schedule.delay)
	}
	if !schedule.forceDownload {
		t.Fatalf("schedule forceDownload = false, want true when one provider is expired")
	}
}

func TestRuleProviderUpdateScheduleIsImmediateButNotForcedWhenAnyProviderMissing(t *testing.T) {
	ruleProviderDir := t.TempDir()
	now := time.Now()
	conf := &config.Config{
		Global: config.Global{RuleProviderUpdateInterval: 24 * time.Hour},
		RuleProvider: []config.KeyableString{
			"fresh:https://example.com/fresh.list",
			"missing:https://example.com/missing.list",
		},
	}

	freshPath := filepath.Join(ruleProviderDir, "fresh.list")
	if err := os.WriteFile(freshPath, []byte("fresh.example\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(freshPath, now, now); err != nil {
		t.Fatal(err)
	}

	schedule := ruleProviderUpdateScheduleForDir(conf, ruleProviderDir, now, true)
	if schedule.delay != time.Nanosecond {
		t.Fatalf("schedule delay = %v, want immediate update", schedule.delay)
	}
	if schedule.forceDownload {
		t.Fatalf("schedule forceDownload = true, want false when only one provider is missing")
	}
}

func TestRuleProviderUpdateLoopRetriesAfterRejectedReload(t *testing.T) {
	reloadReqs := make(chan reloadRequest, 1)
	manager := newReloadManager(reloadReqs, make(chan struct{}, 1), nil)
	manager.reloadPending.Store(true)

	rejected := make(chan struct{}, 1)
	oldSetRunSignalProgress := setRunSignalProgress
	setRunSignalProgress = func(byte, string) error {
		select {
		case rejected <- struct{}{}:
		default:
		}
		return nil
	}
	t.Cleanup(func() { setRunSignalProgress = oldSetRunSignalProgress })

	loop := startRuleProviderUpdateLoop(newDiscardLogger(), manager, ruleProviderUpdateSchedule{
		delay:         time.Millisecond,
		retryDelay:    20 * time.Millisecond,
		forceDownload: true,
	})
	defer loop.Stop()

	select {
	case <-rejected:
	case <-time.After(time.Second):
		t.Fatal("first automatic reload was not rejected")
	}
	manager.reloadPending.Store(false)

	select {
	case req := <-reloadReqs:
		if !req.forceRuleProviderDownload || !req.ignoreRuleProviderErrors {
			t.Fatalf("retried reload request = %+v, want forced best-effort update", req)
		}
		manager.reloadPending.Store(false)
		endReloadProxyFailureSuppression()
	case <-time.After(time.Second):
		t.Fatal("automatic update did not retry on the next period")
	}
}

func TestRuleProvidersFullyCached(t *testing.T) {
	conf := &config.Config{
		RuleProvider: []config.KeyableString{
			"a:https://example.com/a.list",
			"b:https://example.com/b.list",
		},
	}

	t.Run("all present", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"a", "b"} {
			if err := os.WriteFile(filepath.Join(dir, name+".list"), []byte("x\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if !ruleProvidersFullyCached(conf, dir) {
			t.Fatal("ruleProvidersFullyCached() = false, want true when every provider is cached")
		}
	})

	// One missing provider must disqualify the best-effort path: routing cannot
	// be built from a rule set that is not there, so the refresh must stay fatal.
	t.Run("one missing", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "a.list"), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if ruleProvidersFullyCached(conf, dir) {
			t.Fatal("ruleProvidersFullyCached() = true, want false when a provider is missing")
		}
	})

	t.Run("no providers", func(t *testing.T) {
		if ruleProvidersFullyCached(&config.Config{}, t.TempDir()) {
			t.Fatal("ruleProvidersFullyCached() = true, want false with no providers configured")
		}
	})
}
