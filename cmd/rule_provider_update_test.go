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
