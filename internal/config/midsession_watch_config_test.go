package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestMidsessionWatchDefaults asserts the compiled-in tuning is used
// when no config exists: the full pass runs every 6th tick, unthrottled
// (concurrency 0 = the walk's normal concurrency).
func TestMidsessionWatchDefaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workdir := t.TempDir()
	lc, _, err := LoadLauncher(workdir)
	if err != nil {
		t.Fatalf("LoadLauncher: %v", err)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassTicks; got == nil || *got != 6 {
		t.Errorf("FullPassTicks = %v, want unset → 6", got)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassConcurrency; got != 0 {
		t.Errorf("FullPassConcurrency = %d, want 0 (unthrottled)", got)
	}
}

// TestMidsessionWatchDisableFullPass asserts full_pass_ticks: 0 disables
// the full re-scan (a deliberate user choice) instead of falling back to
// the default, and survives the load path unchanged.
func TestMidsessionWatchDisableFullPass(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeConfig(t, filepath.Join(home, ".config", "omac", "config.yaml"), `
sandbox:
  midsession_watch:
    full_pass_ticks: 0
`)
	lc, _, err := LoadLauncher(t.TempDir())
	if err != nil {
		t.Fatalf("LoadLauncher: %v", err)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassTicks; got == nil || *got != 0 {
		t.Errorf("FullPassTicks = %v, want 0 (disabled)", got)
	}
}

// TestMidsessionWatchGlobalConfigOverride asserts the user-global config
// can tune the watch, and that an unset field falls back to its default.
func TestMidsessionWatchGlobalConfigOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeConfig(t, filepath.Join(home, ".config", "omac", "config.yaml"), `
sandbox:
  midsession_watch:
    full_pass_ticks: 30
    full_pass_concurrency: 2
`)
	lc, _, err := LoadLauncher(t.TempDir())
	if err != nil {
		t.Fatalf("LoadLauncher: %v", err)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassTicks; got == nil || *got != 30 {
		t.Errorf("FullPassTicks = %v, want 30", got)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassConcurrency; got != 2 {
		t.Errorf("FullPassConcurrency = %d, want 2", got)
	}
}

// TestSecurityWorkdirConfigCannotTuneMidsessionWatch asserts the watch
// tuning is a security field: a weaker full-pass cadence widens the
// window in which a mid-session secret file goes unnoticed, so only the
// user-global config may set it — a project config must not.
func TestSecurityWorkdirConfigCannotTuneMidsessionWatch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workdir := t.TempDir()
	writeConfig(t, filepath.Join(workdir, ".opencode", "oh-my-agentic-coder.yaml"), `
sandbox:
  midsession_watch:
    full_pass_ticks: 1000000
    full_pass_concurrency: 1
`)
	lc, path, err := LoadLauncher(workdir)
	if err != nil {
		t.Fatalf("LoadLauncher: %v", err)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassTicks; got == nil || *got != 6 {
		t.Errorf("a workdir config set full_pass_ticks to %v (want the default 6): a project can weaken its own detection bound", got)
	}
	if got := lc.Sandbox.MidsessionWatch.FullPassConcurrency; got != 0 {
		t.Errorf("a workdir config set full_pass_concurrency to %d (want the default 0 = unthrottled)", got)
	}
	_ = path
}

// TestMidsessionWatchRejectsNegative asserts a negative tuning value is
// a config error, not a silently broken watch (a non-positive full-pass
// interval would divide by zero in the tick counter).
func TestMidsessionWatchRejectsNegative(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeConfig(t, filepath.Join(home, ".config", "omac", "config.yaml"), `
sandbox:
  midsession_watch:
    full_pass_ticks: -3
`)
	_, _, err := LoadLauncher(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "full_pass_ticks") {
		t.Fatalf("LoadLauncher err = %v, want a full_pass_ticks validation error", err)
	}
}
