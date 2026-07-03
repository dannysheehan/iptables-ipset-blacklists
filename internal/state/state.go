// Package state persists what a successful run produced, for three
// consumers that all outlive the oneshot process: the boot-restore service
// (re-applies the last-known-good ruleset before feeds are re-downloaded),
// the rollback command, and the shrink guard of the *next* run (which needs
// the previous entry count to detect a collapsing feed set).
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	lastGoodFile = "last-good.nft"
	metaFile     = "last-run.json"
)

// FeedRun records one feed's contribution, kept for status output and for
// diagnosing which feed caused a sudden count change.
type FeedRun struct {
	Name      string `json:"name"`
	Entries   int    `json:"entries"`
	FromCache bool   `json:"from_cache"`
	Stale     bool   `json:"stale,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Meta describes the last successful apply.
type Meta struct {
	Timestamp   time.Time `json:"timestamp"`
	TotalV4     int       `json:"total_v4"`
	TotalV6     int       `json:"total_v6"`
	Feeds       []FeedRun `json:"feeds"`
	ToolVersion string    `json:"tool_version"`
}

func (m Meta) Total() int { return m.TotalV4 + m.TotalV6 }

// Store reads and writes run state under one directory
// (default /var/lib/nft-blocklist, systemd's StateDirectory).
type Store struct{ Dir string }

func New(dir string) Store { return Store{Dir: dir} }

func (s Store) lastGoodPath() string { return filepath.Join(s.Dir, lastGoodFile) }
func (s Store) metaPath() string     { return filepath.Join(s.Dir, metaFile) }

// SaveLastGood persists the applied ruleset and its metadata. Both writes
// are atomic (temp + rename): the boot-restore service must never see a
// torn .nft file, because applying half a ruleset is exactly the v1 failure
// mode this project exists to eliminate.
func (s Store) SaveLastGood(ruleset []byte, meta Meta) error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	if err := atomicWrite(s.lastGoodPath(), ruleset, 0o600); err != nil {
		return fmt.Errorf("saving last-good ruleset: %w", err)
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(s.metaPath(), mb, 0o644); err != nil {
		return fmt.Errorf("saving run metadata: %w", err)
	}
	return nil
}

// LoadLastGood returns the previously applied ruleset (for rollback and
// boot restore). os.ErrNotExist means no successful run has happened yet.
func (s Store) LoadLastGood() ([]byte, error) {
	return os.ReadFile(s.lastGoodPath())
}

// LoadMeta returns the last run's metadata; a zero Meta (and no error) when
// none exists yet, so first runs don't need special-casing by callers.
func (s Store) LoadMeta() (Meta, error) {
	var m Meta
	b, err := os.ReadFile(s.metaPath())
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("parsing %s: %w", s.metaPath(), err)
	}
	return m, nil
}

// CheckShrink implements the shrink guard: refuse an update whose total
// entry count collapses below guardPercent of the previous run. This exists
// because an upstream feed going empty (dead URL, format change, provider
// trimming their list) must degrade loudly, not silently flush most of the
// firewall's protection — the v1 script did exactly that.
// A zero guardPercent or no previous run disables the check.
func CheckShrink(prevTotal, newTotal, guardPercent int) error {
	if guardPercent <= 0 || prevTotal == 0 {
		return nil
	}
	floor := prevTotal * guardPercent / 100
	if newTotal < floor {
		return fmt.Errorf(
			"shrink guard: new total %d is below %d%% of previous %d (floor %d); "+
				"refusing to apply (use --force to override)",
			newTotal, guardPercent, prevTotal, floor)
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	return nil
}
