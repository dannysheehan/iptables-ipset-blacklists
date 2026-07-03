package state

import (
	"strings"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	s := New(t.TempDir() + "/nested/state") // dir must be created on demand

	// Before any run: empty meta, no last-good.
	m, err := s.LoadMeta()
	if err != nil || m.Total() != 0 {
		t.Fatalf("initial meta = %+v err=%v, want zero", m, err)
	}
	if _, err := s.LoadLastGood(); err == nil {
		t.Fatal("want error loading last-good before any save")
	}

	meta := Meta{
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		TotalV4:   100,
		TotalV6:   10,
		Feeds: []FeedRun{
			{Name: "spamhaus-drop", Entries: 100},
			{Name: "feodo", Entries: 10, FromCache: true, Stale: true},
		},
		ToolVersion: "test",
	}
	ruleset := []byte("add table inet blocklist\n")
	if err := s.SaveLastGood(ruleset, meta); err != nil {
		t.Fatal(err)
	}

	got, err := s.LoadLastGood()
	if err != nil || string(got) != string(ruleset) {
		t.Fatalf("LoadLastGood = %q err=%v", got, err)
	}
	m, err = s.LoadMeta()
	if err != nil {
		t.Fatal(err)
	}
	if m.Total() != 110 || len(m.Feeds) != 2 || m.Feeds[1].Stale != true {
		t.Errorf("meta round trip = %+v", m)
	}
}

func TestCheckShrink(t *testing.T) {
	tests := []struct {
		name             string
		prev, new, guard int
		wantErr          bool
	}{
		{name: "no previous run always passes", prev: 0, new: 5, guard: 50},
		{name: "guard disabled", prev: 1000, new: 0, guard: 0},
		{name: "same size passes", prev: 1000, new: 1000, guard: 50},
		{name: "growth passes", prev: 1000, new: 5000, guard: 50},
		{name: "exactly at floor passes", prev: 1000, new: 500, guard: 50},
		{name: "below floor fails", prev: 1000, new: 499, guard: 50, wantErr: true},
		{name: "collapse to zero fails", prev: 1000, new: 0, guard: 50, wantErr: true},
		{name: "strict guard", prev: 1000, new: 899, guard: 90, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckShrink(tt.prev, tt.new, tt.guard)
			if tt.wantErr && err == nil {
				t.Fatal("want shrink-guard error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "--force") {
				t.Errorf("error should mention --force override: %v", err)
			}
		})
	}
}
