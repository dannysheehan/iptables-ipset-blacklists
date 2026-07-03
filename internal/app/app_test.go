package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dannysheehan/nft-blocklist/internal/config"
	"github.com/dannysheehan/nft-blocklist/internal/feed"
	"github.com/dannysheehan/nft-blocklist/internal/notify"
	"github.com/dannysheehan/nft-blocklist/internal/state"
)

// fakeNFT records rulesets instead of touching the kernel.
type fakeNFT struct {
	checked   [][]byte
	applied   [][]byte
	failCheck error
	failApply error
}

func (f *fakeNFT) Check(_ context.Context, rs []byte) error {
	f.checked = append(f.checked, rs)
	return f.failCheck
}
func (f *fakeNFT) Apply(_ context.Context, rs []byte) error {
	if f.failApply != nil {
		return f.failApply
	}
	f.applied = append(f.applied, rs)
	return nil
}
func (f *fakeNFT) CountSet(context.Context, string, string) (int, error) { return 0, nil }

// captureSink records events dispatched during a run.
type captureSink struct{ events []notify.Event }

func (c *captureSink) Name() string { return "capture" }
func (c *captureSink) Send(_ context.Context, e notify.Event) error {
	c.events = append(c.events, e)
	return nil
}

func (c *captureSink) kinds() []string {
	out := make([]string, len(c.events))
	for i, e := range c.events {
		out[i] = string(e.Kind)
	}
	return out
}

func (c *captureSink) has(k notify.Kind) bool {
	for _, e := range c.events {
		if e.Kind == k {
			return true
		}
	}
	return false
}

// newTestApp wires an App against a temp environment and a feed server.
func newTestApp(t *testing.T, cfg config.Config) (*App, *fakeNFT, *captureSink) {
	t.Helper()
	dir := t.TempDir()
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.CacheDir = filepath.Join(dir, "cache")
	nft := &fakeNFT{}
	sink := &captureSink{}
	var disp notify.Dispatcher
	disp.Add(sink, notify.Info, nil)

	fetcher := feed.NewFetcher(cfg.CacheDir)
	return &App{
		Cfg:      cfg,
		Fetcher:  fetcher,
		NFT:      nft,
		Store:    state.New(cfg.StateDir),
		Notify:   &disp,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "test",
		Hostname: "testhost",
	}, nft, sink
}

// feedServer serves fixture-style bodies per path.
func feedServer(t *testing.T, bodies map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(srvURL string, paths ...string) config.Config {
	cfg := config.Defaults()
	cfg.ShrinkGuardPercent = 50
	for i, p := range paths {
		f := config.FeedDefaults()
		f.Name = fmt.Sprintf("feed-%d", i)
		f.URL = srvURL + p
		f.Format = config.FormatCIDR
		f.Family = config.FamilyBoth
		f.MinFetchInterval = 0 // tests re-fetch on every Update call
		cfg.Feeds = append(cfg.Feeds, f)
	}
	return cfg
}

func TestUpdateHappyPath(t *testing.T) {
	srv := feedServer(t, map[string]string{
		"/a": "1.2.3.4\n5.6.7.0/24\n",
		"/b": "5.6.7.8\n2600:1::/48\n",
	})
	cfg := testConfig(srv.URL, "/a", "/b")
	a, nft, sink := newTestApp(t, cfg)

	if err := a.Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(nft.checked) != 1 || len(nft.applied) != 1 {
		t.Fatalf("check/apply counts = %d/%d, want 1/1", len(nft.checked), len(nft.applied))
	}
	rs := string(nft.applied[0])
	// 5.6.7.8 must have merged into 5.6.7.0/24.
	if !strings.Contains(rs, "5.6.7.0/24") || strings.Contains(rs, "5.6.7.8") {
		t.Errorf("CIDR merge missing in ruleset:\n%s", rs)
	}
	if !strings.Contains(rs, "2600:1::/48") {
		t.Errorf("v6 entry missing")
	}

	// State persisted for boot restore + next run's shrink guard.
	meta, err := a.Store.LoadMeta()
	if err != nil || meta.Total() != 3 { // 1.2.3.4, 5.6.7.0/24, 2600:1::/48
		t.Errorf("meta = %+v err=%v, want total 3", meta, err)
	}
	if !sink.has(notify.KindUpdateApplied) {
		t.Errorf("events = %v, want update_applied", sink.kinds())
	}
}

func TestUpdateShrinkGuardAndForce(t *testing.T) {
	bodies := map[string]string{"/a": "1.2.3.1\n1.2.4.2\n1.2.5.3\n1.2.6.4\n"}
	srv := feedServer(t, bodies)
	cfg := testConfig(srv.URL, "/a")
	a, nft, sink := newTestApp(t, cfg)

	if err := a.Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	// Feed collapses to one entry (25% of previous, below the 50% guard):
	// the update must refuse, keep kernel state, and alert.
	bodies["/a"] = "9.9.9.9\n"
	err := a.Update(context.Background(), UpdateOptions{})
	if err == nil || !strings.Contains(err.Error(), "shrink guard") {
		t.Fatalf("err = %v, want shrink guard refusal", err)
	}
	if len(nft.applied) != 1 {
		t.Fatalf("applied %d rulesets, want 1 (guard must block second apply)", len(nft.applied))
	}
	if !sink.has(notify.KindShrinkGuard) || !sink.has(notify.KindUpdateFailed) {
		t.Errorf("events = %v, want shrink_guard and update_failed", sink.kinds())
	}
	// Previous state stays authoritative for the next run.
	meta, _ := a.Store.LoadMeta()
	if meta.Total() != 4 {
		t.Errorf("meta total = %d, want 4 (unchanged)", meta.Total())
	}

	// --force overrides deliberately.
	if err := a.Update(context.Background(), UpdateOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	if len(nft.applied) != 2 {
		t.Fatalf("applied = %d, want 2 after force", len(nft.applied))
	}
	meta, _ = a.Store.LoadMeta()
	if meta.Total() != 1 {
		t.Errorf("meta total = %d, want 1 after forced shrink", meta.Total())
	}
}

func TestUpdateAllowlistWinsAndCollisionReported(t *testing.T) {
	srv := feedServer(t, map[string]string{"/a": "1.2.3.4\n5.6.7.8\n"})
	cfg := testConfig(srv.URL, "/a")

	dir := t.TempDir()
	cfg.AllowlistFile = filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(cfg.AllowlistFile, []byte("# my server\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, nft, sink := newTestApp(t, cfg)
	if err := a.Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	rs := string(nft.applied[0])
	if strings.Contains(rs, "add element inet blocklist static4 { 1.2.3.4, 5.6.7.8 }") {
		t.Error("allowlisted IP must be subtracted from static set")
	}
	if !strings.Contains(rs, "add element inet blocklist allow4 { 5.6.7.8 }") {
		t.Errorf("allow set must carry the allowlisted IP:\n%s", rs)
	}
	if !sink.has(notify.KindAllowlistCollision) {
		t.Errorf("events = %v, want allowlist_collision", sink.kinds())
	}
}

func TestUpdateFeedFailureDegrades(t *testing.T) {
	srv := feedServer(t, map[string]string{"/good": "1.2.3.4\n2.3.4.5\n"})
	// /bad 404s; feed-1 has no cache, so with fail_policy use_cache it is
	// skipped for the run while the good feed still applies.
	cfg := testConfig(srv.URL, "/good", "/bad")
	a, nft, sink := newTestApp(t, cfg)

	if err := a.Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatalf("one bad feed must not abort the run: %v", err)
	}
	if len(nft.applied) != 1 {
		t.Fatal("good feed's entries must still be applied")
	}
	if !sink.has(notify.KindFeedDegraded) {
		t.Errorf("events = %v, want feed_degraded", sink.kinds())
	}
	meta, _ := a.Store.LoadMeta()
	var badRun *state.FeedRun
	for i := range meta.Feeds {
		if meta.Feeds[i].Name == "feed-1" {
			badRun = &meta.Feeds[i]
		}
	}
	if badRun == nil || badRun.Error == "" {
		t.Errorf("failed feed must be recorded with its error: %+v", meta.Feeds)
	}
}

func TestUpdateDryRunAppliesNothing(t *testing.T) {
	srv := feedServer(t, map[string]string{"/a": "1.2.3.4\n"})
	cfg := testConfig(srv.URL, "/a")
	a, nft, _ := newTestApp(t, cfg)

	var out strings.Builder
	if err := a.Update(context.Background(), UpdateOptions{DryRun: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(nft.applied) != 0 {
		t.Error("dry run must not apply")
	}
	if len(nft.checked) != 1 {
		t.Error("dry run must still kernel-check the ruleset")
	}
	if !strings.Contains(out.String(), "add element inet blocklist static4 { 1.2.3.4 }") {
		t.Errorf("dry-run output missing elements:\n%s", out.String())
	}
	if meta, _ := a.Store.LoadMeta(); meta.Total() != 0 {
		t.Error("dry run must not persist state")
	}
}

func TestUpdateApplyFailureFailsClosed(t *testing.T) {
	srv := feedServer(t, map[string]string{"/a": "1.2.3.4\n"})
	cfg := testConfig(srv.URL, "/a")
	a, nft, sink := newTestApp(t, cfg)
	nft.failApply = errors.New("netlink says no")

	err := a.Update(context.Background(), UpdateOptions{})
	if err == nil || !strings.Contains(err.Error(), "netlink says no") {
		t.Fatalf("err = %v", err)
	}
	if meta, _ := a.Store.LoadMeta(); meta.Total() != 0 {
		t.Error("failed apply must not be recorded as last-known-good")
	}
	if !sink.has(notify.KindUpdateFailed) {
		t.Errorf("events = %v, want update_failed", sink.kinds())
	}
}

func TestRollback(t *testing.T) {
	srv := feedServer(t, map[string]string{"/a": "1.2.3.4\n"})
	cfg := testConfig(srv.URL, "/a")
	a, nft, sink := newTestApp(t, cfg)

	// No state yet: rollback must refuse rather than apply nothing.
	if err := a.Rollback(context.Background()); err == nil {
		t.Fatal("rollback without last-known-good must error")
	}

	if err := a.Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(nft.applied) != 2 {
		t.Fatalf("applied = %d, want 2 (update + rollback)", len(nft.applied))
	}
	if string(nft.applied[0]) != string(nft.applied[1]) {
		t.Error("rollback must re-apply the exact last-known-good ruleset")
	}
	if !sink.has(notify.KindRollback) {
		t.Errorf("events = %v, want rollback", sink.kinds())
	}
}

func TestStatusOutput(t *testing.T) {
	srv := feedServer(t, map[string]string{"/a": "1.2.3.4\n"})
	cfg := testConfig(srv.URL, "/a")
	a, _, _ := newTestApp(t, cfg)

	var out strings.Builder
	if err := a.Status(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no successful update recorded yet") {
		t.Errorf("pre-run status = %q", out.String())
	}

	if err := a.Update(context.Background(), UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := a.Status(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "recorded entries: 1 IPv4 + 0 IPv6") || !strings.Contains(s, "feed-0") {
		t.Errorf("status = %q", s)
	}
}
