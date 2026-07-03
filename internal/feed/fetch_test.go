package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dannysheehan/nft-blocklist/internal/config"
)

// fakeClock lets tests move time forward across the min_fetch_interval.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newTestFetcher wires a Fetcher to a temp cache dir and a fake clock.
func newTestFetcher(t *testing.T) (*Fetcher, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	f := NewFetcher(t.TempDir())
	f.Now = clock.now
	return f, clock
}

func testFeed(url string) config.Feed {
	f := config.FeedDefaults()
	f.Name = "test-feed"
	f.URL = url
	f.MinFetchInterval = config.Duration(time.Hour)
	return f
}

func TestFetchFreshThenIntervalCache(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()

	f, clock := newTestFetcher(t)
	fd := testFeed(srv.URL)

	res, err := f.Fetch(context.Background(), fd)
	if err != nil || res.FromCache {
		t.Fatalf("first fetch: res=%+v err=%v, want fresh", res, err)
	}

	// Within the interval: must be served from cache without touching the
	// provider (that's the whole point of min_fetch_interval).
	clock.advance(30 * time.Minute)
	res, err = f.Fetch(context.Background(), fd)
	if err != nil || !res.FromCache || res.Stale {
		t.Fatalf("cached fetch: res=%+v err=%v, want from cache", res, err)
	}
	if hits != 1 {
		t.Fatalf("server hits = %d, want 1 (interval must prevent re-download)", hits)
	}

	// After the interval a real request goes out again.
	clock.advance(31 * time.Minute)
	if _, err := f.Fetch(context.Background(), fd); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("server hits = %d, want 2", hits)
	}
}

func TestFetchETag304(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()

	f, clock := newTestFetcher(t)
	fd := testFeed(srv.URL)

	if _, err := f.Fetch(context.Background(), fd); err != nil {
		t.Fatal(err)
	}

	clock.advance(2 * time.Hour)
	res, err := f.Fetch(context.Background(), fd)
	if err != nil {
		t.Fatal(err)
	}
	if !res.FromCache || res.Stale || string(res.Body) != "1.2.3.4\n" {
		t.Fatalf("304 fetch: res=%+v, want cached body", res)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}

	// The 304 must restart the interval window (provider confirmed the
	// content; hammering it again within the interval is still rude).
	clock.advance(30 * time.Minute)
	if _, err := f.Fetch(context.Background(), fd); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2 (304 must refresh interval window)", hits)
	}
}

func TestFetchFailPolicies(t *testing.T) {
	healthy := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()

	f, clock := newTestFetcher(t)
	fd := testFeed(srv.URL)

	if _, err := f.Fetch(context.Background(), fd); err != nil {
		t.Fatal(err)
	}

	healthy = false
	clock.advance(2 * time.Hour)

	// use_cache: outage degrades to the stale cached copy.
	fd.FailPolicy = config.FailUseCache
	res, err := f.Fetch(context.Background(), fd)
	if err != nil || !res.Stale || string(res.Body) != "1.2.3.4\n" {
		t.Fatalf("use_cache: res=%+v err=%v, want stale cache", res, err)
	}

	// skip: outage is an error the caller uses to drop this feed's
	// contribution for the run.
	fd.FailPolicy = config.FailSkip
	if _, err := f.Fetch(context.Background(), fd); err == nil {
		t.Fatal("skip policy: want error on outage")
	}
}

func TestFetchErrorWithoutCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f, _ := newTestFetcher(t)
	fd := testFeed(srv.URL)
	fd.FailPolicy = config.FailUseCache // no cache exists, so still an error
	if _, err := f.Fetch(context.Background(), fd); err == nil {
		t.Fatal("want error when fetch fails and no cache exists")
	}
}

func TestURLChangeInvalidatesCache(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("1.1.1.1\n"))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("2.2.2.2\n"))
	}))
	defer srvB.Close()

	f, _ := newTestFetcher(t)
	fd := testFeed(srvA.URL)
	if _, err := f.Fetch(context.Background(), fd); err != nil {
		t.Fatal(err)
	}

	// Same feed name, new URL, still inside the interval: the cache is for
	// the old URL and must not be served.
	fd.URL = srvB.URL
	res, err := f.Fetch(context.Background(), fd)
	if err != nil {
		t.Fatal(err)
	}
	if res.FromCache || !strings.Contains(string(res.Body), "2.2.2.2") {
		t.Fatalf("res=%+v, want fresh body from new URL", res)
	}
}
