package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dannysheehan/nft-blocklist/internal/config"
)

// maxBodyBytes bounds a single feed download (64 MiB). Feeds are text lists
// of at most a few million lines; anything larger is a misconfigured URL or
// a hostile endpoint, and an unbounded read could OOM the (MemoryMax-capped)
// service.
const maxBodyBytes = 64 << 20

// Fetcher downloads feed bodies with two layers of restraint that exist to
// protect *feed providers*, not us: a per-feed minimum fetch interval
// (providers ban IPs that download too often — the v1 script cached for the
// same reason), and conditional requests (ETag/Last-Modified) so unchanged
// lists cost providers almost nothing.
type Fetcher struct {
	Client    *http.Client
	CacheDir  string
	UserAgent string
	// Now is injectable so tests can control interval arithmetic.
	Now func() time.Time
}

// NewFetcher returns a Fetcher with production defaults. The 2-minute
// timeout is generous for multi-MB lists but bounds a hung feed so one dead
// provider cannot stall the whole (systemd-supervised) run.
func NewFetcher(cacheDir string) *Fetcher {
	return &Fetcher{
		Client:    &http.Client{Timeout: 2 * time.Minute},
		CacheDir:  cacheDir,
		UserAgent: "nft-blocklist (+https://github.com/dannysheehan/nft-blocklist)",
		Now:       time.Now,
	}
}

// cacheMeta is stored beside each cached body so a later run (a different
// process — this is a oneshot service, not a daemon) can honor intervals
// and send conditional requests.
type cacheMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// Result reports where a feed body came from, for run logs: sudden shifts
// from "fresh" to "cache" across feeds usually mean network trouble.
type Result struct {
	Body      []byte
	FromCache bool // served from cache (interval not elapsed, 304, or fail_policy)
	Stale     bool // cache used because the fetch FAILED (fail_policy: use_cache)
}

// Fetch returns the body for one feed, applying interval discipline,
// conditional requests, and the feed's fail_policy in that order.
func (f *Fetcher) Fetch(ctx context.Context, fd config.Feed) (Result, error) {
	body, meta, cacheErr := f.readCache(fd.Name)
	haveCache := cacheErr == nil && meta.URL == fd.URL // URL change invalidates cache

	// Inside the minimum interval the cache is authoritative; we must not
	// hit the provider at all.
	if haveCache && f.Now().Sub(meta.FetchedAt) < fd.MinFetchInterval.Std() {
		return Result{Body: body, FromCache: true}, nil
	}

	fresh, err := f.download(ctx, fd, meta, haveCache)
	switch {
	case err == nil && fresh == nil: // 304 Not Modified
		// Refresh the timestamp so the interval window restarts; the
		// provider told us the content is still current.
		meta.FetchedAt = f.Now()
		if werr := f.writeMeta(fd.Name, meta); werr != nil {
			return Result{}, werr
		}
		return Result{Body: body, FromCache: true}, nil

	case err == nil:
		return Result{Body: fresh, FromCache: false}, nil

	default:
		if fd.FailPolicy == config.FailUseCache && haveCache {
			return Result{Body: body, FromCache: true, Stale: true},
				nil
		}
		return Result{}, fmt.Errorf("feed %s: %w", fd.Name, err)
	}
}

// download performs the conditional GET. A nil body with nil error means
// 304 Not Modified.
func (f *Fetcher) download(ctx context.Context, fd config.Feed, meta cacheMeta, haveCache bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fd.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if haveCache {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GET %s: unexpected status %s", fd.URL, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: reading body: %w", fd.URL, err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("GET %s: body exceeds %d bytes", fd.URL, maxBodyBytes)
	}

	newMeta := cacheMeta{
		URL:          fd.URL,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		FetchedAt:    f.Now(),
	}
	if err := f.writeCache(fd.Name, body, newMeta); err != nil {
		return nil, err
	}
	return body, nil
}

func (f *Fetcher) bodyPath(name string) string { return filepath.Join(f.CacheDir, name+".body") }
func (f *Fetcher) metaPath(name string) string { return filepath.Join(f.CacheDir, name+".meta") }

func (f *Fetcher) readCache(name string) ([]byte, cacheMeta, error) {
	var meta cacheMeta
	mb, err := os.ReadFile(f.metaPath(name))
	if err != nil {
		return nil, meta, err
	}
	if err := json.Unmarshal(mb, &meta); err != nil {
		return nil, meta, err
	}
	body, err := os.ReadFile(f.bodyPath(name))
	if err != nil {
		return nil, meta, err
	}
	return body, meta, nil
}

// writeCache persists body then meta, both atomically (write-temp + rename)
// so a crash mid-write can't leave a meta that points at a torn body.
func (f *Fetcher) writeCache(name string, body []byte, meta cacheMeta) error {
	if err := os.MkdirAll(f.CacheDir, 0o755); err != nil {
		return err
	}
	if err := atomicWrite(f.bodyPath(name), body); err != nil {
		return err
	}
	return f.writeMeta(name, meta)
}

func (f *Fetcher) writeMeta(name string, meta cacheMeta) error {
	mb, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return atomicWrite(f.metaPath(name), mb)
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	return nil
}
