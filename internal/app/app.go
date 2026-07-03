// Package app orchestrates the update pipeline. It owns sequencing and
// policy decisions (what happens when a feed fails, when the shrink guard
// trips, when an allowlisted IP shows up in a feed) while delegating all
// mechanics to the stage packages — so this package is where the project's
// safety contract is enforced, and it is testable end-to-end with a fake
// nft Runner and httptest feeds.
package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dannysheehan/nft-blocklist/internal/config"
	"github.com/dannysheehan/nft-blocklist/internal/feed"
	"github.com/dannysheehan/nft-blocklist/internal/ipmath"
	"github.com/dannysheehan/nft-blocklist/internal/nftctl"
	"github.com/dannysheehan/nft-blocklist/internal/nftgen"
	"github.com/dannysheehan/nft-blocklist/internal/notify"
	"github.com/dannysheehan/nft-blocklist/internal/state"
)

// fetchWorkers bounds concurrent feed downloads: enough to hide latency,
// few enough that a fleet of these updaters isn't a burst-load problem for
// providers (they ban abusive clients, which would hurt every user).
const fetchWorkers = 4

type App struct {
	Cfg      config.Config
	Fetcher  *feed.Fetcher
	NFT      nftctl.Runner
	Store    state.Store
	Notify   *notify.Dispatcher
	Log      *slog.Logger
	Version  string
	Hostname string
}

type UpdateOptions struct {
	// DryRun renders and kernel-checks the ruleset, writes it to Out, and
	// stops before Apply — nothing changes, state is not saved.
	DryRun bool
	// Force overrides the shrink guard (documented in its error message).
	Force bool
	// Out receives the ruleset in dry-run mode (default os.Stdout).
	Out io.Writer
}

// event is a small helper so emit sites stay one line; delivery failures
// are logged, never propagated — see notify package doc for why.
func (a *App) event(ctx context.Context, e notify.Event) {
	e.Host = a.Hostname
	if err := a.Notify.Dispatch(ctx, e); err != nil {
		a.Log.Warn("notification delivery failed", "error", err)
	}
}

// Update runs the full pipeline. On any failure the kernel ruleset is
// untouched (fail closed) and an update_failed event is emitted.
func (a *App) Update(ctx context.Context, opts UpdateOptions) error {
	err := a.update(ctx, opts)
	if err != nil {
		a.event(ctx, notify.Event{
			Kind: notify.KindUpdateFailed, Level: notify.Critical,
			Title:   "blocklist update failed",
			Message: err.Error(),
		})
	}
	return err
}

func (a *App) update(ctx context.Context, opts UpdateOptions) error {
	start := time.Now()

	// Local files first: an unreadable allowlist must abort the run before
	// any download happens, because applying feeds *without* the allowlist
	// could block the operator's own access.
	allow, err := a.loadLocalList(a.Cfg.AllowlistFile, "allowlist")
	if err != nil {
		return err
	}
	local, err := a.loadLocalList(a.Cfg.LocalBlocklistFile, "local blocklist")
	if err != nil {
		return err
	}

	results := a.fetchAll(ctx, a.Cfg.EnabledFeeds())

	var (
		blocked  = local
		feedRuns []state.FeedRun
	)
	for _, r := range results {
		run := state.FeedRun{Name: r.fd.Name, Entries: len(r.prefixes), FromCache: r.fromCache, Stale: r.stale}
		if r.err != nil {
			run.Error = r.err.Error()
			feedRuns = append(feedRuns, run)
			// Feed-level failure degrades (that's what fail_policy and the
			// shrink guard are for); it must not abort the whole update or
			// one dead provider would freeze feed refreshes for all.
			a.Log.Warn("feed failed, skipping this run", "feed", r.fd.Name, "error", r.err)
			a.event(ctx, notify.Event{
				Kind: notify.KindFeedDegraded, Level: notify.Warning,
				Title:   fmt.Sprintf("feed %s skipped", r.fd.Name),
				Message: r.err.Error(),
				Fields:  map[string]string{"feed": r.fd.Name},
			})
			continue
		}
		if r.stale {
			a.event(ctx, notify.Event{
				Kind: notify.KindFeedDegraded, Level: notify.Warning,
				Title:   fmt.Sprintf("feed %s using stale cache", r.fd.Name),
				Message: "download failed; last cached copy applied per fail_policy use_cache",
				Fields:  map[string]string{"feed": r.fd.Name},
			})
		}
		a.Log.Info("feed processed", "feed", r.fd.Name,
			"entries", len(r.prefixes), "from_cache", r.fromCache, "stale", r.stale,
			"invalid", r.stats.Invalid, "rejected", r.stats.Rejected)

		a.reportCollisions(ctx, r.fd.Name, allow, r.prefixes)
		blocked = append(blocked, r.prefixes...)
		feedRuns = append(feedRuns, run)
	}

	merged, err := ipmath.Merge(blocked, allow)
	if err != nil {
		return err
	}
	allowMerged, err := ipmath.Merge(allow, nil)
	if err != nil {
		return err
	}

	prevMeta, err := a.Store.LoadMeta()
	if err != nil {
		return err
	}
	if !opts.Force {
		if err := state.CheckShrink(prevMeta.Total(), merged.Total(), a.Cfg.ShrinkGuardPercent); err != nil {
			a.event(ctx, notify.Event{
				Kind: notify.KindShrinkGuard, Level: notify.Critical,
				Title:   "shrink guard refused blocklist update",
				Message: err.Error(),
				Fields: map[string]string{
					"previous": fmt.Sprint(prevMeta.Total()),
					"new":      fmt.Sprint(merged.Total()),
				},
			})
			return err
		}
	}

	ruleset := nftgen.Render(nftgen.Input{
		Cfg:         a.Cfg,
		Static:      merged,
		Allow:       allowMerged,
		GeneratedBy: "nft-blocklist " + a.Version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})

	if err := a.NFT.Check(ctx, []byte(ruleset)); err != nil {
		return fmt.Errorf("ruleset failed nft check: %w", err)
	}
	if opts.DryRun {
		out := opts.Out
		if out == nil {
			out = os.Stdout
		}
		_, err := io.WriteString(out, ruleset)
		a.Log.Info("dry run: ruleset checked, not applied",
			"v4", len(merged.V4), "v6", len(merged.V6))
		return err
	}
	if err := a.NFT.Apply(ctx, []byte(ruleset)); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}

	meta := state.Meta{
		Timestamp:   time.Now().UTC(),
		TotalV4:     len(merged.V4),
		TotalV6:     len(merged.V6),
		Feeds:       feedRuns,
		ToolVersion: a.Version,
	}
	if err := a.Store.SaveLastGood([]byte(ruleset), meta); err != nil {
		// The firewall IS updated; failing to persist state must be loud
		// (boot restore would fall back to the previous ruleset) but the
		// run still counts as applied.
		return fmt.Errorf("ruleset applied but state not saved: %w", err)
	}

	a.Log.Info("blocklist applied",
		"v4", len(merged.V4), "v6", len(merged.V6),
		"previous_total", prevMeta.Total(), "duration", time.Since(start).Round(time.Millisecond))
	a.event(ctx, notify.Event{
		Kind: notify.KindUpdateApplied, Level: notify.Info,
		Title: "blocklist updated",
		Message: fmt.Sprintf("%d IPv4 + %d IPv6 prefixes active (was %d)",
			len(merged.V4), len(merged.V6), prevMeta.Total()),
	})
	return nil
}

// fetchResult carries one feed's outcome across the worker boundary.
type fetchResult struct {
	fd        config.Feed
	prefixes  []netip.Prefix
	stats     feed.ParseStats
	fromCache bool
	stale     bool
	err       error
}

// fetchAll downloads and parses feeds with bounded concurrency, preserving
// config order in the results (deterministic logs and state files).
func (a *App) fetchAll(ctx context.Context, feeds []config.Feed) []fetchResult {
	results := make([]fetchResult, len(feeds))
	sem := make(chan struct{}, fetchWorkers)
	var wg sync.WaitGroup
	for i, fd := range feeds {
		wg.Add(1)
		go func(i int, fd config.Feed) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := fetchResult{fd: fd}
			res, err := a.Fetcher.Fetch(ctx, fd)
			if err != nil {
				r.err = err
			} else {
				r.fromCache, r.stale = res.FromCache, res.Stale
				r.prefixes, r.stats, r.err = feed.Parse(
					strings.NewReader(string(res.Body)), fd, ipmath.Policy{}, a.Cfg.MaxEntriesPerFeed)
			}
			results[i] = r
		}(i, fd)
	}
	wg.Wait()
	return results
}

// reportCollisions warns when an allowlisted address appears in a feed.
// The address is still protected (allowlist wins in both the set math and
// the rule order); the point of the event is the *implication* — either
// that host is compromised and earned its listing, or the feed is poisoned.
// This preserves v1's most-loved feature (the whitelist warning email).
func (a *App) reportCollisions(ctx context.Context, feedName string, allow, feedPrefixes []netip.Prefix) {
	for _, ap := range allow {
		if !ap.IsSingleIP() {
			continue // range collisions are too noisy to be actionable
		}
		if ipmath.Contains(feedPrefixes, ap.Addr()) {
			a.Log.Warn("allowlisted IP found in blocklist feed",
				"ip", ap.Addr(), "feed", feedName)
			a.event(ctx, notify.Event{
				Kind: notify.KindAllowlistCollision, Level: notify.Warning,
				Title:   fmt.Sprintf("allowlisted IP %s is listed in feed %s", ap.Addr(), feedName),
				Message: "the IP remains allowed, but it may be compromised (or the feed poisoned) — investigate",
				Fields:  map[string]string{"ip": ap.Addr().String(), "feed": feedName},
			})
		}
	}
}

// loadLocalList reads an optional operator-maintained file (allowlist or
// local blocklist). Private/special ranges are permitted here — unlike
// feeds — because blocking or allowing internal ranges is a legitimate
// local decision; only feeds are untrusted input.
func (a *App) loadLocalList(path, what string) ([]netip.Prefix, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			a.Log.Info(what+" file not present, continuing", "path", path)
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", what, err)
	}
	defer f.Close()

	prefixes, stats, err := feed.Parse(f,
		config.Feed{Name: what, Format: config.FormatCIDR, Family: config.FamilyBoth},
		ipmath.Policy{AllowPrivate: true}, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s %s: %w", what, path, err)
	}
	if stats.Invalid > 0 {
		a.Log.Warn(what+" has invalid lines", "path", path, "invalid", stats.Invalid)
	}
	return prefixes, nil
}

// Rollback re-applies the last-known-good ruleset (also used at boot by
// the restore service so protection exists before feeds re-download).
func (a *App) Rollback(ctx context.Context) error {
	ruleset, err := a.Store.LoadLastGood()
	if err != nil {
		return fmt.Errorf("no last-known-good ruleset: %w", err)
	}
	if err := a.NFT.Apply(ctx, ruleset); err != nil {
		return fmt.Errorf("re-applying last-known-good: %w", err)
	}
	a.Log.Info("last-known-good ruleset re-applied")
	a.event(ctx, notify.Event{
		Kind: notify.KindRollback, Level: notify.Warning,
		Title:   "blocklist rolled back",
		Message: "last-known-good ruleset re-applied",
	})
	return nil
}

// Status writes a human-readable summary: what the last run recorded and
// what the kernel actually holds right now (the two diverge after manual
// edits or reboots without the restore service — worth surfacing).
func (a *App) Status(ctx context.Context, w io.Writer) error {
	meta, err := a.Store.LoadMeta()
	if err != nil {
		return err
	}
	if meta.Timestamp.IsZero() {
		fmt.Fprintln(w, "no successful update recorded yet")
	} else {
		fmt.Fprintf(w, "last update: %s (tool %s)\n", meta.Timestamp.Format(time.RFC3339), meta.ToolVersion)
		fmt.Fprintf(w, "recorded entries: %d IPv4 + %d IPv6\n", meta.TotalV4, meta.TotalV6)
		for _, fr := range meta.Feeds {
			status := "ok"
			switch {
			case fr.Error != "":
				status = "ERROR: " + fr.Error
			case fr.Stale:
				status = "stale cache"
			case fr.FromCache:
				status = "cache"
			}
			fmt.Fprintf(w, "  feed %-30s %7d entries  [%s]\n", fr.Name, fr.Entries, status)
		}
	}

	for _, set := range []string{nftgen.SetStatic4, nftgen.SetStatic6, nftgen.SetDynamic4, nftgen.SetDynamic6} {
		n, err := a.NFT.CountSet(ctx, a.Cfg.NFT.Table, set)
		if err != nil {
			fmt.Fprintf(w, "kernel set %-10s unavailable (%v)\n", set, err)
			continue
		}
		fmt.Fprintf(w, "kernel set %-10s %7d elements\n", set, n)
	}
	return nil
}
