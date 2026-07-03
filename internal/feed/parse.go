// Package feed downloads and parses upstream blocklist feeds.
package feed

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dannysheehan/nft-blocklist/internal/config"
	"github.com/dannysheehan/nft-blocklist/internal/ipmath"
)

// ParseStats reports what happened to every line of a feed body, so runs
// can be audited and sudden feed-format changes show up in logs.
type ParseStats struct {
	Lines          int // non-empty, non-comment lines seen
	Parsed         int // entries accepted
	Invalid        int // lines that did not parse as an address
	Rejected       int // parsed but refused by the safety policy
	BelowScore     int // scored entries under min_score
	FamilyMismatch int // entries in a family the feed doesn't allow
}

// Parse reads one feed body and returns validated, normalized prefixes.
//
// The plain and cidr formats are parsed identically (first token of each
// line, bare IP or CIDR); both names are accepted so configs read naturally.
// A body whose parseable lines are all invalid (e.g. an HTML error page
// served with HTTP 200) is an error rather than an empty result.
func Parse(r io.Reader, f config.Feed, pol ipmath.Policy, maxEntries int) ([]netip.Prefix, ParseStats, error) {
	var (
		out   []netip.Prefix
		stats ParseStats
	)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := stripComment(sc.Text())
		if line == "" {
			continue
		}
		stats.Lines++

		token, ok := extractToken(line, f, &stats)
		if !ok {
			continue
		}

		pfx, err := ipmath.ParsePrefix(token)
		if err != nil {
			stats.Invalid++
			continue
		}
		if !familyOK(pfx, f.Family) {
			stats.FamilyMismatch++
			continue
		}
		if err := pol.Check(pfx); err != nil {
			stats.Rejected++
			continue
		}

		out = append(out, pfx)
		stats.Parsed++
		if maxEntries > 0 && stats.Parsed > maxEntries {
			return nil, stats, fmt.Errorf("feed %s exceeds max entries (%d)", f.Name, maxEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, stats, fmt.Errorf("reading feed %s: %w", f.Name, err)
	}

	// All-noise bodies (HTML error pages, format changes) must fail loudly
	// so the fail_policy (cached copy) kicks in instead of silently
	// dropping protection.
	if stats.Lines > 0 && stats.Parsed == 0 && stats.Invalid > 0 {
		return nil, stats, fmt.Errorf("feed %s: no valid entries in %d lines (format change or error page?)",
			f.Name, stats.Lines)
	}

	return out, stats, nil
}

// stripComment removes "#" and ";" comments and surrounding whitespace.
func stripComment(line string) string {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// extractToken pulls the candidate address text out of a line according to
// the feed format. ok=false means the line was consumed as non-data (e.g.
// a scored entry below threshold) and already counted in stats.
func extractToken(line string, f config.Feed, stats *ParseStats) (string, bool) {
	switch f.Format {
	case config.FormatCSV:
		delim := f.CSVDelimiter
		if delim == "" {
			delim = ","
		}
		cols := strings.Split(line, delim)
		if f.CSVColumn > len(cols) {
			stats.Invalid++
			return "", false
		}
		return strings.TrimSpace(cols[f.CSVColumn-1]), true

	case config.FormatIpsum:
		fields := strings.Fields(line)
		if len(fields) < 2 {
			stats.Invalid++
			return "", false
		}
		score, err := strconv.Atoi(fields[1])
		if err != nil {
			stats.Invalid++
			return "", false
		}
		if score < f.MinScore {
			stats.BelowScore++
			return "", false
		}
		return fields[0], true

	default: // plain, cidr
		return strings.Fields(line)[0], true
	}
}

func familyOK(p netip.Prefix, fam config.Family) bool {
	switch fam {
	case config.FamilyIPv4:
		return p.Addr().Is4()
	case config.FamilyIPv6:
		return p.Addr().Is6()
	default:
		return true
	}
}
