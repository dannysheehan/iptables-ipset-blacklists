package feed

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dannysheehan/nft-blocklist/internal/config"
	"github.com/dannysheehan/nft-blocklist/internal/ipmath"
)

const fixtureDir = "../../test/fixtures/feeds"

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestParseFixtures(t *testing.T) {
	pol := ipmath.Policy{}

	tests := []struct {
		name       string
		fixture    string
		feed       config.Feed
		want       []string
		wantStats  ParseStats
		wantErrSub string
	}{
		{
			name:    "plain ipv4 with comments and dupes",
			fixture: "plain-ipv4.txt",
			feed:    config.Feed{Name: "plain", Format: config.FormatPlain, Family: config.FamilyIPv4},
			// duplicate 1.2.3.4 stays here; dedupe is ipmath.Merge's job.
			// 198.51.100.7 is TEST-NET-2, rejected by policy.
			want:      []string{"1.2.3.4/32", "5.6.7.8/32", "9.10.11.12/32", "1.2.3.4/32"},
			wantStats: ParseStats{Lines: 5, Parsed: 4, Rejected: 1},
		},
		{
			name:    "cidr with inline comments both families",
			fixture: "cidr-mixed.txt",
			feed:    config.Feed{Name: "drop", Format: config.FormatCIDR, Family: config.FamilyBoth},
			want:    []string{"23.94.24.0/24", "41.77.240.0/21", "5.6.7.8/32", "2600:1234::/32"},
			wantStats: ParseStats{
				Lines: 5, Parsed: 4, Rejected: 1, // 203.0.113.0/24 TEST-NET
			},
		},
		{
			name:    "cidr feed restricted to ipv4 skips v6",
			fixture: "cidr-mixed.txt",
			feed:    config.Feed{Name: "drop4", Format: config.FormatCIDR, Family: config.FamilyIPv4},
			want:    []string{"23.94.24.0/24", "41.77.240.0/21", "5.6.7.8/32"},
			wantStats: ParseStats{
				Lines: 5, Parsed: 3, Rejected: 1, FamilyMismatch: 1,
			},
		},
		{
			name:    "csv second column with header",
			fixture: "csv-column2.csv",
			feed: config.Feed{
				Name: "csv", Format: config.FormatCSV, Family: config.FamilyIPv4,
				CSVColumn: 2, CSVDelimiter: ",",
			},
			want:      []string{"1.2.3.4/32", "5.6.7.8/32", "9.10.11.12/32"},
			wantStats: ParseStats{Lines: 5, Parsed: 3, Invalid: 2}, // header + not-an-ip
		},
		{
			name:    "ipsum scored min 3",
			fixture: "ipsum.txt",
			feed: config.Feed{
				Name: "ipsum", Format: config.FormatIpsum, Family: config.FamilyIPv4,
				MinScore: 3,
			},
			want: []string{"1.2.3.4/32", "5.6.7.8/32", "21.22.23.24/32"},
			wantStats: ParseStats{
				Lines: 6, Parsed: 3, BelowScore: 2, Invalid: 1, // bad score line
			},
		},
		{
			name:      "empty feed is valid and empty",
			fixture:   "empty.txt",
			feed:      config.Feed{Name: "empty", Format: config.FormatPlain, Family: config.FamilyIPv4},
			want:      nil,
			wantStats: ParseStats{},
		},
		{
			name:       "html error page fails loudly",
			fixture:    "error-page.html",
			feed:       config.Feed{Name: "err", Format: config.FormatPlain, Family: config.FamilyIPv4},
			wantErrSub: "no valid entries",
		},
		{
			name:    "malformed lines counted, valid kept",
			fixture: "malformed.txt",
			feed:    config.Feed{Name: "mal", Format: config.FormatPlain, Family: config.FamilyIPv4},
			want:    []string{"1.2.3.4/32", "5.6.7.8/32"},
			wantStats: ParseStats{
				Lines: 6, Parsed: 2, Invalid: 4,
			},
		},
		{
			name:    "poisoned feed private ranges rejected",
			fixture: "private-ranges.txt",
			feed:    config.Feed{Name: "poison", Format: config.FormatCIDR, Family: config.FamilyIPv4},
			want:    []string{"1.2.3.4/32"},
			wantStats: ParseStats{
				Lines: 7, Parsed: 1, Rejected: 6,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, stats, err := Parse(openFixture(t, tt.fixture), tt.feed, pol, 0)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("err = %v, want substring %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if g, w := strings.Join(strs(got), ","), strings.Join(tt.want, ","); g != w {
				t.Errorf("prefixes = %v, want %v", strs(got), tt.want)
			}
			if stats != tt.wantStats {
				t.Errorf("stats = %+v, want %+v", stats, tt.wantStats)
			}
		})
	}
}

func TestParseMaxEntries(t *testing.T) {
	feed := config.Feed{Name: "big", Format: config.FormatPlain, Family: config.FamilyIPv4}
	body := "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
	_, _, err := Parse(strings.NewReader(body), feed, ipmath.Policy{}, 2)
	if err == nil || !strings.Contains(err.Error(), "max entries") {
		t.Fatalf("err = %v, want max entries error", err)
	}
	got, _, err := Parse(strings.NewReader(body), feed, ipmath.Policy{}, 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %d entries, err %v; want 3, nil", len(got), err)
	}
}
