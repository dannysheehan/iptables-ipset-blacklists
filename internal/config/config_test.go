package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadValid(t *testing.T) {
	cfg, err := Load("testdata/valid/config.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.NFT.Table != "blocklist" || cfg.NFT.Priority != -150 {
		t.Errorf("nft config wrong: %+v", cfg.NFT)
	}
	if cfg.Policy.Action != ActionDrop {
		t.Errorf("action = %q, want drop", cfg.Policy.Action)
	}
	if got := len(cfg.Policy.LogTCPPorts); got != 3 {
		t.Errorf("log_tcp_ports len = %d, want 3", got)
	}
	if cfg.ShrinkGuardPercent != 60 {
		t.Errorf("shrink_guard_percent = %d, want 60", cfg.ShrinkGuardPercent)
	}

	// inline-feed + spamhaus-drop + ipsum + tor-exit-nodes (feeds.d sorted).
	names := make([]string, 0, len(cfg.Feeds))
	for _, f := range cfg.Feeds {
		names = append(names, f.Name)
	}
	want := []string{"inline-feed", "ipsum", "tor-exit-nodes", "spamhaus-drop"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("feed names = %v, want %v", names, want)
	}

	byName := map[string]Feed{}
	for _, f := range cfg.Feeds {
		byName[f.Name] = f
	}

	// Defaults applied to inline feed.
	inline := byName["inline-feed"]
	if !inline.Enabled || inline.FailPolicy != FailUseCache || inline.Family != FamilyIPv4 {
		t.Errorf("inline feed defaults not applied: %+v", inline)
	}
	if inline.MinFetchInterval.Std() != 23*time.Hour {
		t.Errorf("default min_fetch_interval = %v", inline.MinFetchInterval.Std())
	}

	sh := byName["spamhaus-drop"]
	if sh.Format != FormatCIDR || sh.MinFetchInterval.Std() != 24*time.Hour {
		t.Errorf("spamhaus feed wrong: %+v", sh)
	}

	ips := byName["ipsum"]
	if ips.Format != FormatIpsum || ips.MinScore != 3 {
		t.Errorf("ipsum feed wrong: %+v", ips)
	}

	tor := byName["tor-exit-nodes"]
	if tor.Enabled {
		t.Errorf("tor feed should be disabled")
	}

	enabled := cfg.EnabledFeeds()
	if len(enabled) != 3 {
		t.Errorf("EnabledFeeds len = %d, want 3", len(enabled))
	}
}

// writeConfig creates a config.yaml (and optional feeds.d files) in a temp
// dir and returns its path.
func writeConfig(t *testing.T, body string, feedFiles map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if feedFiles != nil {
		fd := filepath.Join(dir, "feeds.d")
		if err := os.Mkdir(fd, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range feedFiles {
			if err := os.WriteFile(filepath.Join(fd, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return path
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		feeds   map[string]string
		wantErr string
	}{
		{
			name:    "unknown top-level key",
			body:    "nonsense_key: true\n",
			wantErr: "not found",
		},
		{
			name: "unknown feed key",
			body: `feeds:
  - name: f1
    url: https://example.com/a
    surprise: 1
`,
			wantErr: "not found",
		},
		{
			name:    "bad action",
			body:    "policy:\n  action: explode\n",
			wantErr: "policy.action",
		},
		{
			name: "bad url scheme",
			body: `feeds:
  - name: f1
    url: ftp://example.com/a
`,
			wantErr: "scheme must be http or https",
		},
		{
			name: "duplicate feed names",
			body: `feeds:
  - name: f1
    url: https://example.com/a
  - name: f1
    url: https://example.com/b
`,
			wantErr: "duplicate name",
		},
		{
			name: "aggressive without acknowledgement",
			body: `feeds:
  - name: country-block
    url: https://example.com/cn
    risk: aggressive
`,
			wantErr: "acknowledge_risk",
		},
		{
			name: "bad duration",
			body: `feeds:
  - name: f1
    url: https://example.com/a
    min_fetch_interval: fortnight
`,
			wantErr: "invalid duration",
		},
		{
			name:    "bad shrink guard",
			body:    "shrink_guard_percent: 150\n",
			wantErr: "shrink_guard_percent",
		},
		{
			name: "bad feed in feeds.d",
			body: "{}\n",
			feeds: map[string]string{
				"bad.yaml": "name: [not, a, string]\nurl: https://example.com/a\n",
			},
			wantErr: "bad.yaml",
		},
		{
			name: "invalid feed name characters",
			body: `feeds:
  - name: "Bad Name!"
    url: https://example.com/a
`,
			wantErr: "name must match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.body, tt.feeds)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadMissingFeedsDirIsOK(t *testing.T) {
	path := writeConfig(t, "{}\n", nil)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Feeds) != 0 {
		t.Errorf("expected no feeds, got %d", len(cfg.Feeds))
	}
}

func TestEmptyFeedsDFileIsOK(t *testing.T) {
	path := writeConfig(t, "{}\n", map[string]string{
		"empty.yaml":   "",
		"comment.yaml": "# nothing here\n",
		"notyaml.conf": "ignored entirely",
	})
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Feeds) != 0 {
		t.Errorf("expected no feeds, got %d", len(cfg.Feeds))
	}
}
