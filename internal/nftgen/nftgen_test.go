package nftgen

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dannysheehan/nft-blocklist/internal/config"
	"github.com/dannysheehan/nft-blocklist/internal/ipmath"
)

var update = flag.Bool("update", false, "rewrite golden files")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run `make golden`): %v", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s.\nGot:\n%s\nWant:\n%s", path, got, string(want))
	}
}

func baseInput() Input {
	cfg := config.Defaults()
	cfg.Policy.LogTCPPorts = []int{53, 80, 443}
	cfg.Policy.LogUDPPorts = []int{53}
	return Input{
		Cfg: cfg,
		Static: ipmath.Result{
			V4: mustPrefixes("1.2.3.4/32", "23.94.24.0/24"),
			V6: mustPrefixes("2600:1234::/32"),
		},
		Allow: ipmath.Result{
			V4: mustPrefixes("198.51.100.7/32"),
		},
		GeneratedBy: "nft-blocklist test",
		GeneratedAt: "2026-01-01T00:00:00Z",
	}
}

func TestRenderDefaultDrop(t *testing.T) {
	checkGolden(t, "default-drop", Render(baseInput()))
}

func TestRenderRejectNoLogging(t *testing.T) {
	in := baseInput()
	in.Cfg.Policy.Action = config.ActionReject
	in.Cfg.Policy.LogTCPPorts = nil
	in.Cfg.Policy.LogUDPPorts = nil
	checkGolden(t, "reject-no-logging", Render(in))
}

func TestRenderEmptySets(t *testing.T) {
	in := baseInput()
	in.Static = ipmath.Result{}
	in.Allow = ipmath.Result{}
	checkGolden(t, "empty-sets", Render(in))
}

func TestRenderCustomTable(t *testing.T) {
	in := baseInput()
	in.Cfg.NFT.Table = "myblock"
	in.Cfg.NFT.Chain = "prefilter"
	in.Cfg.NFT.Priority = -300
	checkGolden(t, "custom-table", Render(in))
}

func TestElementChunking(t *testing.T) {
	in := baseInput()
	var v4 []netip.Prefix
	for i := 0; i < 450; i++ {
		v4 = append(v4, netip.MustParsePrefix(fmt.Sprintf("5.%d.%d.0/24", i/250, i%250)))
	}
	in.Static.V4 = v4
	out := Render(in)

	lines := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "add element inet blocklist static4 ") {
			lines++
		}
	}
	if lines != 3 { // 450 elements at 200/line
		t.Errorf("static4 element lines = %d, want 3", lines)
	}
}

func TestDynamicSetsNeverFlushed(t *testing.T) {
	out := Render(baseInput())
	for _, s := range []string{SetDynamic4, SetDynamic6} {
		if strings.Contains(out, "flush set inet blocklist "+s) {
			t.Errorf("dynamic set %s must never be flushed", s)
		}
		if strings.Contains(out, "add element inet blocklist "+s) {
			t.Errorf("dynamic set %s must never receive elements from feed updates", s)
		}
	}
	// But rules must still reference them.
	if !strings.Contains(out, "ip saddr @dynamic4 counter drop") {
		t.Error("missing dynamic4 drop rule")
	}
}

func TestAllowRuleBeforeDrop(t *testing.T) {
	out := Render(baseInput())
	allowIdx := strings.Index(out, "ip saddr @allow4 accept")
	dropIdx := strings.Index(out, "ip saddr @static4 counter drop")
	if allowIdx == -1 || dropIdx == -1 || allowIdx > dropIdx {
		t.Errorf("allow rule must precede drop rule (allow=%d drop=%d)", allowIdx, dropIdx)
	}
}

func TestSingleIPRenderedBare(t *testing.T) {
	out := Render(baseInput())
	if strings.Contains(out, "1.2.3.4/32") {
		t.Error("host prefixes should render as bare addresses")
	}
	if !strings.Contains(out, "{ 1.2.3.4, 23.94.24.0/24 }") {
		t.Error("expected mixed bare address and CIDR in one element line")
	}
}
