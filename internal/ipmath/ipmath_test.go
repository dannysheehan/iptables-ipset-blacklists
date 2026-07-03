package ipmath

import (
	"net/netip"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "1.2.3.4", want: "1.2.3.4/32"},
		{in: "  1.2.3.4 ", want: "1.2.3.4/32"},
		{in: "1.2.3.0/24", want: "1.2.3.0/24"},
		{in: "1.2.3.99/24", want: "1.2.3.0/24"}, // normalized/masked
		{in: "2001:db9::1", want: "2001:db9::1/128"},
		{in: "2001:db9::/32", want: "2001:db9::/32"},
		{in: "::ffff:1.2.3.4", want: "1.2.3.4/32"}, // 4-in-6 unmapped
		{in: "", wantErr: true},
		{in: "not-an-ip", wantErr: true},
		{in: "300.1.2.3", wantErr: true},
		{in: "1.2.3.4/33", wantErr: true},
		{in: "1.2.3.4/-1", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParsePrefix(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePrefix(%q) = %v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePrefix(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("ParsePrefix(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	def := Policy{}
	tests := []struct {
		prefix string
		policy Policy
		wantOK bool
	}{
		{prefix: "203.0.114.0/24", policy: def, wantOK: true}, // ordinary public
		{prefix: "8.8.8.8/32", policy: def, wantOK: true},
		{prefix: "2600::/16", policy: def, wantOK: true},

		{prefix: "0.0.0.0/0", policy: def, wantOK: false}, // default route
		{prefix: "::/0", policy: def, wantOK: false},      // default route
		{prefix: "5.0.0.0/7", policy: def, wantOK: false}, // broader than /8
		{prefix: "5.0.0.0/8", policy: def, wantOK: true},  // exactly /8 ok
		{prefix: "2600::/15", policy: def, wantOK: false}, // broader than /16
		{prefix: "10.1.2.3/32", policy: def, wantOK: false},
		{prefix: "192.168.1.0/24", policy: def, wantOK: false},
		{prefix: "127.0.0.1/32", policy: def, wantOK: false},
		{prefix: "169.254.10.0/24", policy: def, wantOK: false},
		{prefix: "224.1.2.3/32", policy: def, wantOK: false},
		{prefix: "255.255.255.255/32", policy: def, wantOK: false},
		{prefix: "fe80::1/128", policy: def, wantOK: false},
		{prefix: "fc00::/48", policy: def, wantOK: false},
		{prefix: "2001:db8::/48", policy: def, wantOK: false},

		// Private allowed when opted in (local blocklists may want this).
		{prefix: "10.1.2.3/32", policy: Policy{AllowPrivate: true}, wantOK: true},
		{prefix: "0.0.0.0/0", policy: Policy{AllowPrivate: true}, wantOK: false}, // never

		// Custom breadth limits.
		{prefix: "5.0.0.0/8", policy: Policy{MinV4Bits: 16}, wantOK: false},
		{prefix: "5.5.0.0/16", policy: Policy{MinV4Bits: 16}, wantOK: true},
	}
	for _, tt := range tests {
		err := tt.policy.Check(netip.MustParsePrefix(tt.prefix))
		if tt.wantOK && err != nil {
			t.Errorf("Check(%s) = %v, want ok", tt.prefix, err)
		}
		if !tt.wantOK && err == nil {
			t.Errorf("Check(%s) accepted, want rejection", tt.prefix)
		}
	}
}

func mustParseAll(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name   string
		block  []string
		allow  []string
		wantV4 []string
		wantV6 []string
	}{
		{
			name:   "duplicates collapse",
			block:  []string{"1.2.3.4/32", "1.2.3.4/32"},
			wantV4: []string{"1.2.3.4/32"},
		},
		{
			name:   "ip inside net collapses",
			block:  []string{"1.2.3.4/32", "1.2.3.0/24"},
			wantV4: []string{"1.2.3.0/24"},
		},
		{
			name:   "nested nets collapse to broadest",
			block:  []string{"1.2.3.0/24", "1.2.0.0/16"},
			wantV4: []string{"1.2.0.0/16"},
		},
		{
			name:   "adjacent nets merge",
			block:  []string{"1.2.2.0/24", "1.2.3.0/24"},
			wantV4: []string{"1.2.2.0/23"},
		},
		{
			name:   "allow punches hole",
			block:  []string{"1.2.3.0/30"},
			allow:  []string{"1.2.3.1/32"},
			wantV4: []string{"1.2.3.0/32", "1.2.3.2/31"},
		},
		{
			name:   "allow removes whole entry",
			block:  []string{"1.2.3.4/32", "5.6.7.8/32"},
			allow:  []string{"1.2.3.0/24"},
			wantV4: []string{"5.6.7.8/32"},
		},
		{
			name:   "families split",
			block:  []string{"1.2.3.4/32", "2600:1::/64"},
			wantV4: []string{"1.2.3.4/32"},
			wantV6: []string{"2600:1::/64"},
		},
		{
			name:   "allow in other family is no-op",
			block:  []string{"1.2.3.4/32"},
			allow:  []string{"2600:1::/64"},
			wantV4: []string{"1.2.3.4/32"},
		},
		{
			name: "empty input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Merge(mustParseAll(t, tt.block...), mustParseAll(t, tt.allow...))
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			gotV4 := prefixStrings(res.V4)
			gotV6 := prefixStrings(res.V6)
			if !equal(gotV4, tt.wantV4) {
				t.Errorf("V4 = %v, want %v", gotV4, tt.wantV4)
			}
			if !equal(gotV6, tt.wantV6) {
				t.Errorf("V6 = %v, want %v", gotV6, tt.wantV6)
			}
			if res.Total() != len(res.V4)+len(res.V6) {
				t.Errorf("Total() = %d inconsistent", res.Total())
			}
		})
	}
}

// TestMergeIdempotent: merging the output again must be a fixed point.
func TestMergeIdempotent(t *testing.T) {
	block := mustParseAll(t,
		"1.2.3.4/32", "1.2.3.0/24", "1.2.0.0/16", "9.9.9.0/24", "9.9.10.0/24",
		"2600:1::/64", "2600:1::/48",
	)
	first, err := Merge(block, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Merge(append(append([]netip.Prefix{}, first.V4...), first.V6...), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(prefixStrings(first.V4), prefixStrings(second.V4)) ||
		!equal(prefixStrings(first.V6), prefixStrings(second.V6)) {
		t.Errorf("merge not idempotent: %v vs %v", first, second)
	}
}

func TestContains(t *testing.T) {
	ps := mustParseAll(t, "1.2.3.0/24", "2600:1::/64")
	if !Contains(ps, netip.MustParseAddr("1.2.3.99")) {
		t.Error("expected 1.2.3.99 to be contained")
	}
	if Contains(ps, netip.MustParseAddr("1.2.4.1")) {
		t.Error("did not expect 1.2.4.1 to be contained")
	}
	if !Contains(ps, netip.MustParseAddr("2600:1::42")) {
		t.Error("expected 2600:1::42 to be contained")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
