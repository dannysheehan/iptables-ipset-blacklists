package nftctl

import (
	"context"
	"strings"
	"testing"
)

// realOutput is captured from `nft -j list set inet blocklist static4`
// (nftables 1.0.9) after applying the default-drop golden ruleset — the
// parser is tested against the actual wire format, not an approximation.
const realOutput = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "static4", "table": "blocklist", "type": "ipv4_addr", "handle": 3, "flags": ["interval"], "elem": ["1.2.3.4", {"prefix": {"addr": "23.94.24.0", "len": 24}}]}}]}`

func TestParseSetCount(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{name: "real nft output mixed elem forms", in: realOutput, want: 2},
		{
			name: "empty set",
			in:   `{"nftables": [{"metainfo": {}}, {"set": {"name": "static6"}}]}`,
			want: 0,
		},
		{name: "no set object", in: `{"nftables": [{"metainfo": {}}]}`, wantErr: true},
		{name: "not json", in: `<html>`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSetCount([]byte(tt.in))
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("count = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestExecErrorIncludesStderr uses `false`-like behavior via a shell to
// prove nft's stderr diagnostics surface in errors.
func TestExecErrorIncludesStderr(t *testing.T) {
	e := Exec{Nft: "/bin/sh"} // sh -c is close enough to exercise run()
	_, err := e.run(context.Background(), nil, "-c", "echo 'file:1:1 syntax error' >&2; exit 1")
	if err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("err = %v, want stderr content", err)
	}
}
