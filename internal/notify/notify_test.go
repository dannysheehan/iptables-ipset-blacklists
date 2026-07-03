package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dannysheehan/nft-blocklist/internal/config"
)

// recordSink captures dispatched events for filter assertions.
type recordSink struct {
	name string
	got  []Event
}

func (r *recordSink) Name() string                          { return r.name }
func (r *recordSink) Send(_ context.Context, e Event) error { r.got = append(r.got, e); return nil }

func TestDispatcherFiltering(t *testing.T) {
	all := &recordSink{name: "all"}
	critOnly := &recordSink{name: "crit"}
	collisionsOnly := &recordSink{name: "collisions"}

	var d Dispatcher
	d.Add(all, Info, nil)
	d.Add(critOnly, Critical, nil)
	d.Add(collisionsOnly, Info, []Kind{KindAllowlistCollision})

	events := []Event{
		{Kind: KindUpdateApplied, Level: Info},
		{Kind: KindAllowlistCollision, Level: Warning},
		{Kind: KindUpdateFailed, Level: Critical},
	}
	for _, e := range events {
		if err := d.Dispatch(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}

	if len(all.got) != 3 {
		t.Errorf("all sink got %d events, want 3", len(all.got))
	}
	if len(critOnly.got) != 1 || critOnly.got[0].Kind != KindUpdateFailed {
		t.Errorf("crit sink got %+v, want only update_failed", critOnly.got)
	}
	if len(collisionsOnly.got) != 1 || collisionsOnly.got[0].Kind != KindAllowlistCollision {
		t.Errorf("collisions sink got %+v", collisionsOnly.got)
	}
}

func TestWebhookSinkDefaultPayload(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &body); err != nil {
			t.Errorf("payload not JSON: %v", err)
		}
	}))
	defer srv.Close()

	d, err := Build(config.Notifications{
		MinLevel: "info",
		Sinks:    []config.NotifySink{{Name: "hook", Type: config.SinkWebhook, URL: srv.URL}},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	e := Event{
		Kind: KindShrinkGuard, Level: Critical, Title: "shrink guard tripped",
		Message: "refusing to apply", Host: "server1",
		Fields: map[string]string{"previous": "1000", "new": "10"},
	}
	if err := d.Dispatch(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if body["kind"] != "shrink_guard" || body["level"] != "critical" || body["host"] != "server1" {
		t.Errorf("payload = %v", body)
	}
}

func TestWebhookSinkTemplatePayloadDiscordStyle(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	}))
	defer srv.Close()

	d, err := Build(config.Notifications{
		MinLevel: "info",
		Sinks: []config.NotifySink{{
			Name: "discord", Type: config.SinkWebhook, URL: srv.URL,
			PayloadTemplate: `{"content": "[{{.Level}}] {{.Title}} on {{.Host}}"}`,
		}},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	e := Event{Kind: KindUpdateFailed, Level: Critical, Title: "update failed", Host: "server1"}
	if err := d.Dispatch(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	want := `{"content": "[critical] update failed on server1"}`
	if got != want {
		t.Errorf("payload = %q, want %q", got, want)
	}
}

func TestWebhookSinkErrorSurfacesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
	}))
	defer srv.Close()

	d, err := Build(config.Notifications{
		MinLevel: "info",
		Sinks:    []config.NotifySink{{Name: "hook", Type: config.SinkWebhook, URL: srv.URL}},
	}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	err = d.Dispatch(context.Background(), Event{Kind: KindUpdateFailed, Level: Critical})
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("err = %v, want 401 with body snippet", err)
	}
}

func TestCommandSink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script sink test")
	}
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out")
	script := filepath.Join(dir, "notify.sh")
	// The script proves both delivery paths: env vars and stdin JSON.
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\necho \"$NFTBL_EVENT $NFTBL_LEVEL\" > "+outFile+"\ncat >> "+outFile+"\n"),
		0o755); err != nil {
		t.Fatal(err)
	}

	d, err := Build(config.Notifications{
		MinLevel: "info",
		Sinks:    []config.NotifySink{{Name: "script", Type: config.SinkCommand, Command: script}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := Event{Kind: KindAllowlistCollision, Level: Warning, Title: "collision", Host: "h"}
	if err := d.Dispatch(context.Background(), e); err != nil {
		t.Fatal(err)
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "allowlist_collision warning\n") {
		t.Errorf("env delivery wrong: %q", s)
	}
	if !strings.Contains(s, `"kind":"allowlist_collision"`) {
		t.Errorf("stdin JSON delivery wrong: %q", s)
	}
}

func TestCommandSinkFailureIncludesOutput(t *testing.T) {
	d, err := Build(config.Notifications{
		MinLevel: "info",
		Sinks: []config.NotifySink{{
			Name: "bad", Type: config.SinkCommand,
			Command: "/bin/sh", Args: []string{"-c", "echo boom >&2; exit 3"},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Dispatch(context.Background(), Event{Kind: KindUpdateFailed, Level: Critical})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want script stderr in error", err)
	}
}

// TestBuildRejectsReservedTypes documents that reserved transports fail at
// Build time (config.Validate rejects them earlier with a friendlier hint).
func TestBuildRejectsReservedTypes(t *testing.T) {
	_, err := Build(config.Notifications{
		MinLevel: "info",
		Sinks:    []config.NotifySink{{Name: "tg", Type: config.SinkTelegram}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("err = %v, want not-implemented error", err)
	}
}
