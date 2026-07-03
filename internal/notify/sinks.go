package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"text/template"

	"github.com/dannysheehan/nft-blocklist/internal/config"
)

// Build turns the validated config into a Dispatcher. It exists as the
// single registry mapping SinkType -> implementation, so adding a native
// Telegram/Signal/WhatsApp/Discord transport later is one new case here
// plus lifting the type out of config.ReservedSinkTypes — no call sites
// change.
func Build(n config.Notifications, client *http.Client) (*Dispatcher, error) {
	defLevel, err := ParseLevel(n.MinLevel)
	if err != nil {
		return nil, fmt.Errorf("notifications.min_level: %w", err)
	}
	if client == nil {
		client = http.DefaultClient
	}

	d := &Dispatcher{}
	for _, sc := range n.Sinks {
		var s Sink
		switch sc.Type {
		case config.SinkWebhook:
			s, err = newWebhookSink(sc, client)
		case config.SinkCommand:
			s = &commandSink{name: sc.Name, command: sc.Command, args: sc.Args}
		default:
			// config.Validate already rejects these; guard anyway so a
			// future schema change can't silently drop notifications.
			return nil, fmt.Errorf("sink %s: type %q not implemented", sc.Name, sc.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("sink %s: %w", sc.Name, err)
		}

		level := defLevel
		if sc.MinLevel != "" {
			if level, err = ParseLevel(sc.MinLevel); err != nil {
				return nil, fmt.Errorf("sink %s: %w", sc.Name, err)
			}
		}
		kinds := make([]Kind, 0, len(sc.Events))
		for _, k := range sc.Events {
			kinds = append(kinds, Kind(k))
		}
		d.Add(s, level, kinds)
	}
	return d, nil
}

// webhookSink POSTs the event to a URL. With the default payload (the raw
// event JSON) it suits generic receivers; payload_template reshapes it for
// opinionated APIs — e.g. Discord: {"content": "{{.Title}}: {{.Message}}"}.
type webhookSink struct {
	name   string
	url    string
	tmpl   *template.Template
	client *http.Client
}

func newWebhookSink(sc config.NotifySink, client *http.Client) (*webhookSink, error) {
	w := &webhookSink{name: sc.Name, url: sc.URL, client: client}
	if sc.PayloadTemplate != "" {
		t, err := template.New("payload").Parse(sc.PayloadTemplate)
		if err != nil {
			return nil, fmt.Errorf("payload_template: %w", err)
		}
		w.tmpl = t
	}
	return w, nil
}

func (w *webhookSink) Name() string { return w.name }

// templateEvent is the dot for payload templates: Event plus the level as a
// string (Level is an int and would render as a number otherwise).
type templateEvent struct {
	Event
	Level string
}

func (w *webhookSink) Send(ctx context.Context, e Event) error {
	var body []byte
	if w.tmpl != nil {
		var buf bytes.Buffer
		if err := w.tmpl.Execute(&buf, templateEvent{Event: e, Level: e.LevelName()}); err != nil {
			return fmt.Errorf("rendering payload: %w", err)
		}
		body = buf.Bytes()
	} else {
		wire := struct {
			Event
			Level string `json:"level"`
		}{e, e.LevelName()}
		var err error
		if body, err = json.Marshal(wire); err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Read a little of the body for diagnostics; webhook APIs put the
	// reason ("invalid token") there.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("POST %s: %s: %s", w.url, resp.Status, bytes.TrimSpace(snippet))
	}
	return nil
}

// commandSink pipes the event JSON into a local program. It is the
// universal escape hatch: anything reachable from a shell (signal-cli,
// WhatsApp bridges, ntfy, mail, PagerDuty CLIs) becomes a notifier without
// this codebase learning its protocol. Key details are duplicated into
// NFTBL_* environment variables so simple shell scripts don't need jq.
type commandSink struct {
	name    string
	command string
	args    []string
}

func (c *commandSink) Name() string { return c.name }

func (c *commandSink) Send(ctx context.Context, e Event) error {
	payload, err := json.Marshal(struct {
		Event
		Level string `json:"level"`
	}{e, e.LevelName()})
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, c.command, c.args...)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Env = append(cmd.Environ(),
		"NFTBL_EVENT="+string(e.Kind),
		"NFTBL_LEVEL="+e.LevelName(),
		"NFTBL_TITLE="+e.Title,
		"NFTBL_MESSAGE="+e.Message,
		"NFTBL_HOST="+e.Host,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", c.command, err, bytes.TrimSpace(out))
	}
	return nil
}
