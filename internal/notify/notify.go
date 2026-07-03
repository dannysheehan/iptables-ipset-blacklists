// Package notify delivers operational events (allowlist collisions, failed
// updates, shrink-guard trips, suspected floods) to external channels.
//
// Why a fan-out design: the v1 script could only email root via a local MTA,
// which modern minimal hosts don't have — failures were silent, which for a
// perimeter defense tool is the worst possible behavior. Here events flow
// through one Dispatcher to any number of Sinks. Two transports are built in
// (webhook, command); Telegram/Signal/WhatsApp/Discord are reserved sink
// types in the config schema so native integrations can land later without
// breaking existing configs. Until then Discord already works through the
// webhook sink with a payload_template, and Signal/WhatsApp work through the
// command sink (signal-cli, mautrix bridges, etc.).
package notify

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Level orders event severity. Sinks filter on it so chat channels only see
// what their audience cares about.
type Level int

const (
	Info Level = iota
	Warning
	Critical
)

func (l Level) String() string {
	switch l {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Critical:
		return "critical"
	default:
		return fmt.Sprintf("level(%d)", int(l))
	}
}

// ParseLevel maps config strings to Levels; empty defaults to Warning
// because routine success chatter must be opt-in, not opt-out.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "info":
		return Info, nil
	case "", "warning":
		return Warning, nil
	case "critical":
		return Critical, nil
	default:
		return Warning, fmt.Errorf("unknown level %q", s)
	}
}

// Kind is a stable machine-readable event identifier. Sinks and config
// filters match on these strings, so they are API: never rename, only add.
type Kind string

const (
	// KindAllowlistCollision: one of *your* allowlisted IPs appeared in a
	// blocklist feed — you may be compromised, or the feed poisoned. The
	// entry was NOT blocked (allowlist wins), but a human must look.
	KindAllowlistCollision Kind = "allowlist_collision"
	// KindUpdateFailed: the update run aborted; the previous ruleset is
	// still active (fail-closed at the kernel).
	KindUpdateFailed Kind = "update_failed"
	// KindUpdateApplied: info-level success summary with entry counts.
	KindUpdateApplied Kind = "update_applied"
	// KindShrinkGuard: the new dataset shrank below the guard threshold
	// and was refused — usually a dead or truncated upstream feed.
	KindShrinkGuard Kind = "shrink_guard"
	// KindFeedDegraded: a feed failed and its fail_policy kicked in
	// (stale cache used or feed skipped for the run).
	KindFeedDegraded Kind = "feed_degraded"
	// KindDropSpike: blocked-packet counters are rising abnormally fast —
	// a possible (D)DoS or scan burst. Emitted by the counter-watching
	// mode (see docs/notifications.md); reserved here so sink filters can
	// reference it before that mode ships.
	KindDropSpike Kind = "drop_spike"
	// KindRollback: an operator (or boot restore) re-applied the
	// last-known-good ruleset.
	KindRollback Kind = "rollback"
)

// Event is the unit of notification. Fields carries structured details
// (feed name, counts, offending IP) so template-driven sinks can format
// service-specific messages without parsing prose.
type Event struct {
	Kind    Kind              `json:"kind"`
	Level   Level             `json:"-"`
	Title   string            `json:"title"`
	Message string            `json:"message"`
	Host    string            `json:"host"`
	Time    time.Time         `json:"time"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// LevelName is what serializes into JSON payloads.
func (e Event) LevelName() string { return e.Level.String() }

// Sink is one delivery transport. Implementations must be safe for
// sequential reuse and must respect ctx (a hung chat API must not stall a
// firewall update).
type Sink interface {
	Name() string
	Send(ctx context.Context, e Event) error
}

// binding pairs a sink with its filters.
type binding struct {
	sink     Sink
	minLevel Level
	kinds    map[Kind]bool // empty = all kinds
}

// Dispatcher fans events out to all configured sinks.
type Dispatcher struct {
	bindings []binding
	timeout  time.Duration
}

// Add registers a sink. kinds may be nil for "all".
func (d *Dispatcher) Add(s Sink, minLevel Level, kinds []Kind) {
	km := map[Kind]bool{}
	for _, k := range kinds {
		km[k] = true
	}
	d.bindings = append(d.bindings, binding{sink: s, minLevel: minLevel, kinds: km})
}

// Dispatch sends e to every matching sink and returns the joined delivery
// errors. Callers log these but never fail the firewall operation over
// them: protecting the host outranks telling someone about it.
func (d *Dispatcher) Dispatch(ctx context.Context, e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	timeout := d.timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	var errs []error
	for _, b := range d.bindings {
		if e.Level < b.minLevel {
			continue
		}
		if len(b.kinds) > 0 && !b.kinds[e.Kind] {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, timeout)
		if err := b.sink.Send(sctx, e); err != nil {
			errs = append(errs, fmt.Errorf("sink %s: %w", b.sink.Name(), err))
		}
		cancel()
	}
	return errors.Join(errs...)
}
