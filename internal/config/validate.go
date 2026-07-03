package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Validate checks the whole configuration; it returns all problems joined so
// a user can fix a config in one pass.
func (c *Config) Validate() error {
	var errs []error

	switch c.Policy.Action {
	case ActionDrop, ActionReject:
	default:
		errs = append(errs, fmt.Errorf("policy.action must be %q or %q, got %q",
			ActionDrop, ActionReject, c.Policy.Action))
	}
	for _, p := range append(append([]int{}, c.Policy.LogTCPPorts...), c.Policy.LogUDPPorts...) {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("log port %d out of range 1-65535", p))
		}
	}
	if c.ShrinkGuardPercent < 0 || c.ShrinkGuardPercent > 100 {
		errs = append(errs, fmt.Errorf("shrink_guard_percent must be 0-100, got %d", c.ShrinkGuardPercent))
	}
	if c.NFT.Table == "" || c.NFT.Chain == "" {
		errs = append(errs, errors.New("nftables.table and nftables.chain must not be empty"))
	}

	errs = append(errs, c.validateNotifications()...)

	seen := map[string]bool{}
	for i := range c.Feeds {
		f := &c.Feeds[i]
		prefix := fmt.Sprintf("feed %q", f.Name)
		if f.Name == "" {
			prefix = fmt.Sprintf("feed #%d", i+1)
		}

		if !nameRe.MatchString(f.Name) {
			errs = append(errs, fmt.Errorf("%s: name must match %s", prefix, nameRe))
		}
		if seen[f.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", prefix))
		}
		seen[f.Name] = true

		if err := validateURL(f.URL); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", prefix, err))
		}

		switch f.Format {
		case FormatPlain, FormatCIDR, FormatCSV, FormatIpsum:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown format %q", prefix, f.Format))
		}
		switch f.Family {
		case FamilyIPv4, FamilyIPv6, FamilyBoth:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown family %q", prefix, f.Family))
		}
		switch f.Risk {
		case RiskLow, RiskMedium, RiskAggressive:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown risk %q", prefix, f.Risk))
		}
		switch f.FailPolicy {
		case FailUseCache, FailSkip:
		default:
			errs = append(errs, fmt.Errorf("%s: unknown fail_policy %q", prefix, f.FailPolicy))
		}

		if f.Risk == RiskAggressive && f.Enabled && !f.AcknowledgeRisk {
			errs = append(errs, fmt.Errorf(
				"%s: aggressive feeds need acknowledge_risk: true to be enabled", prefix))
		}
		if f.Format == FormatCSV && f.CSVColumn < 1 {
			errs = append(errs, fmt.Errorf("%s: csv_column must be >= 1", prefix))
		}
		if f.MinScore < 0 {
			errs = append(errs, fmt.Errorf("%s: min_score must be >= 0", prefix))
		}
		if f.MinFetchInterval < 0 {
			errs = append(errs, fmt.Errorf("%s: min_fetch_interval must be >= 0", prefix))
		}
	}

	return errors.Join(errs...)
}

// validLevels for notification filtering, ordered by severity elsewhere
// (internal/notify); validation only cares about membership.
var validLevels = map[string]bool{"info": true, "warning": true, "critical": true}

// validateNotifications checks sink declarations. Reserved-but-unimplemented
// transports (telegram, signal, whatsapp, discord) are called out explicitly
// so users get "not yet implemented, use webhook/command" instead of a
// confusing "unknown type" — the schema promises these will exist.
func (c *Config) validateNotifications() []error {
	var errs []error
	if !validLevels[c.Notifications.MinLevel] {
		errs = append(errs, fmt.Errorf("notifications.min_level %q must be info, warning or critical",
			c.Notifications.MinLevel))
	}
	seen := map[string]bool{}
	for i, s := range c.Notifications.Sinks {
		prefix := fmt.Sprintf("notification sink %q", s.Name)
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("notification sink #%d: name is required", i+1))
			prefix = fmt.Sprintf("notification sink #%d", i+1)
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", prefix))
		}
		seen[s.Name] = true
		if s.MinLevel != "" && !validLevels[s.MinLevel] {
			errs = append(errs, fmt.Errorf("%s: min_level %q must be info, warning or critical", prefix, s.MinLevel))
		}

		switch {
		case s.Type == SinkWebhook:
			if err := validateURL(s.URL); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", prefix, err))
			}
		case s.Type == SinkCommand:
			if s.Command == "" {
				errs = append(errs, fmt.Errorf("%s: command is required", prefix))
			}
		case ReservedSinkTypes[s.Type]:
			errs = append(errs, fmt.Errorf(
				"%s: sink type %q is not implemented yet; use type webhook (with payload_template) or command meanwhile",
				prefix, s.Type))
		default:
			errs = append(errs, fmt.Errorf("%s: unknown sink type %q", prefix, s.Type))
		}
	}
	return errs
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return fmt.Errorf("url %q has no host", raw)
		}
		return nil
	default:
		return fmt.Errorf("url %q: scheme must be http or https", raw)
	}
}

// EnabledFeeds returns only the feeds that will actually be processed.
func (c *Config) EnabledFeeds() []Feed {
	var out []Feed
	for _, f := range c.Feeds {
		if f.Enabled {
			out = append(out, f)
		}
	}
	return out
}
