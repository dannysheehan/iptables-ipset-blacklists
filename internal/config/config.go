// Package config defines the strongly typed configuration schema for
// nft-blocklist: a main config.yaml plus per-feed YAML files in feeds.d/.
package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so YAML values like "24h" or "15m" parse.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

// Risk classifies how likely a feed is to produce false positives.
type Risk string

const (
	RiskLow        Risk = "low"
	RiskMedium     Risk = "medium"
	RiskAggressive Risk = "aggressive"
)

// FailPolicy controls behavior when a feed cannot be fetched.
type FailPolicy string

const (
	// FailUseCache reuses the last cached download, however old.
	FailUseCache FailPolicy = "use_cache"
	// FailSkip drops the feed's entries from this run.
	FailSkip FailPolicy = "skip"
)

// Format identifies the on-the-wire layout of a feed body.
type Format string

const (
	// FormatPlain is one IP per line, "#" or ";" comments allowed.
	FormatPlain Format = "plain"
	// FormatCIDR is one IP or CIDR per line, comments allowed.
	FormatCIDR Format = "cidr"
	// FormatCSV takes the IP/CIDR from a delimited column.
	FormatCSV Format = "csv"
	// FormatIpsum is stamparm/ipsum: "<ip>\t<score>" lines.
	FormatIpsum Format = "ipsum"
)

// Family restricts which address family a feed may contribute.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
	FamilyBoth Family = "both"
)

// Action is what the firewall does with blocked sources.
type Action string

const (
	ActionDrop   Action = "drop"
	ActionReject Action = "reject"
)

// Feed describes one upstream blocklist source.
type Feed struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Format  Format `yaml:"format"`
	Family  Family `yaml:"family"`

	// MinFetchInterval is the minimum time between downloads; the cached
	// copy is reused inside this window (protects feed providers).
	MinFetchInterval Duration   `yaml:"min_fetch_interval"`
	Risk             Risk       `yaml:"risk"`
	FailPolicy       FailPolicy `yaml:"fail_policy"`

	// AcknowledgeRisk must be set true to enable an aggressive feed.
	AcknowledgeRisk bool `yaml:"acknowledge_risk"`

	// MinScore filters scored feeds (format: ipsum); entries below the
	// score are discarded. Ignored for unscored formats.
	MinScore int `yaml:"min_score"`

	// CSVColumn is the 1-based column holding the IP (format: csv).
	CSVColumn int `yaml:"csv_column"`
	// CSVDelimiter defaults to ",".
	CSVDelimiter string `yaml:"csv_delimiter"`
}

// NFT names the managed nftables objects.
type NFT struct {
	Table    string `yaml:"table"`
	Chain    string `yaml:"chain"`
	Priority int    `yaml:"priority"`
}

// Policy controls the generated rule behavior.
type Policy struct {
	// Action for blocked sources: drop (default) or reject.
	Action Action `yaml:"action"`
	// LogTCPPorts/LogUDPPorts get rate-limited audit logging before the
	// drop, so legitimate-traffic blocking can be audited later.
	LogTCPPorts []int  `yaml:"log_tcp_ports"`
	LogUDPPorts []int  `yaml:"log_udp_ports"`
	LogRate     string `yaml:"log_rate"`
	LogPrefix   string `yaml:"log_prefix"`
}

// SinkType identifies a notification transport. Only some are implemented;
// the others are reserved so configs written today keep working when the
// native integrations land (the design contract requested by the project:
// messaging hooks must be pluggable from day one).
type SinkType string

const (
	// SinkWebhook POSTs JSON to a URL; with payload_template it already
	// speaks to Discord/Slack/Mattermost/Telegram-gateway endpoints.
	SinkWebhook SinkType = "webhook"
	// SinkCommand executes a local program with the event JSON on stdin —
	// the universal escape hatch (signal-cli, whatsapp bridges, mail).
	SinkCommand SinkType = "command"

	// Reserved: recognized by the schema, rejected at validation with a
	// "not yet implemented" message rather than "unknown type".
	SinkTelegram SinkType = "telegram"
	SinkSignal   SinkType = "signal"
	SinkWhatsApp SinkType = "whatsapp"
	SinkDiscord  SinkType = "discord"
)

// ReservedSinkTypes are declared-but-unimplemented transports.
var ReservedSinkTypes = map[SinkType]bool{
	SinkTelegram: true,
	SinkSignal:   true,
	SinkWhatsApp: true,
	SinkDiscord:  true,
}

// NotifySink configures one notification destination.
type NotifySink struct {
	Name string   `yaml:"name"`
	Type SinkType `yaml:"type"`

	// MinLevel filters events for this sink: info, warning or critical
	// (empty inherits notifications.min_level).
	MinLevel string `yaml:"min_level"`
	// Events optionally restricts which event kinds reach this sink
	// (empty = all). Kinds are defined in internal/notify.
	Events []string `yaml:"events"`

	// Webhook settings.
	URL string `yaml:"url"`
	// PayloadTemplate is a Go text/template over the event; it lets the
	// generic webhook speak any service's JSON dialect (e.g. Discord's
	// {"content": ...}) without new code.
	PayloadTemplate string `yaml:"payload_template"`

	// Command settings.
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

// Notifications configures event delivery to external channels.
type Notifications struct {
	// MinLevel is the default threshold for all sinks (default: warning,
	// so routine successful updates don't spam anyone).
	MinLevel string       `yaml:"min_level"`
	Sinks    []NotifySink `yaml:"sinks"`
}

// Config is the root schema of /etc/nft-blocklist/config.yaml.
type Config struct {
	NFT    NFT    `yaml:"nftables"`
	Policy Policy `yaml:"policy"`

	// AllowlistFile and LocalBlocklistFile are optional plain/cidr files.
	AllowlistFile      string `yaml:"allowlist_file"`
	LocalBlocklistFile string `yaml:"local_blocklist_file"`

	StateDir string `yaml:"state_dir"`
	CacheDir string `yaml:"cache_dir"`

	// FeedsDir holds per-feed YAML files (default: <configdir>/feeds.d).
	FeedsDir string `yaml:"feeds_dir"`

	// ShrinkGuardPercent refuses to apply when the new total entry count
	// falls below this percentage of the previous run (0 disables).
	ShrinkGuardPercent int `yaml:"shrink_guard_percent"`

	// MaxEntriesPerFeed caps a single feed's contribution (0 = no cap).
	MaxEntriesPerFeed int `yaml:"max_entries_per_feed"`

	Notifications Notifications `yaml:"notifications"`

	Feeds []Feed `yaml:"feeds"`
}

// Defaults returns a Config populated with production defaults; Load applies
// the YAML on top of it.
func Defaults() Config {
	return Config{
		NFT: NFT{
			Table:    "blocklist",
			Chain:    "input",
			Priority: -150,
		},
		Policy: Policy{
			Action:    ActionDrop,
			LogRate:   "5/minute",
			LogPrefix: "[BL DROP] ",
		},
		StateDir:           "/var/lib/nft-blocklist",
		CacheDir:           "/var/cache/nft-blocklist",
		ShrinkGuardPercent: 50,
		MaxEntriesPerFeed:  2_000_000,
		Notifications:      Notifications{MinLevel: "warning"},
	}
}

// FeedDefaults are applied to each feed before its YAML is decoded.
func FeedDefaults() Feed {
	return Feed{
		Enabled:          true,
		Family:           FamilyIPv4,
		Format:           FormatPlain,
		MinFetchInterval: Duration(23 * time.Hour),
		Risk:             RiskMedium,
		FailPolicy:       FailUseCache,
		CSVColumn:        1,
		CSVDelimiter:     ",",
	}
}
