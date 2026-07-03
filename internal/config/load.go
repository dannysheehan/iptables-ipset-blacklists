package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// rawConfig mirrors Config but defers feed decoding so each feed can start
// from FeedDefaults() before its YAML is applied.
type rawConfig struct {
	NFT                NFT           `yaml:"nftables"`
	Policy             Policy        `yaml:"policy"`
	AllowlistFile      string        `yaml:"allowlist_file"`
	LocalBlocklistFile string        `yaml:"local_blocklist_file"`
	StateDir           string        `yaml:"state_dir"`
	CacheDir           string        `yaml:"cache_dir"`
	FeedsDir           string        `yaml:"feeds_dir"`
	ShrinkGuardPercent *int          `yaml:"shrink_guard_percent"`
	MaxEntriesPerFeed  *int          `yaml:"max_entries_per_feed"`
	Notifications      Notifications `yaml:"notifications"`
	Feeds              []yaml.Node   `yaml:"feeds"`
}

// Load reads path (config.yaml), merges feeds from the inline `feeds:` list
// and from FeedsDir (default <dir-of-path>/feeds.d), applies defaults, and
// validates the result.
func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config: %w", err)
	}

	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return cfg, fmt.Errorf("parsing %s: %w", path, err)
	}

	applyRaw(&cfg, raw)

	for i := range raw.Feeds {
		f, err := decodeFeed(&raw.Feeds[i])
		if err != nil {
			return cfg, fmt.Errorf("parsing %s: %w", path, err)
		}
		cfg.Feeds = append(cfg.Feeds, f)
	}

	if cfg.FeedsDir == "" {
		cfg.FeedsDir = filepath.Join(filepath.Dir(path), "feeds.d")
	}
	dirFeeds, err := loadFeedsDir(cfg.FeedsDir)
	if err != nil {
		return cfg, err
	}
	cfg.Feeds = append(cfg.Feeds, dirFeeds...)

	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyRaw(cfg *Config, raw rawConfig) {
	if raw.NFT.Table != "" {
		cfg.NFT.Table = raw.NFT.Table
	}
	if raw.NFT.Chain != "" {
		cfg.NFT.Chain = raw.NFT.Chain
	}
	if raw.NFT.Priority != 0 {
		cfg.NFT.Priority = raw.NFT.Priority
	}
	if raw.Policy.Action != "" {
		cfg.Policy.Action = raw.Policy.Action
	}
	if raw.Policy.LogRate != "" {
		cfg.Policy.LogRate = raw.Policy.LogRate
	}
	if raw.Policy.LogPrefix != "" {
		cfg.Policy.LogPrefix = raw.Policy.LogPrefix
	}
	cfg.Policy.LogTCPPorts = raw.Policy.LogTCPPorts
	cfg.Policy.LogUDPPorts = raw.Policy.LogUDPPorts
	if raw.AllowlistFile != "" {
		cfg.AllowlistFile = raw.AllowlistFile
	}
	if raw.LocalBlocklistFile != "" {
		cfg.LocalBlocklistFile = raw.LocalBlocklistFile
	}
	if raw.StateDir != "" {
		cfg.StateDir = raw.StateDir
	}
	if raw.CacheDir != "" {
		cfg.CacheDir = raw.CacheDir
	}
	if raw.FeedsDir != "" {
		cfg.FeedsDir = raw.FeedsDir
	}
	if raw.ShrinkGuardPercent != nil {
		cfg.ShrinkGuardPercent = *raw.ShrinkGuardPercent
	}
	if raw.MaxEntriesPerFeed != nil {
		cfg.MaxEntriesPerFeed = *raw.MaxEntriesPerFeed
	}
	if raw.Notifications.MinLevel != "" {
		cfg.Notifications.MinLevel = raw.Notifications.MinLevel
	}
	cfg.Notifications.Sinks = raw.Notifications.Sinks
}

func decodeFeed(node *yaml.Node) (Feed, error) {
	f := FeedDefaults()
	// Re-encode the node and decode strictly into the defaulted Feed so
	// unknown feed keys are rejected too.
	buf, err := yaml.Marshal(node)
	if err != nil {
		return f, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(buf))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("feed entry: %w", err)
	}
	return f, nil
}

// loadFeedsDir reads every *.yaml/*.yml in dir. Each file holds either a
// single feed document or a `feeds:` list. A missing dir is not an error.
func loadFeedsDir(dir string) ([]Feed, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading feeds dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var feeds []Feed
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		fs, err := decodeFeedFile(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		feeds = append(feeds, fs...)
	}
	return feeds, nil
}

func decodeFeedFile(data []byte) ([]Feed, error) {
	// Try the `feeds:` list form first.
	var wrapper struct {
		Feeds []yaml.Node `yaml:"feeds"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err == nil && len(wrapper.Feeds) > 0 {
		out := make([]Feed, 0, len(wrapper.Feeds))
		for i := range wrapper.Feeds {
			f, err := decodeFeed(&wrapper.Feeds[i])
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
		return out, nil
	}

	// Fall back to a single feed document.
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if node.Kind == 0 || len(node.Content) == 0 {
		return nil, nil // empty file
	}
	f, err := decodeFeed(node.Content[0])
	if err != nil {
		return nil, err
	}
	return []Feed{f}, nil
}
