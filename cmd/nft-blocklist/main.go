// Command nft-blocklist maintains nftables blocklist sets from curated
// threat-intelligence feeds. This file is deliberately thin — flag parsing
// and wiring only — because everything with behavior worth testing lives in
// internal/ packages (see docs/architecture.md).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dannysheehan/nft-blocklist/internal/app"
	"github.com/dannysheehan/nft-blocklist/internal/config"
	"github.com/dannysheehan/nft-blocklist/internal/feed"
	"github.com/dannysheehan/nft-blocklist/internal/nftctl"
	"github.com/dannysheehan/nft-blocklist/internal/notify"
	"github.com/dannysheehan/nft-blocklist/internal/state"
)

// version is stamped by the linker (see Makefile LDFLAGS).
var version = "dev"

const usage = `nft-blocklist — nftables blocklist manager

Usage: nft-blocklist [global flags] <command> [command flags]

Commands:
  update     fetch feeds and atomically apply the blocklist ruleset
               --dry-run   render + kernel-check, print ruleset, change nothing
               --force     override the shrink guard
  validate   check configuration (and feeds.d) without touching anything
  status     show last run and live kernel set counts
  rollback   re-apply the last-known-good ruleset
  version    print version

Global flags:
  --config PATH   config file (default /etc/nft-blocklist/config.yaml)
  --nft PATH      nft binary (default: from PATH)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	global := flag.NewFlagSet("nft-blocklist", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configPath := global.String("config", "/etc/nft-blocklist/config.yaml", "config file")
	nftPath := global.String("nft", "", "path to nft binary")
	if err := global.Parse(args); err != nil {
		return 2
	}
	if global.NArg() < 1 {
		global.Usage()
		return 2
	}
	cmd, rest := global.Arg(0), global.Args()[1:]

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	// SIGTERM must interrupt in-flight downloads promptly: systemd sends
	// it on stop/timeout and escalates to SIGKILL after a grace period.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cmd == "version" {
		fmt.Println("nft-blocklist", version)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("configuration invalid", "error", err)
		return 1
	}
	if cmd == "validate" {
		fmt.Printf("configuration OK: %d feeds (%d enabled), %d notification sinks\n",
			len(cfg.Feeds), len(cfg.EnabledFeeds()), len(cfg.Notifications.Sinks))
		return 0
	}

	dispatcher, err := notify.Build(cfg.Notifications, nil)
	if err != nil {
		log.Error("building notification sinks", "error", err)
		return 1
	}
	hostname, _ := os.Hostname()

	a := &app.App{
		Cfg:      cfg,
		Fetcher:  feed.NewFetcher(cfg.CacheDir),
		NFT:      nftctl.Exec{Nft: *nftPath},
		Store:    state.New(cfg.StateDir),
		Notify:   dispatcher,
		Log:      log,
		Version:  version,
		Hostname: hostname,
	}

	switch cmd {
	case "update":
		fs := flag.NewFlagSet("update", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "render and check only")
		force := fs.Bool("force", false, "override shrink guard")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if err := a.Update(ctx, app.UpdateOptions{DryRun: *dryRun, Force: *force}); err != nil {
			log.Error("update failed", "error", err)
			return 1
		}
	case "status":
		if err := a.Status(ctx, os.Stdout); err != nil {
			log.Error("status failed", "error", err)
			return 1
		}
	case "rollback":
		if err := a.Rollback(ctx); err != nil {
			log.Error("rollback failed", "error", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		global.Usage()
		return 2
	}
	return 0
}
