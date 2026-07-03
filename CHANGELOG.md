# Changelog

## Unreleased (v2.0.0)

Complete rewrite. The repo was renamed `iptables-ipset-blacklists` →
`nft-blocklist` (GitHub redirects the old URLs).

### Added

- Go CLI `nft-blocklist` (`update`, `validate`, `status`, `rollback`,
  `version`) replacing `blacklists.sh`.
- Native nftables backend: dedicated `table inet blocklist`, interval sets
  with automatic CIDR merging, IPv6 support, single atomic `nft -f`
  transaction per update.
- Safety rails: bogon/private/default-route rejection, per-feed entry caps,
  HTML-error-page detection, shrink guard against collapsed feeds,
  last-known-good ruleset with `rollback` and boot restore.
- Curated default feed catalog (Spamhaus DROP v4/v6, FireHOL level1,
  blocklist.de, CINS Army, ipsum with confidence scoring; abuse.ch C2 and
  Tor exits shipped disabled) with per-feed metadata: format, family, risk
  tier, fail policy, minimum fetch interval.
- HTTP fetch cache with ETag/Last-Modified conditional requests.
- Notifications: event model (allowlist collision, update failed, shrink
  guard, feed degraded, rollback, planned drop-spike) with webhook and
  command sinks; telegram/signal/whatsapp/discord reserved in the schema.
- systemd units: hardened oneshot service (CPUQuota/MemoryMax replace
  cpulimit), jittered daily timer, boot-restore service, OnFailure notifier.
- fail2ban integration: bans land in separate `dynamic4`/`dynamic6` sets
  that feed updates never touch.
- Packaging: `.deb`/`.rpm` via nfpm.
- Tests: unit (parsers, IP math, golden rulesets, orchestration), real-kernel
  integration in unprivileged network namespaces, five-distro Vagrant e2e
  matrix (Ubuntu 24.04, Debian 12, Rocky 9, Leap 15.6, Fedora).

### Changed

- Default block action is `drop` (v1 used REJECT on service ports);
  `reject` remains available via `policy.action`.
- Allowlist ("whitelist" in v1) is now subtracted from feeds *and* enforced
  by an accept rule; collisions notify instead of only emailing root.

### Removed

- iptables/ipset/cron/cpulimit stack (script preserved in `legacy/`).
- Dead v1 feeds: openbl.org, autoshun.org, infiltrated.net,
  palevo/spyeye/zeus trackers, emerging threats RBN, dshield top10.
- PSAD `top_attackers` import (superseded by fail2ban integration).
