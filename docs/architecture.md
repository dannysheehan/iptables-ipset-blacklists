# nft-blocklist architecture

`nft-blocklist` downloads curated IP threat feeds, normalizes and merges
them, and atomically installs the result as native nftables sets. It is the
v2 rewrite of the 2014 `blacklists.sh` iptables/ipset script.

## Why this design

The v1 script had four structural problems that shaped every decision here:

1. **Non-atomic updates.** A bash loop of `ipset add` calls that dies halfway
   leaves the firewall partially updated. nftables executes an entire
   `nft -f` file as **one kernel transaction** — it fully applies or nothing
   changes — so the whole pipeline funnels into generating a single file.
2. **Deprecated stack.** RHEL 9+ deprecates ipset/iptables; Ubuntu 22.04+ and
   SLES 15+ are nftables-native. We use a dedicated `table inet blocklist`
   that *coexists* with firewalld/UFW instead of fighting them for ownership.
3. **Trusting feeds blindly.** Feeds die, change format, or serve HTML error
   pages with HTTP 200. Every entry passes a safety policy (no default
   routes, no private/special ranges, no absurdly broad prefixes), and a
   shrink guard refuses updates that would silently drop most protection.
4. **cron + cpulimit fragility.** systemd timers give jitter (so thousands of
   installs don't stampede feed providers at midnight) and cgroup limits
   (`CPUQuota=`, `MemoryMax=`) replace the cpulimit SIGSTOP/SIGCONT hack.

## Update pipeline

One `nft-blocklist update` run:

```mermaid
flowchart TD
    A[config.yaml + feeds.d/*.yaml] -->|internal/config| B[validated Config]
    B --> C{for each enabled feed}
    C -->|internal/feed fetcher| D[HTTP GET with ETag /\nmin_fetch_interval cache]
    D -->|fresh or cached body| E[internal/feed parser\nplain / cidr / csv / ipsum]
    E --> F[ipmath.Policy check\nreject bogons, default routes,\ntoo-broad prefixes]
    F --> G[ipmath.Merge\ndedupe + CIDR merge\nsubtract allowlist]
    H[allowlist file] --> G
    I[local blocklist file] --> F
    G --> J{shrink guard:\nnew total ≥ N% of last run?}
    J -->|no, and no --force| K[abort: keep current\nfirewall state]
    J -->|yes| L[nftgen.Render\none atomic .nft file]
    L --> M[nft -c -f check]
    M --> N[nft -f apply\nsingle kernel transaction]
    N --> O[persist last-known-good\n+ run metadata]
```

Package responsibilities mirror the pipeline stages exactly; anything pure
(parsing, IP math, rendering) has no I/O so it can be unit-tested
exhaustively, and the two impure edges (HTTP, nft) sit behind interfaces.

## nftables object model

```mermaid
flowchart LR
    subgraph kernel["table inet blocklist (owned by nft-blocklist)"]
        allow4["set allow4/allow6\ninterval, auto-merge"]
        static4["set static4/static6\ninterval, auto-merge"]
        dynamic4["set dynamic4/dynamic6\nflags timeout"]
        chain["chain input\nhook input, priority -150"]
    end
    updater[nft-blocklist update] -->|flush + repopulate\natomically| allow4
    updater -->|flush + repopulate\natomically| static4
    updater -.->|declares, never\nflushes or writes| dynamic4
    f2b[fail2ban action] -->|add element with timeout\nper ban| dynamic4
    chain -->|1: saddr @allow accept| allow4
    chain -->|2: audit log + drop| static4
    chain -->|3: drop| dynamic4
```

Why three set pairs:

- **allow** — the allowlist wins over everything, evaluated first. It is
  subtracted from the static sets at build time *and* enforced as an accept
  rule, so even a hand-added element can't block an allowlisted IP.
- **static** — feed-derived entries. Flushed and repopulated inside the same
  transaction on every update, so there is no unprotected window.
- **dynamic** — owned by reactive tools (fail2ban). Feed updates declare it
  (so rules can reference it on first boot) but never flush it or write
  elements: a feed refresh must never un-ban an active attacker or clobber
  fail2ban's state. Verified by `TestDynamicSetsNeverFlushed`.

Priority -150 runs before firewalld (default 0 for filter input) and UFW
chains, without editing tables those tools own — Red Hat explicitly warns
against two managers editing the same tables.

## Update sequence (systemd)

```mermaid
sequenceDiagram
    participant T as nft-blocklist.timer<br/>(daily + RandomizedDelaySec)
    participant S as nft-blocklist.service<br/>(oneshot, CPUQuota, MemoryMax)
    participant B as nft-blocklist binary
    participant F as feed providers
    participant K as kernel (nftables)
    participant N as OnFailure notifier

    T->>S: elapses (with jitter)
    S->>B: update --config /etc/nft-blocklist/config.yaml
    B->>F: conditional GETs (ETag / min interval)
    F-->>B: 200 body / 304 not modified / error
    Note over B: parse → policy check → merge<br/>→ subtract allowlist → shrink guard
    B->>K: nft -c -f (check), then nft -f (atomic apply)
    K-->>B: whole transaction OK or whole transaction rejected
    B->>B: save last-known-good .nft + metadata
    B-->>S: exit 0 (or non-zero, previous rules intact)
    S--)N: OnFailure= → webhook/journal alert
```

At boot, `nft-blocklist-restore.service` applies the saved last-known-good
file *before* the network is fully up — the v1 script's `.sav` restore had
the same goal: never face the internet unprotected while feeds re-download.

## Failure philosophy

Fail **closed at the kernel, open at the pipeline**: any error in fetching
or parsing one feed degrades to that feed's `fail_policy` (cached copy or
skip), any error in the final apply changes nothing at all, and only a
successful full transaction replaces the last-known-good file used by boot
restore and `rollback`.

## Repo layout

| Path                | Purpose                                              |
|---------------------|------------------------------------------------------|
| `cmd/nft-blocklist` | CLI entry point (thin; logic lives in `internal/`)   |
| `internal/…`        | pipeline stages, one package per stage (see diagram) |
| `configs/`          | example config + curated `feeds.d/` catalog          |
| `systemd/`          | service/timer/restore/notify units                   |
| `fail2ban/`         | action + jail examples targeting the dynamic sets    |
| `test/fixtures/`    | feed bodies shared by unit + integration + e2e tests |
| `test/integration/` | real-kernel tests in network namespaces              |
| `test/e2e/`         | Vagrant matrix + hermetic fixture feed server        |
| `legacy/`           | frozen v1 bash script (unmaintained)                 |
