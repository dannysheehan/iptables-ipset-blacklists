# RHEL / Rocky / AlmaLinux / Fedora

Tested on Rocky 9 and Fedora (e2e matrix boxes `rocky9`, `fedora`).
RHEL 9+ deprecates ipset/iptables — this tool is the supported-stack
replacement for the v1 script on these systems.

## Install

```sh
sudo dnf install ./nft-blocklist-*.x86_64.rpm
sudo vi /etc/nft-blocklist/allowlist.txt          # ADD YOUR OWN IPs FIRST
sudo nft-blocklist update --dry-run | less
sudo nft-blocklist update
sudo systemctl enable --now nft-blocklist.timer
sudo systemctl enable nft-blocklist-restore.service
```

## Coexistence with firewalld

**Do not** load big blocklists through firewalld ipsets: with the nftables
backend, reloads with >10k entries degrade from seconds to minutes
(documented upstream, firewalld#738). nft-blocklist deliberately bypasses
firewalld with its own kernel table:

- firewalld keeps owning zones, services and its tables (default priority 0);
- `table inet blocklist` drops feed-listed sources at priority -150,
  before firewalld processing — less work for firewalld, not more;
- `firewall-cmd --reload` does not touch our table, and our updates never
  touch firewalld's.

Red Hat's warning about running two firewall *managers* refers to two
managers editing the same tables; separate tables coexist by design in
nftables.

## SELinux

The service runs from a systemd unit with standard contexts; no custom
policy is needed. If you relocate `state_dir`/`cache_dir` off
`/var/lib` / `/var/cache`, label accordingly.
